#![windows_subsystem = "console"]

mod alerts;
mod cli;
mod config;
mod diag;
mod endpoint;
mod engine;
mod etw;
mod handles;
mod notify;
mod process;
mod siem;
mod wintrust;

use anyhow::{anyhow, Context, Result};
use crossbeam_channel::bounded;
use engine::Engine;
use std::{fs, path::PathBuf, sync::Arc, thread, time::Duration};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, ERROR_NOT_ALL_ASSIGNED, GetLastError, LUID},
        Security::{
            AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW,
            LUID_AND_ATTRIBUTES, TokenElevation, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION,
            TOKEN_PRIVILEGES, TOKEN_QUERY, SE_PRIVILEGE_ENABLED,
        },
        System::Com::{CoInitializeEx, COINIT_MULTITHREADED},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
        UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK},
    },
};

fn main() -> Result<()> {
    if let Err(e) = run() {
        show_startup_error(&e);
        return Err(e);
    }
    Ok(())
}

fn run() -> Result<()> {
    diag::startup("startup begin");
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }
    diag::startup("COM initialized");

    let cli = cli::Cli::parse();

    let mut cfg_path = cli.config.clone();
    if !cli.config_explicit && !cfg_path.exists() {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let candidate = dir.join("config.toml");
                if candidate.exists() {
                    cfg_path = candidate;
                }
            }
        }
    }

    let cfg = config::Config::load(&cfg_path)
        .with_context(|| format!("failed to load config from {}", cfg_path.display()))?;
    diag::startup(&format!("config loaded from {}", cfg_path.display()));
    ensure_elevated().context("elevation preflight failed")?;
    diag::startup("elevation check passed");
    ensure_kernel_trace_privilege().context("failed to enable SeSystemProfilePrivilege")?;
    diag::startup("SeSystemProfilePrivilege enabled");

    let (alert_tx, alert_rx) = bounded::<alerts::Alert>(cfg.concurrency.alert_channel_capacity);

    let engine = Arc::new(Engine::new(cfg.clone(), alert_tx.clone()));

    let log_root = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let log_dir = log_root.join("TITAN-Vigil-CE").join("logs");
    fs::create_dir_all(&log_dir)
        .with_context(|| format!("failed to create log directory {}", log_dir.display()))?;
    diag::startup(&format!("log dir ready: {}", log_dir.display()));
    let logger = Arc::new(
        alerts::AlertLogger::new(&log_dir, &cfg)
            .with_context(|| format!("failed to initialize logger in {}", log_dir.display()))?,
    );
    let endpoint = Arc::new(endpoint::EndpointAlerter::from_config(&cfg.endpoint_alert));

    if !cfg.general.quiet {
        if let Some(primary_log) = logger.primary_log_path() {
            eprintln!("[TITAN Vigil] running; logging to {}", primary_log.display());
        } else {
            eprintln!("[TITAN Vigil] running");
        }
    }

    if let Some(path) = siem::generate_sigma_rules(&cfg, &log_dir)
        .with_context(|| format!("failed to generate sigma rules in {}", log_dir.display()))?
    {
        diag::startup(&format!("sigma rules generated: {}", path.display()));
        if !cfg.general.quiet {
            eprintln!("[TITAN Vigil] sigma rules generated: {}", path.display());
        }
    }

    let worker_count = cfg.concurrency.worker_threads.max(1);
    let verbose = cli.verbose;
    for idx in 0..worker_count {
        let rx = alert_rx.clone();
        let logger = logger.clone();
        let endpoint = endpoint.clone();
        thread::Builder::new()
            .name(format!("vigil-alert-worker-{idx}"))
            .spawn(move || {
                while let Ok(alert) = rx.recv() {
                    notify::toast_from_alert(&alert);

                    if verbose {
                        println!("{}", alert.human_line());
                    }

                    if let Err(e) = logger.write(&alert) {
                        eprintln!("[TML][LOG] {:?}", e);
                    }

                    if endpoint.is_enabled() {
                        if let Err(e) = endpoint.send(&alert) {
                            eprintln!("[TML][ENDPOINT] {:?}", e);
                        }
                    }
                }
            })?;
    }

    let _ = engine.preflight_trusted_handles();
    diag::startup("preflight trusted handle scan completed");
    let _session = etw::start_etw(engine.clone())?;
    diag::startup("ETW session started");

    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn show_startup_error(err: &anyhow::Error) {
    diag::startup(&format!("startup error: {err}"));
    let mut msg = String::from("TITAN Vigil failed to start.\n\n");
    msg.push_str(&format!("Error: {err}\n"));
    for cause in err.chain().skip(1) {
        msg.push_str(&format!("Caused by: {cause}\n"));
    }

    if let Some(hint) = startup_hint(err) {
        msg.push_str("\nHint:\n");
        msg.push_str(hint);
        msg.push('\n');
    }

    let title = to_wide("TITAN Vigil");
    let body = to_wide(&msg);
    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR(body.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    use std::os::windows::prelude::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

fn ensure_elevated() -> Result<()> {
    if is_process_elevated()? {
        return Ok(());
    }

    Err(anyhow!(
        "insufficient privileges: administrator elevation is required for kernel ETW tracing"
    ))
}

fn is_process_elevated() -> Result<bool> {
    unsafe {
        let mut token = Default::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| anyhow!("OpenProcessToken failed: {e}"))?;

        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
        .is_ok();

        let _ = CloseHandle(token);

        if !ok {
            return Err(anyhow!("GetTokenInformation(TokenElevation) failed"));
        }

        Ok(elevation.TokenIsElevated != 0)
    }
}

fn startup_hint(err: &anyhow::Error) -> Option<&'static str> {
    let msg = err.to_string().to_lowercase();
    if msg.contains("access denied")
        || msg.contains("error 5")
        || msg.contains("administrator")
        || msg.contains("insufficient privileges")
        || msg.contains("sesystemprofileprivilege")
    {
        return Some(
            "Run from an elevated terminal (Run as Administrator) and ensure the account has SeSystemProfilePrivilege. If a stale ETW session exists, run: `logman stop TITAN-Vigil -ets`.",
        );
    }
    None
}

fn ensure_kernel_trace_privilege() -> Result<()> {
    const PRIV_NAME: &str = "SeSystemProfilePrivilege";

    unsafe {
        let mut token = Default::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut token,
        )
        .map_err(|e| anyhow!("OpenProcessToken for privilege adjustment failed: {e}"))?;

        let mut luid = LUID::default();
        let name = to_wide(PRIV_NAME);
        LookupPrivilegeValueW(None, PCWSTR(name.as_ptr()), &mut luid)
            .map_err(|e| anyhow!("LookupPrivilegeValueW({PRIV_NAME}) failed: {e}"))?;

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None)
            .map_err(|e| anyhow!("AdjustTokenPrivileges({PRIV_NAME}) failed: {e}"))?;

        let last = GetLastError();
        let _ = CloseHandle(token);

        if last == ERROR_NOT_ALL_ASSIGNED {
            return Err(anyhow!(
                "{PRIV_NAME} is not assigned to this token; kernel ETW cannot start"
            ));
        }
    }

    Ok(())
}
