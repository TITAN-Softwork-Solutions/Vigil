#![windows_subsystem = "windows"]

mod alerts;
mod cli;
mod config;
mod engine;
mod etw;
mod handles;
mod notify;
mod process;
mod wintrust;

use anyhow::Result;
use crossbeam_channel::unbounded;
use engine::Engine;
use std::{fs, path::PathBuf, sync::Arc};
use windows::{
    core::PCWSTR,
    Win32::{
        System::Com::{CoInitializeEx, COINIT_MULTITHREADED},
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
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }

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

    let cfg = config::Config::load(&cfg_path)?;
    let (alert_tx, alert_rx) = unbounded::<alerts::Alert>();

    let engine = Arc::new(Engine::new(cfg.clone(), alert_tx.clone()));

    let log_root = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let log_dir = log_root.join("TITAN-Vigil-CE").join("logs");
    fs::create_dir_all(&log_dir)?;
    let logger = alerts::AlertLogger::new(&log_dir, cfg.general.jsonl)?;

    if !cfg.general.quiet {
        eprintln!(
            "[TITAN Vigil] running; logging to {}",
            logger.log_path().display()
        );
    }

    let _ = engine.preflight_trusted_handles();
    let _session = etw::start_etw(engine.clone())?;

    loop {
        let alert = match alert_rx.recv() {
            Ok(a) => a,
            Err(_) => break,
        };

        notify::toast_from_alert(&alert);

        if cli.verbose {
            println!("{}", alert.human_line());
        }

        if let Err(e) = logger.write(&alert) {
            eprintln!("[TML][LOG] {:?}", e);
        }
    }

    Ok(())
}

fn show_startup_error(err: &anyhow::Error) {
    let mut msg = String::from("TITAN Vigil failed to start.\n\n");
    msg.push_str(&format!("{err}\n"));

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
