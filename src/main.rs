mod alerts;
mod cli;
mod config;
mod engine;
mod etw;
mod handles;
mod notify;
mod paths;
mod process;
mod sigcheck;

use anyhow::Result;
use crossbeam_channel::unbounded;
use engine::Engine;
use std::sync::Arc;
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

fn main() -> Result<()> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }

    let cli = cli::Cli::parse();

    let cfg = config::Config::load(&cli.config)?;
    let log_dir = paths::log_dir()?;
    std::fs::create_dir_all(&log_dir)?;

    let (alert_tx, alert_rx) = unbounded::<alerts::Alert>();

    let engine = Arc::new(Engine::new(cfg.clone(), alert_tx.clone()));
    let logger = alerts::AlertLogger::new(&log_dir, cfg.general.jsonl)?;

    let _ = engine.preflight_trusted_handles();

    if !cfg.general.quiet || cli.verbose {
        eprintln!(
            "[TML] booting | config={} | logs={}",
            cli.config.display(),
            log_dir.display()
        );
    }

    let _session = etw::start_etw(engine.clone())?;

    if !cfg.general.quiet || cli.verbose {
        eprintln!(
            "[TML] running | config={} | logs={}",
            cli.config.display(),
            log_dir.display()
        );
    }

    loop {
        let alert = match alert_rx.recv() {
            Ok(a) => a,
            Err(_) => break,
        };

        logger.write(&alert)?;
        notify::toast_from_alert(&alert);

        if cli.verbose {
            println!("{}", alert.human_line());
        }
    }

    Ok(())
}
