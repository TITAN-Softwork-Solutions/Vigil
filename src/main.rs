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
use std::sync::Arc;
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

fn main() -> Result<()> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }

    let cli = cli::Cli::parse();

    let cfg = config::Config::load(&cli.config)?;
    let (alert_tx, alert_rx) = unbounded::<alerts::Alert>();

    let engine = Arc::new(Engine::new(cfg.clone(), alert_tx.clone()));

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
    }

    Ok(())
}