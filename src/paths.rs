use anyhow::{Context, Result};
use std::path::PathBuf;

pub fn local_appdata() -> Result<PathBuf> {
    let v = std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA env var missing")?;
    Ok(PathBuf::from(v))
}

pub fn log_dir() -> Result<PathBuf> {
    Ok(local_appdata()?.join("TITAN-Operative-CE").join("logs"))
}
