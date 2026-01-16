use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub watch: WatchConfig,
    pub allowlist: AllowlistConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_quiet")]
    pub quiet: bool,

    #[serde(default = "default_jsonl")]
    pub jsonl: bool,

    #[serde(default = "default_suppress_ms")]
    pub suppress_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedRule {
    pub substring: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchConfig {
    #[serde(default)]
    pub protected: Vec<ProtectedRule>,

    #[serde(default)]
    pub protected_substrings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub signer_subject_allow: Vec<String>,

    #[serde(default)]
    pub process_name_allow: Vec<String>,
}

fn default_quiet() -> bool {
    true
}
fn default_jsonl() -> bool {
    true
}
fn default_suppress_ms() -> u64 {
    1500
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;

        let mut cfg: Config = toml::from_str(&text).context("failed to parse config.toml")?;

        for rule in &mut cfg.watch.protected {
            rule.substring = rule.substring.to_lowercase();
        }

        cfg.watch.protected_substrings = cfg
            .watch
            .protected_substrings
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();

        cfg.allowlist.signer_subject_allow = cfg
            .allowlist
            .signer_subject_allow
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();

        cfg.allowlist.process_name_allow = cfg
            .allowlist
            .process_name_allow
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();

        if cfg.watch.protected.is_empty() && !cfg.watch.protected_substrings.is_empty() {
            cfg.watch.protected = cfg
                .watch
                .protected_substrings
                .iter()
                .map(|s| ProtectedRule {
                    substring: s.clone(),
                    name: s.clone(),
                })
                .collect();
        }

        Ok(cfg)
    }
}