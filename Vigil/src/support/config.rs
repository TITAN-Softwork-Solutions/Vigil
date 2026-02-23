use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,

    #[serde(default)]
    pub watch: WatchConfig,

    #[serde(default)]
    pub allowlist: AllowlistConfig,

    #[serde(default)]
    pub security: SecurityConfig,

    #[serde(default)]
    pub concurrency: ConcurrencyConfig,

    #[serde(default)]
    pub endpoint_alert: EndpointAlertConfig,

    #[serde(default)]
    pub siem: SiemConfig,

    #[serde(default)]
    pub trust_api: TrustApiConfig,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WatchConfig {
    #[serde(default)]
    pub protected: Vec<ProtectedRule>,

    #[serde(default)]
    pub protected_substrings: Vec<String>,

    #[serde(default)]
    pub exact_paths: Vec<ProtectedRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub signer_subject_allow: Vec<String>,

    #[serde(default)]
    pub process_name_allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RevocationMode {
    #[default]
    None,
    Chain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_require_signature")]
    pub require_signature: bool,

    #[serde(default = "default_require_signer_allowlist")]
    pub require_signer_allowlist: bool,

    #[serde(default)]
    pub allow_legacy_process_name_fallback: bool,

    #[serde(default)]
    pub revocation_mode: RevocationMode,

    #[serde(default)]
    pub denylisted_cert_thumbprints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustApiMode {
    WintrustOnly,
    ApiOnly,
    PreferApi,
    PreferWintrust,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustApiConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_trust_api_endpoint")]
    pub endpoint: String,

    #[serde(default)]
    pub api_key: Option<String>,

    #[serde(default = "default_trust_api_timeout_ms")]
    pub timeout_ms: u64,

    #[serde(default = "default_trust_api_mode")]
    pub mode: TrustApiMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcurrencyConfig {
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,

    #[serde(default = "default_alert_channel_capacity")]
    pub alert_channel_capacity: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EndpointTransport {
    #[default]
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointAlertConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub endpoint: String,

    #[serde(default)]
    pub transport: EndpointTransport,

    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,

    #[serde(default = "default_endpoint_retries")]
    pub retries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    #[serde(default = "default_siem_enabled")]
    pub enabled: bool,

    #[serde(default = "default_siem_formats")]
    pub formats: Vec<String>,

    #[serde(default = "default_generate_sigma_rules")]
    pub generate_sigma_rules: bool,

    #[serde(default = "default_sigma_rules_file")]
    pub sigma_rules_file: String,
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
fn default_require_signature() -> bool {
    true
}
fn default_require_signer_allowlist() -> bool {
    true
}
fn default_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().max(2))
        .unwrap_or(4)
}
fn default_alert_channel_capacity() -> usize {
    4096
}
fn default_connect_timeout_ms() -> u64 {
    1500
}
fn default_endpoint_retries() -> usize {
    1
}
fn default_trust_api_timeout_ms() -> u64 {
    2500
}
fn default_siem_enabled() -> bool {
    true
}
fn default_siem_formats() -> Vec<String> {
    vec![
        "jsonl".to_string(),
        "cef".to_string(),
        "sigma_json".to_string(),
    ]
}
fn default_generate_sigma_rules() -> bool {
    true
}
fn default_sigma_rules_file() -> String {
    "sigma_rules.yml".to_string()
}
fn default_trust_api_mode() -> TrustApiMode {
    TrustApiMode::WintrustOnly
}
fn default_trust_api_endpoint() -> String {
    String::new()
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            quiet: default_quiet(),
            jsonl: default_jsonl(),
            suppress_ms: default_suppress_ms(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            require_signature: default_require_signature(),
            require_signer_allowlist: default_require_signer_allowlist(),
            allow_legacy_process_name_fallback: false,
            revocation_mode: RevocationMode::None,
            denylisted_cert_thumbprints: Vec::new(),
        }
    }
}

impl Default for ConcurrencyConfig {
    fn default() -> Self {
        Self {
            worker_threads: default_worker_threads(),
            alert_channel_capacity: default_alert_channel_capacity(),
        }
    }
}

impl Default for EndpointAlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            transport: EndpointTransport::Udp,
            connect_timeout_ms: default_connect_timeout_ms(),
            retries: default_endpoint_retries(),
        }
    }
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            enabled: default_siem_enabled(),
            formats: default_siem_formats(),
            generate_sigma_rules: default_generate_sigma_rules(),
            sigma_rules_file: default_sigma_rules_file(),
        }
    }
}

impl Default for TrustApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_trust_api_endpoint(),
            api_key: None,
            timeout_ms: default_trust_api_timeout_ms(),
            mode: default_trust_api_mode(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;

        let mut cfg: Config = toml::from_str(&text).context("failed to parse config.toml")?;

        for rule in &mut cfg.watch.protected {
            rule.substring = rule.substring.to_lowercase();
        }
        for rule in &mut cfg.watch.exact_paths {
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

        cfg.security.denylisted_cert_thumbprints = cfg
            .security
            .denylisted_cert_thumbprints
            .into_iter()
            .map(normalize_thumbprint)
            .filter(|s| !s.is_empty())
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

        if cfg.concurrency.worker_threads == 0 {
            cfg.concurrency.worker_threads = default_worker_threads();
        }
        if cfg.concurrency.alert_channel_capacity == 0 {
            cfg.concurrency.alert_channel_capacity = default_alert_channel_capacity();
        }

        if cfg.endpoint_alert.enabled && cfg.endpoint_alert.endpoint.trim().is_empty() {
            anyhow::bail!("endpoint_alert.enabled=true but endpoint_alert.endpoint is empty");
        }

        if cfg.trust_api.enabled && cfg.trust_api.endpoint.trim().is_empty() {
            anyhow::bail!("trust_api.enabled=true but trust_api.endpoint is empty");
        }

        cfg.siem.formats = cfg
            .siem
            .formats
            .into_iter()
            .map(|v| v.trim().to_lowercase())
            .filter(|v| !v.is_empty())
            .collect();
        if cfg.siem.formats.is_empty() {
            cfg.siem.formats = default_siem_formats();
        }
        validate_siem_formats(&cfg.siem.formats)?;

        Ok(cfg)
    }
}

fn normalize_thumbprint(value: String) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase()
}

fn validate_siem_formats(formats: &[String]) -> Result<()> {
    let allowed: HashSet<&str> = ["jsonl", "text", "cef", "sigma_json"].into_iter().collect();
    for fmt in formats {
        if !allowed.contains(fmt.as_str()) {
            anyhow::bail!(
                "unknown siem format '{}' (allowed: jsonl, text, cef, sigma_json)",
                fmt
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn write_temp_config(content: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("titan-vigil-config-{ts}.toml"));
        fs::write(&path, content).expect("failed to write temp config");
        path
    }

    #[test]
    fn normalize_thumbprint_strips_non_hex_and_uppercases() {
        let got = normalize_thumbprint("aa:bb cc-dd_11".to_string());
        assert_eq!(got, "AABBCCDD11");
    }

    #[test]
    fn config_load_rejects_unknown_siem_format() {
        let path = write_temp_config(
            r#"
[siem]
formats = ["jsonl", "bogus"]
"#,
        );

        let err = Config::load(&path).expect_err("config should fail");
        let _ = fs::remove_file(&path);
        let msg = format!("{err:#}");
        assert!(msg.contains("unknown siem format"));
    }

    #[test]
    fn config_load_validates_endpoint_when_enabled() {
        let path = write_temp_config(
            r#"
[endpoint_alert]
enabled = true
endpoint = ""
"#,
        );

        let err = Config::load(&path).expect_err("config should fail");
        let _ = fs::remove_file(&path);
        let msg = format!("{err:#}");
        assert!(msg.contains("endpoint_alert.enabled=true"));
    }

    #[test]
    fn config_load_normalizes_allowlist_and_rules() {
        let path = write_temp_config(
            r#"
[allowlist]
signer_subject_allow = ["Microsoft Corporation"]
process_name_allow = ["Chrome.exe"]

[security]
denylisted_cert_thumbprints = ["aa:bb:11"]

[watch]
protected_substrings = ["\\Users\\Damon\\Cookies"]
"#,
        );

        let cfg = Config::load(&path).expect("config should load");
        let _ = fs::remove_file(&path);

        assert_eq!(
            cfg.allowlist.signer_subject_allow[0],
            "microsoft corporation"
        );
        assert_eq!(cfg.allowlist.process_name_allow[0], "chrome.exe");
        assert_eq!(cfg.security.denylisted_cert_thumbprints[0], "AABB11");
        assert_eq!(cfg.watch.protected[0].substring, "\\users\\damon\\cookies");
    }
}
