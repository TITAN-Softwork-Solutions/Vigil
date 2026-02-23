use crate::support::config::Config;
use anyhow::{Context, Result};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub ts_unix: u64,
    pub pid: u32,
    pub process: String,
    pub target: String,
    pub data_name: String,
    pub event_id: u16,
    pub kind: String,
    pub note: String,
}

impl Alert {
    pub fn new(
        pid: u32,
        process: String,
        target: String,
        data_name: String,
        event_id: u16,
        kind: &str,
        note: &str,
    ) -> Self {
        let ts_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            ts_unix,
            pid,
            process,
            target,
            data_name,
            event_id,
            kind: kind.to_string(),
            note: note.to_string(),
        }
    }

    pub fn human_line(&self) -> String {
        format!(
            "[{}] pid={} proc={} event_id={} kind={} data={} target={} note={}",
            self.ts_unix,
            self.pid,
            self.process,
            self.event_id,
            self.kind,
            self.data_name,
            self.target,
            self.note
        )
    }

    pub fn cef_line(&self) -> String {
        let sev = match self.kind.as_str() {
            "suspicious_whitelisted_handle_access" => 9,
            "protected_resource_access" => 8,
            _ => 6,
        };
        format!(
            "CEF:0|TITAN|Vigil|1.0|{}|{}|{}|src={} suser={} msg={} filePath={} cs1Label=ruleName cs1={} cs2Label=eventKind cs2={}",
            self.event_id,
            sanitize_cef(&self.data_name),
            sev,
            self.pid,
            sanitize_cef(&self.process),
            sanitize_cef(&self.note),
            sanitize_cef(&self.target),
            sanitize_cef(&self.data_name),
            sanitize_cef(&self.kind)
        )
    }

    pub fn sigma_json(&self) -> serde_json::Value {
        let mut tags = Vec::new();
        let data_low = self.data_name.to_lowercase();
        if data_low.contains("cookie") {
            tags.push("attack.collection");
        }
        if data_low.contains("password") {
            tags.push("attack.credential_access");
        }
        serde_json::json!({
            "ts_unix": self.ts_unix,
            "title": "TITAN Vigil protected resource access",
            "logsource": {
                "product": "windows",
                "service": "kernel-etw",
                "category": "file_access"
            },
            "detection": {
                "pid": self.pid,
                "process": self.process,
                "file_target": self.target,
                "rule_name": self.data_name,
                "event_id": self.event_id,
                "kind": self.kind,
            },
            "level": "high",
            "tags": tags,
            "note": self.note
        })
    }
}

#[derive(Clone, Copy)]
enum LogFormat {
    Jsonl,
    Text,
    Cef,
    SigmaJson,
}

impl LogFormat {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "jsonl" => Some(Self::Jsonl),
            "text" => Some(Self::Text),
            "cef" => Some(Self::Cef),
            "sigma_json" => Some(Self::SigmaJson),
            _ => None,
        }
    }

    fn file_name(self) -> &'static str {
        match self {
            Self::Jsonl => "alerts.jsonl",
            Self::Text => "alerts.log",
            Self::Cef => "alerts.cef",
            Self::SigmaJson => "alerts_sigma.ndjson",
        }
    }
}

struct SinkWriter {
    format: LogFormat,
    writer: Mutex<BufWriter<File>>,
}

pub struct AlertLogger {
    paths: BTreeMap<String, PathBuf>,
    sinks: Vec<SinkWriter>,
}

impl AlertLogger {
    pub fn new(log_dir: &Path, cfg: &Config) -> Result<Self> {
        let mut requested = cfg.siem.formats.clone();
        if !cfg.siem.enabled {
            requested.clear();
            if cfg.general.jsonl {
                requested.push("jsonl".to_string());
            } else {
                requested.push("text".to_string());
            }
        }

        let mut paths = BTreeMap::new();
        let mut sinks = Vec::new();
        for value in requested {
            let Some(format) = LogFormat::parse(&value) else {
                continue;
            };
            let (path, file) = open_sink_file(log_dir, format.file_name())
                .with_context(|| format!("failed to open log sink for format {}", value))?;
            sinks.push(SinkWriter {
                format,
                writer: Mutex::new(BufWriter::new(file)),
            });
            paths.insert(value, path);
        }

        Ok(Self { paths, sinks })
    }

    pub fn primary_log_path(&self) -> Option<&Path> {
        self.paths.values().next().map(|p| p.as_path())
    }

    pub fn write(&self, alert: &Alert) -> Result<()> {
        for sink in &self.sinks {
            let mut w = sink.writer.lock();
            match sink.format {
                LogFormat::Jsonl => {
                    serde_json::to_writer(&mut *w, alert)?;
                    w.write_all(b"\n")?;
                }
                LogFormat::Text => {
                    w.write_all(alert.human_line().as_bytes())?;
                    w.write_all(b"\n")?;
                }
                LogFormat::Cef => {
                    w.write_all(alert.cef_line().as_bytes())?;
                    w.write_all(b"\n")?;
                }
                LogFormat::SigmaJson => {
                    serde_json::to_writer(&mut *w, &alert.sigma_json())?;
                    w.write_all(b"\n")?;
                }
            }
            w.flush()?;
        }
        Ok(())
    }
}

fn sanitize_cef(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('=', "\\=")
        .replace(['\n', '\r'], " ")
}

fn open_sink_file(log_dir: &Path, file_name: &str) -> Result<(PathBuf, File)> {
    let primary = log_dir.join(file_name);
    if let Ok(file) = open_append_file(&primary) {
        return Ok((primary, file));
    }

    let pid = std::process::id();
    let pid_fallback = log_dir.join(format!("{file_name}.{pid}.log"));
    if let Ok(file) = open_append_file(&pid_fallback) {
        return Ok((pid_fallback, file));
    }

    let temp_root = std::env::temp_dir().join("TITAN-Vigil-CE").join("logs");
    let _ = std::fs::create_dir_all(&temp_root);
    let temp_path = temp_root.join(file_name);
    let file = open_append_file(&temp_path).with_context(|| {
        format!(
            "failed sink paths: {}, {}, {}",
            primary.display(),
            pid_fallback.display(),
            temp_path.display()
        )
    })?;
    Ok((temp_path, file))
}

fn open_append_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open failed: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::config::{
        AllowlistConfig, ConcurrencyConfig, EndpointAlertConfig, GeneralConfig, SecurityConfig,
        SiemConfig, TrustApiConfig, WatchConfig,
    };
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn test_cfg_with_formats(formats: Vec<String>) -> Config {
        Config {
            general: GeneralConfig {
                quiet: true,
                jsonl: true,
                suppress_ms: 1500,
            },
            watch: WatchConfig::default(),
            allowlist: AllowlistConfig::default(),
            security: SecurityConfig::default(),
            concurrency: ConcurrencyConfig::default(),
            endpoint_alert: EndpointAlertConfig::default(),
            siem: SiemConfig {
                enabled: true,
                formats,
                generate_sigma_rules: false,
                sigma_rules_file: "sigma_rules.yml".to_string(),
            },
            trust_api: TrustApiConfig::default(),
        }
    }

    #[test]
    fn cef_line_escapes_special_chars() {
        let alert = Alert::new(
            10,
            r"C:\proc|name.exe".to_string(),
            r"C:\target=a\file".to_string(),
            "Name|Eq=Test".to_string(),
            12,
            "protected_resource_access",
            "line1\nline2",
        );

        let cef = alert.cef_line();
        assert!(cef.starts_with("CEF:0|TITAN|Vigil|1.0|12|"));
        assert!(cef.contains(r"Name\|Eq\=Test"));
        assert!(cef.contains(r"filePath=C:\\target\=a\\file"));
        assert!(cef.contains("msg=line1 line2"));
    }

    #[test]
    fn sigma_json_contains_expected_fields() {
        let alert = Alert::new(
            20,
            "proc.exe".to_string(),
            "target".to_string(),
            "Cookie Vault".to_string(),
            12,
            "protected_resource_access",
            "note",
        );
        let sigma = alert.sigma_json();
        assert_eq!(sigma["logsource"]["product"], "windows");
        assert_eq!(sigma["detection"]["pid"], 20);
        assert_eq!(sigma["detection"]["rule_name"], "Cookie Vault");
        assert!(
            sigma["tags"]
                .as_array()
                .expect("tags should be array")
                .iter()
                .any(|v| v == "attack.collection")
        );
    }

    #[test]
    fn logger_writes_configured_sink_files() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let log_dir = std::env::temp_dir().join(format!("titan-vigil-alert-tests-{ts}"));
        fs::create_dir_all(&log_dir).expect("failed to create temp log dir");

        let cfg = test_cfg_with_formats(vec!["jsonl".to_string(), "cef".to_string()]);
        let logger = AlertLogger::new(&log_dir, &cfg).expect("logger init");
        let alert = Alert::new(
            99,
            "proc.exe".to_string(),
            "target".to_string(),
            "Data".to_string(),
            12,
            "protected_resource_access",
            "note",
        );
        logger.write(&alert).expect("logger write");

        assert!(log_dir.join("alerts.jsonl").exists());
        assert!(log_dir.join("alerts.cef").exists());

        let _ = fs::remove_dir_all(&log_dir);
    }
}
