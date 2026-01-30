use anyhow::Result;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
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
}

pub struct AlertLogger {
    path: PathBuf,
    jsonl: bool,
    w: Mutex<BufWriter<File>>,
}

impl AlertLogger {
    pub fn new(log_dir: &Path, jsonl: bool) -> Result<Self> {
        let path = if jsonl {
            log_dir.join("alerts.jsonl")
        } else {
            log_dir.join("alerts.log")
        };

        let f = OpenOptions::new().create(true).append(true).open(&path)?;

        Ok(Self {
            path,
            jsonl,
            w: Mutex::new(BufWriter::new(f)),
        })
    }

    pub fn log_path(&self) -> &Path {
        &self.path
    }

    pub fn write(&self, alert: &Alert) -> Result<()> {
        let mut w = self.w.lock();

        if self.jsonl {
            serde_json::to_writer(&mut *w, alert)?;
            w.write_all(b"\n")?;
        } else {
            w.write_all(alert.human_line().as_bytes())?;
            w.write_all(b"\n")?;
        }

        w.flush()?;
        Ok(())
    }
}
