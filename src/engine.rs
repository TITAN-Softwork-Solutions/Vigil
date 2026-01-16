use crate::{alerts::Alert, config::Config, handles, process, sigcheck};
use crossbeam_channel::Sender;
use parking_lot::Mutex;
use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct ProcMeta {
    pub image: String,
    pub ts: Instant,
    pub is_trusted_signed: bool,
    pub signer_subject: Option<String>,
}

#[derive(Debug)]
pub struct Engine {
    cfg: Config,
    alert_tx: Sender<Alert>,
    proc_cache: Mutex<HashMap<u32, ProcMeta>>,
    filekey_cache: Mutex<HashMap<u64, String>>,
    last_alert: Mutex<HashMap<u64, Instant>>,
    whitelisted_file_objects: Mutex<HashMap<u64, HashSet<u32>>>,
}

impl Engine {
    pub fn new(cfg: Config, alert_tx: Sender<Alert>) -> Self {
        Self {
            cfg,
            alert_tx,
            proc_cache: Mutex::new(HashMap::new()),
            filekey_cache: Mutex::new(HashMap::new()),
            last_alert: Mutex::new(HashMap::new()),
            whitelisted_file_objects: Mutex::new(HashMap::new()),
        }
    }

    pub fn preflight_trusted_handles(&self) -> anyhow::Result<()> {
        let pids = process::enum_process_ids()?;
        let mut trusted_pids = Vec::new();

        for pid in pids {
            let img = match process::get_process_image_path(pid) {
                Some(p) => p,
                None => continue,
            };

            let trust = self.trust_for_path(&img);
            if trust.is_trusted {
                self.proc_cache.lock().insert(
                    pid,
                    ProcMeta {
                        image: img.clone(),
                        ts: Instant::now(),
                        is_trusted_signed: true,
                        signer_subject: trust.signer_subject.clone(),
                    },
                );
                trusted_pids.push(pid);
            }
        }

        if trusted_pids.is_empty() {
            return Ok(());
        }

        let entries = handles::collect_file_objects_for_pids(&trusted_pids)?;
        if entries.is_empty() {
            return Ok(());
        }

        let mut wl = self.whitelisted_file_objects.lock();
        for (file_object, pids_set) in entries {
            wl.entry(file_object).or_default().extend(pids_set);
        }

        Ok(())
    }

    #[inline]
    pub fn on_process_start(&self, pid: u32, image: String, _cmdline: Option<String>) {
        let low = image.to_lowercase();
        if !low.ends_with(".exe") {
            return;
        }

        let trust = self.trust_for_path(&image);

        self.proc_cache.lock().insert(
            pid,
            ProcMeta {
                image,
                ts: Instant::now(),
                is_trusted_signed: trust.is_trusted,
                signer_subject: trust.signer_subject,
            },
        );
    }

    #[inline]
    pub fn on_file_name_mapping(&self, file_key: u64, file_name: String) {
        self.filekey_cache.lock().insert(file_key, file_name);
    }

    #[inline]
    pub fn clear_file_key(&self, file_key: u64) {
        self.filekey_cache.lock().remove(&file_key);
    }

    #[inline]
    pub fn resolve_file_key(&self, file_key: u64) -> Option<String> {
        self.filekey_cache.lock().get(&file_key).cloned()
    }

    #[inline]
    pub fn resolve_process_image(&self, pid: u32) -> String {
        if pid == 0 || pid == 4 {
            return "SYSTEM".to_string();
        }

        let ttl = Duration::from_secs(10);

        if let Some(meta) = self.proc_cache.lock().get(&pid).cloned() {
            if meta.ts.elapsed() <= ttl {
                return meta.image;
            }
        }

        let img = process::get_process_image_path(pid).unwrap_or_else(|| "unknown".to_string());

        self.proc_cache.lock().insert(
            pid,
            ProcMeta {
                image: img.clone(),
                ts: Instant::now(),
                is_trusted_signed: false,
                signer_subject: None,
            },
        );

        img
    }

    #[inline]
    pub fn match_protected_rule(&self, path: &str) -> Option<(String, String)> {
        let p = path.to_lowercase();
        for rule in &self.cfg.watch.protected {
            if p.contains(&rule.substring) {
                return Some((rule.name.clone(), rule.substring.clone()));
            }
        }
        None
    }

    #[inline]
    pub fn is_legacy_allowlisted_process_name(&self, proc_path: &str) -> bool {
        let p = proc_path.to_lowercase();
        self.cfg
            .allowlist
            .process_name_allow
            .iter()
            .any(|suffix| p.ends_with(suffix))
    }

    #[inline]
    pub fn is_pid_trusted(&self, pid: u32, proc_path: &str) -> bool {
        if let Some(meta) = self.proc_cache.lock().get(&pid) {
            if meta.ts.elapsed() <= Duration::from_secs(60) && meta.is_trusted_signed {
                return true;
            }
        }
        self.is_legacy_allowlisted_process_name(proc_path)
    }

    #[inline]
    pub fn learn_whitelisted_file_object(&self, file_object: u64, pid: u32) {
        if file_object == 0 || pid == 0 || pid == 4 {
            return;
        }
        self.whitelisted_file_objects
            .lock()
            .entry(file_object)
            .or_default()
            .insert(pid);
    }

    #[inline]
    pub fn whitelisted_file_object_owner(&self, file_object: u64) -> Option<HashSet<u32>> {
        self.whitelisted_file_objects
            .lock()
            .get(&file_object)
            .cloned()
    }

    fn dedupe_key(pid: u32, target: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut h = DefaultHasher::new();
        pid.hash(&mut h);
        target.hash(&mut h);
        h.finish()
    }

    #[inline]
    fn should_suppress(&self, pid: u32, target: &str) -> bool {
        let key = Self::dedupe_key(pid, target);
        let now = Instant::now();
        let suppress = Duration::from_millis(self.cfg.general.suppress_ms);

        let mut map = self.last_alert.lock();
        if let Some(prev) = map.get(&key) {
            if now.duration_since(*prev) < suppress {
                return true;
            }
        }
        map.insert(key, now);

        if map.len() > 50_000 {
            map.retain(|_, t| now.duration_since(*t) < suppress * 8);
        }

        false
    }

    #[inline]
    pub fn alert(
        &self,
        pid: u32,
        process: String,
        target: String,
        data_name: String,
        event_id: u16,
        kind: &str,
        note: &str,
    ) {
        if self.should_suppress(pid, &target) {
            return;
        }

        let _ = self.alert_tx.send(Alert::new(
            pid, process, target, data_name, event_id, kind, note,
        ));
    }

    #[inline]
    fn trust_for_path(&self, path: &str) -> sigcheck::TrustResult {
        let trust = sigcheck::verify_file_signature(path);

        if !trust.is_signed {
            return sigcheck::TrustResult {
                is_signed: false,
                is_trusted: false,
                signer_subject: None,
            };
        }

        if !self.cfg.allowlist.signer_subject_allow.is_empty() {
            let subj = trust
                .signer_subject
                .clone()
                .unwrap_or_default()
                .to_lowercase();

            let ok = self
                .cfg
                .allowlist
                .signer_subject_allow
                .iter()
                .any(|needle| subj.contains(needle));

            return sigcheck::TrustResult {
                is_signed: true,
                is_trusted: ok,
                signer_subject: trust.signer_subject,
            };
        }

        sigcheck::TrustResult {
            is_signed: true,
            is_trusted: true,
            signer_subject: trust.signer_subject,
        }
    }
}