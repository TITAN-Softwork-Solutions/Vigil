use crate::{
    alerts::Alert,
    config::{Config, RevocationMode},
    handles, process, wintrust,
};
use crossbeam_channel::Sender;
use parking_lot::Mutex;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    time::{Duration, Instant},
};

const WHITELIST_TTL: Duration = Duration::from_secs(10 * 60);
const WHITELIST_MAX: usize = 100_000;

#[derive(Debug, Clone)]
pub struct ProcMeta {
    pub image: String,
    pub ts: Instant,
    pub is_trusted_signed: bool,
}

#[derive(Debug)]
pub struct Engine {
    cfg: Config,
    alert_tx: Sender<Alert>,
    protected_exact_rules: BTreeMap<String, String>,
    protected_substring_rules: BTreeMap<String, String>,
    proc_cache: Mutex<HashMap<u32, ProcMeta>>,
    filekey_cache: Mutex<HashMap<u64, String>>,
    last_alert: Mutex<HashMap<u64, Instant>>,
    whitelisted_file_objects: Mutex<HashMap<u64, WhitelistedFileObject>>,
}

#[derive(Debug, Clone)]
struct WhitelistedFileObject {
    owners: HashSet<u32>,
    last_seen: Instant,
}

impl Engine {
    pub fn new(cfg: Config, alert_tx: Sender<Alert>) -> Self {
        let mut protected_exact_rules = BTreeMap::new();
        for rule in &cfg.watch.exact_paths {
            protected_exact_rules.insert(rule.substring.clone(), rule.name.clone());
        }

        let mut protected_substring_rules = BTreeMap::new();
        for rule in &cfg.watch.protected {
            protected_substring_rules.insert(rule.substring.clone(), rule.name.clone());
        }

        Self {
            cfg,
            alert_tx,
            protected_exact_rules,
            protected_substring_rules,
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

        let now = Instant::now();
        let mut wl = self.whitelisted_file_objects.lock();
        for (file_object, pids_set) in entries {
            let entry = wl
                .entry(file_object)
                .or_insert_with(|| WhitelistedFileObject {
                    owners: HashSet::new(),
                    last_seen: now,
                });
            entry.owners.extend(pids_set);
            entry.last_seen = now;
        }

        Ok(())
    }

    #[inline]
    pub fn on_process_start(&self, pid: u32, image: String, _cmdline: Option<String>) {
        let low = image.to_lowercase();
        if !low.ends_with(".exe") {
            return;
        }

        let (is_trusted, _) = self.trust_for_image(&image);

        self.proc_cache.lock().insert(
            pid,
            ProcMeta {
                image,
                ts: Instant::now(),
                is_trusted_signed: is_trusted,
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
        let (is_trusted, _) = self.trust_for_image(&img);

        self.proc_cache.lock().insert(
            pid,
            ProcMeta {
                image: img.clone(),
                ts: Instant::now(),
                is_trusted_signed: is_trusted,
            },
        );

        img
    }

    #[inline]
    pub fn match_protected_rule(&self, path: &str) -> Option<(String, String)> {
        let p = path.to_lowercase();
        if let Some(name) = self.protected_exact_rules.get(&p) {
            return Some((name.clone(), p));
        }

        for (needle, name) in &self.protected_substring_rules {
            if p.contains(needle) {
                return Some((name.clone(), needle.clone()));
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
        if pid == 0 || pid == 4 {
            return true;
        }

        if let Some(meta) = self.proc_cache.lock().get(&pid) {
            if meta.ts.elapsed() <= Duration::from_secs(60) {
                return meta.is_trusted_signed;
            }
        }

        let (is_trusted, _) = self.trust_for_image(proc_path);

        self.proc_cache.lock().insert(
            pid,
            ProcMeta {
                image: proc_path.to_string(),
                ts: Instant::now(),
                is_trusted_signed: is_trusted,
            },
        );

        is_trusted
    }

    #[inline]
    pub fn learn_whitelisted_file_object(&self, file_object: u64, pid: u32) {
        if file_object == 0 || pid == 0 || pid == 4 {
            return;
        }
        let now = Instant::now();
        let mut wl = self.whitelisted_file_objects.lock();

        if wl.len() > WHITELIST_MAX {
            wl.retain(|_, v| now.duration_since(v.last_seen) <= WHITELIST_TTL);
        }

        let entry = wl
            .entry(file_object)
            .or_insert_with(|| WhitelistedFileObject {
                owners: HashSet::new(),
                last_seen: now,
            });
        entry.owners.insert(pid);
        entry.last_seen = now;
    }

    #[inline]
    pub fn whitelisted_file_object_owner(&self, file_object: u64) -> Option<HashSet<u32>> {
        let now = Instant::now();
        let mut wl = self.whitelisted_file_objects.lock();
        let Some(entry) = wl.get(&file_object) else {
            return None;
        };

        if now.duration_since(entry.last_seen) > WHITELIST_TTL {
            wl.remove(&file_object);
            return None;
        }

        Some(entry.owners.clone())
    }

    fn dedupe_key(pid: u32, target: &str) -> u64 {
        let mut hash: u64 = 0xcbf29ce484222325;
        for b in pid.to_le_bytes() {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        for b in target.as_bytes() {
            hash ^= *b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
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
    fn trust_for_path(&self, path: &str) -> wintrust::TrustResult {
        let trust = wintrust::verify_file_signature(path, self.revocation_policy());

        if self.cfg.security.require_signature && !trust.is_signed {
            return wintrust::TrustResult {
                is_signed: false,
                is_trusted: false,
                signer_subject: None,
                signer_thumbprint: None,
            };
        }

        if let Some(thumbprint) = &trust.signer_thumbprint {
            let is_denylisted = self
                .cfg
                .security
                .denylisted_cert_thumbprints
                .iter()
                .any(|blocked| blocked == thumbprint);
            if is_denylisted {
                return wintrust::TrustResult {
                    is_signed: trust.is_signed,
                    is_trusted: false,
                    signer_subject: trust.signer_subject,
                    signer_thumbprint: trust.signer_thumbprint,
                };
            }
        }

        if !self.cfg.allowlist.signer_subject_allow.is_empty()
            && self.cfg.security.require_signer_allowlist
        {
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

            return wintrust::TrustResult {
                is_signed: trust.is_signed,
                is_trusted: ok && trust.is_trusted,
                signer_subject: trust.signer_subject,
                signer_thumbprint: trust.signer_thumbprint,
            };
        }

        wintrust::TrustResult {
            is_signed: trust.is_signed,
            is_trusted: trust.is_trusted,
            signer_subject: trust.signer_subject,
            signer_thumbprint: trust.signer_thumbprint,
        }
    }

    #[inline]
    fn trust_for_image(&self, path: &str) -> (bool, Option<String>) {
        if path == "unknown" || path == "SYSTEM" || path.is_empty() {
            return (false, None);
        }

        let trust = self.trust_for_path(path);
        let is_trusted = trust.is_trusted;
        let signer_subject = trust.signer_subject;

        let is_trusted = if self.cfg.security.allow_legacy_process_name_fallback {
            is_trusted || self.is_legacy_allowlisted_process_name(path)
        } else {
            is_trusted
        };

        (is_trusted, signer_subject)
    }

    fn revocation_policy(&self) -> wintrust::RevocationPolicy {
        match self.cfg.security.revocation_mode {
            RevocationMode::None => wintrust::RevocationPolicy::None,
            RevocationMode::Chain => wintrust::RevocationPolicy::WholeChain,
        }
    }
}
