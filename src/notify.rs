use crate::alerts::Alert;
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use windows::{
    core::HSTRING,
    Data::Xml::Dom::XmlDocument,
    UI::Notifications::{ToastNotification, ToastNotificationManager},
};

const APP_ID: &str =
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe";
const TOAST_SUPPRESS: Duration = Duration::from_secs(30);

static PID_TOAST_GATE: OnceLock<Mutex<HashMap<u32, Instant>>> = OnceLock::new();
static ACTIVE_TOASTS: OnceLock<Mutex<Vec<(Instant, ToastNotification)>>> = OnceLock::new();

fn should_toast(pid: u32) -> bool {
    if pid == 0 || pid == 4 {
        return false;
    }

    let gate = PID_TOAST_GATE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = gate.lock().unwrap();

    let now = Instant::now();
    map.retain(|_, t| now.duration_since(*t) < TOAST_SUPPRESS);

    if map.contains_key(&pid) {
        return false;
    }

    map.insert(pid, now);
    true
}

fn exe_basename(s: &str) -> &str {
    if let Some(i) = s.rfind('\\') {
        return &s[i + 1..];
    }
    if let Some(i) = s.rfind('/') {
        return &s[i + 1..];
    }
    s
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn verb_from_event(event_id: u16) -> &'static str {
    match event_id {
        12 => "accessed",
        _ => "touched",
    }
}

fn show_toast(headline: &str) -> windows::core::Result<()> {
    let xml = format!(
        r#"<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>{}</text>
      <text>{}</text>
    </binding>
  </visual>
</toast>"#,
        xml_escape("TITAN Operative Alert"),
        xml_escape(headline),
    );

    let doc = XmlDocument::new()?;
    doc.LoadXml(&HSTRING::from(xml))?;

    let toast = ToastNotification::CreateToastNotification(&doc)?;

    let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(APP_ID))?;
    notifier.Show(&toast)?;

    // Keep toast objects alive briefly (prevents premature drop issues)
    let now = Instant::now();
    let store = ACTIVE_TOASTS.get_or_init(|| Mutex::new(Vec::new()));
    let mut v = store.lock().unwrap();
    v.retain(|(t, _)| now.duration_since(*t) < Duration::from_secs(120));
    v.push((now, toast));

    Ok(())
}

pub fn toast_from_alert(alert: &Alert) {
    if !should_toast(alert.pid) {
        return;
    }

    let proc = exe_basename(&alert.process);
    let verb = verb_from_event(alert.event_id);
    let headline = format!("{proc} {verb} {}", alert.data_name);

    if let Err(e) = show_toast(&headline) {
        eprintln!("[TML][TOAST] {:?}", e);
    }
}