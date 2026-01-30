use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

fn main() {
    let patterns = vec![
        (r"\Google\Chrome\User Data\Default\Login Data", "Chrome Passwords"),
        (r"\Google\Chrome\User Data\Default\Network\Cookies", "Chrome Cookies"),
        (r"\BraveSoftware\Brave-Browser\User Data\Default\Login Data", "Brave Passwords"),
        (r"\BraveSoftware\Brave-Browser\User Data\Default\Network\Cookies", "Brave Cookies"),
        (r"\Microsoft\Edge\User Data\Default\Login Data", "MsEdge Passwords"),
        (r"\Microsoft\Edge\User Data\Default\Network\Cookies", "MsEdge Cookies"),
        (r"\Mozilla\Firefox\Profiles", "Firefox Profile Store"),
        (r"\discord\Local Storage\leveldb", "Discord Token Store"),
        (r"\.minecraft\", "Minecraft Data"),
        (r"\Roblox\cookies", "Roblox Cookies"),
    ];

    let local_appdata = env::var("LOCALAPPDATA").unwrap_or_default();
    let appdata = env::var("APPDATA").unwrap_or_default();

    let bases = vec![PathBuf::from(local_appdata), PathBuf::from(appdata)];

    println!("Scanning AppData folders + attempting opens on matches...\n");

    let mut found = 0;

    for base in bases {
        if base.as_os_str().is_empty() || !base.exists() {
            continue;
        }

        println!("Scanning: {}", base.display());

        // Recurse with read_dir (triggers dir enum ETW)
        visit_dir(&base, &patterns, &mut found);
    }

    println!("\nDone. Attempted access on {} matching paths.", found);
}

fn visit_dir(dir: &Path, patterns: &[(&str, &str)], found: &mut usize) {
    let Ok(entries) = fs::read_dir(dir) else { return; };

    for entry in entries.flatten() {
        let path = entry.path();
        let path_str = match path.to_str() {
            Some(s) => s.to_lowercase(),
            None => continue,
        };

        let mut is_match = false;
        let mut name = "";

        for (substr, n) in patterns {
            let substr_lower = substr.to_lowercase();
            if path_str.contains(&substr_lower) {
                is_match = true;
                name = n;
                break;
            }
        }

        if is_match {
            println!("MATCH + attempting open: {} → {}", name, path.display());
            *found += 1;

            let _ = File::open(&path);
        }

        if path.is_dir() {
            visit_dir(&path, patterns, found);
        }
    }
}