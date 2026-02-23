use crate::support::config::Config;
use anyhow::{Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub fn generate_sigma_rules(cfg: &Config, log_dir: &Path) -> Result<Option<PathBuf>> {
    if !cfg.siem.enabled || !cfg.siem.generate_sigma_rules {
        return Ok(None);
    }

    let out = PathBuf::from(&cfg.siem.sigma_rules_file);
    let output_path = if out.is_absolute() {
        out
    } else {
        log_dir.join(out)
    };

    let mut content = String::new();
    for rule in &cfg.watch.protected {
        let rule_id = stable_rule_id(&rule.substring);
        content.push_str("---\n");
        content.push_str(&format!("title: TITAN Vigil - {}\n", rule.name));
        content.push_str(&format!("id: {}\n", rule_id));
        content.push_str("status: stable\n");
        content.push_str("logsource:\n");
        content.push_str("  product: windows\n");
        content.push_str("  service: kernel-etw\n");
        content.push_str("  category: file_access\n");
        content.push_str("detection:\n");
        content.push_str("  selection:\n");
        content.push_str(&format!(
            "    data_name: '{}'\n",
            escape_single_quotes(&rule.name)
        ));
        content.push_str(&format!(
            "    target|contains: '{}'\n",
            escape_single_quotes(&rule.substring)
        ));
        content.push_str("  condition: selection\n");
        content.push_str("level: high\n");
        content.push_str("tags:\n");
        content.push_str("  - attack.collection\n");
        content.push_str("  - attack.credential_access\n");
    }

    fs::write(&output_path, content)
        .with_context(|| format!("failed to write sigma rules file {}", output_path.display()))?;
    Ok(Some(output_path))
}

fn stable_rule_id(rule: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in rule.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("titan-vigil-{hash:016x}")
}

fn escape_single_quotes(input: &str) -> String {
    input.replace('\'', "''")
}
