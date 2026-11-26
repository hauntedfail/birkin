//! Human report formatting and atomic JSON state persistence.

use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

pub fn format_human(report: &Value) -> String {
    let cmd = report["command"].as_str().unwrap_or("");
    let status = report["status"].as_str().unwrap_or("");
    let exit_code = report["exit_code"].as_i64().unwrap_or(0);
    let sha = report["config_sha256"].as_str().unwrap_or("n/a");

    let mut lines = vec![
        format!("birkin ({cmd}): status={status} exit_code={exit_code}"),
        format!("  config_sha256: {sha}"),
    ];

    if let Some(sections) = report.get("sections").and_then(Value::as_object) {
        for (name, sec) in sections {
            let sec_code = sec["exit_code"].as_i64().unwrap_or(0);
            let findings = sec["findings"].as_array();
            let count = findings.map(|a| a.len()).unwrap_or(0);
            lines.push(format!("  [{name}] exit_code={sec_code} findings={count}"));
            if let Some(arr) = findings {
                for f in arr {
                    let rule = f["rule"].as_str().unwrap_or("");
                    let sev = f["severity"].as_str().unwrap_or("");
                    let msg = f["message"].as_str().unwrap_or("");
                    let rem = f["remediation"].as_str().unwrap_or("");
                    lines.push(format!("    - {rule} ({sev}): {msg}"));
                    lines.push(format!("      remediation: {rem}"));
                }
            }
        }
    }
    lines.join("\n")
}

/// Write report JSON atomically via temp file + rename in the target directory.
pub fn write_state_atomic(state_file: &Path, report: &Value) -> Result<(), String> {
    let parent = state_file.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|e| format!("Failed creating state dir {}: {e}", parent.display()))?;
    let payload = serde_json::to_string_pretty(report)
        .map_err(|e| format!("Failed serializing state JSON: {e}"))?;
    let mut tmp = NamedTempFile::new_in(parent)
        .map_err(|e| format!("Failed creating temp state file: {e}"))?;
    tmp.write_all(payload.as_bytes())
        .and_then(|_| tmp.write_all(b"\n"))
        .and_then(|_| tmp.as_file().sync_all())
        .map_err(|e| format!("Failed writing temp state file: {e}"))?;
    tmp.persist(state_file)
        .map_err(|e| format!("Failed persisting {}: {e}", state_file.display()))?;
    Ok(())
}
