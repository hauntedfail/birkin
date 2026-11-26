//! Layer 3: Live Hermes gateway runtime drift verification.

use crate::config_utils::as_number;
use crate::constants::{EXIT_DRIFT, EXIT_PASS};
use crate::models::{Finding, RuntimePolicy};
use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::UNIX_EPOCH;

#[cfg(unix)]
pub fn pid_is_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // SAFETY: kill(pid, 0) checks process existence without sending a signal.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    err.raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
pub fn pid_is_alive(pid: i32) -> bool {
    pid > 0
}

pub fn git_head_sha(repo_dir: &Path) -> Option<String> {
    if !repo_dir.join(".git").exists() {
        return None;
    }
    let out = Command::new("git")
        .args(["-C", &repo_dir.to_string_lossy(), "rev-parse", "HEAD"])
        .output()
        .ok()?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }
    None
}

fn file_mtime_epoch(path: &Path) -> Option<f64> {
    let md = fs::metadata(path).ok()?;
    let modified = md.modified().ok()?;
    let dur = modified.duration_since(UNIX_EPOCH).ok()?;
    Some(dur.as_secs_f64())
}

fn epoch_to_iso(ts: f64) -> String {
    let secs = ts.trunc() as i64;
    let nanos = ((ts.fract()) * 1e9) as u32;
    DateTime::<Utc>::from_timestamp(secs, nanos)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| format!("{ts}"))
}

fn resolve_gateway_create_time(
    lifecycle: &Map<String, Value>,
    gw_state: &Map<String, Value>,
) -> Option<f64> {
    for key in ["create_time", "start_time"] {
        if let Some(v) = as_number(lifecycle.get(key)) {
            if v > 0.0 {
                return Some(v);
            }
        }
    }
    if let Some(val) = as_number(gw_state.get("start_time")) {
        if val > 0.0 {
            return Some(if val > 1e11 { val / 100.0 } else { val });
        }
    }
    None
}

fn drift_finding(
    rule: &str,
    message: String,
    remediation: String,
    details: BTreeMap<String, Value>,
) -> Finding {
    Finding {
        rule: rule.to_string(),
        severity: "error".to_string(),
        layer: "drift".to_string(),
        message,
        remediation,
        details,
    }
}

pub fn verify_drift(
    config_path: &Path,
    env_path: &Path,
    hermes_home: &Path,
    policy: &RuntimePolicy,
    config_sha256: Option<&str>,
) -> (i32, Vec<Finding>, Map<String, Value>) {
    verify_drift_with(
        config_path,
        env_path,
        hermes_home,
        policy,
        config_sha256,
        pid_is_alive,
        git_head_sha,
    )
}

pub fn verify_drift_with<F, G>(
    config_path: &Path,
    env_path: &Path,
    hermes_home: &Path,
    policy: &RuntimePolicy,
    config_sha256: Option<&str>,
    pid_alive_fn: F,
    git_head_fn: G,
) -> (i32, Vec<Finding>, Map<String, Value>)
where
    F: Fn(i32) -> bool,
    G: Fn(&Path) -> Option<String>,
{
    let mut findings = Vec::new();
    let lifecycle_path = hermes_home.join("state").join("gateway.lifecycle.json");
    let gw_state_path = hermes_home.join("gateway_state.json");

    let cfg_mtime = file_mtime_epoch(config_path);
    let env_mtime = file_mtime_epoch(env_path);

    let mut meta = Map::new();
    meta.insert("config_path".into(), json!(config_path.to_string_lossy()));
    meta.insert("config_mtime".into(), json!(cfg_mtime));
    meta.insert("env_mtime".into(), json!(env_mtime));
    meta.insert("gateway_pid".into(), Value::Null);
    meta.insert("gateway_create_time".into(), Value::Null);

    let mut lifecycle = Map::new();
    if lifecycle_path.exists() {
        match fs::read_to_string(&lifecycle_path)
            .map_err(|e| e.to_string())
            .and_then(|txt| serde_json::from_str::<Value>(&txt).map_err(|e| e.to_string()))
        {
            Ok(Value::Object(m)) => lifecycle = m,
            Ok(_) => findings.push(drift_finding(
                "DRIFT_LIFECYCLE_UNREADABLE",
                format!("Could not parse {}: expected JSON object", lifecycle_path.display()),
                "Inspect gateway lifecycle state file.".into(),
                BTreeMap::new(),
            )),
            Err(err) => findings.push(drift_finding(
                "DRIFT_LIFECYCLE_UNREADABLE",
                format!("Could not parse {}: {err}", lifecycle_path.display()),
                "Inspect gateway lifecycle state file.".into(),
                BTreeMap::new(),
            )),
        }
    }

    let mut gw_state = Map::new();
    if gw_state_path.exists() {
        match fs::read_to_string(&gw_state_path)
            .map_err(|e| e.to_string())
            .and_then(|txt| serde_json::from_str::<Value>(&txt).map_err(|e| e.to_string()))
        {
            Ok(Value::Object(m)) => gw_state = m,
            Ok(_) => findings.push(drift_finding(
                "DRIFT_GATEWAY_STATE_UNREADABLE",
                format!("Could not parse {}: expected JSON object", gw_state_path.display()),
                "Inspect gateway_state.json or restart the gateway.".into(),
                BTreeMap::new(),
            )),
            Err(err) => findings.push(drift_finding(
                "DRIFT_GATEWAY_STATE_UNREADABLE",
                format!("Could not parse {}: {err}", gw_state_path.display()),
                "Inspect gateway_state.json or restart the gateway.".into(),
                BTreeMap::new(),
            )),
        }
    }

    let pid_val = lifecycle.get("pid").or_else(|| gw_state.get("pid"));
    let create_time = resolve_gateway_create_time(&lifecycle, &gw_state);
    meta.insert("gateway_pid".into(), pid_val.cloned().unwrap_or(Value::Null));
    meta.insert("gateway_create_time".into(), json!(create_time));

    let pid_int = match pid_val.and_then(Value::as_i64) {
        Some(p) if p > 0 => p as i32,
        _ => {
            findings.push(drift_finding(
                "DRIFT_GATEWAY_PID_MISSING",
                "No valid live gateway PID found in gateway.lifecycle.json or gateway_state.json.".into(),
                "Start or restart the gateway (`hermes gateway status`) or pass --skip-drift for CLI-only runs.".into(),
                BTreeMap::new(),
            ));
            return (EXIT_DRIFT, findings, meta);
        }
    };

    if !pid_alive_fn(pid_int) {
        let mut details = BTreeMap::new();
        details.insert("pid".into(), json!(pid_int));
        findings.push(drift_finding(
            "DRIFT_GATEWAY_NOT_ALIVE",
            format!("Recorded gateway PID {pid_int} is no longer running."),
            "Restart the Hermes gateway from a separate shell.".into(),
            details,
        ));
        return (EXIT_DRIFT, findings, meta);
    }

    if let Some(state_str) = gw_state.get("gateway_state").and_then(Value::as_str) {
        if !state_str.is_empty() && state_str != "running" {
            let mut details = BTreeMap::new();
            details.insert("pid".into(), json!(pid_int));
            details.insert("gateway_state".into(), json!(state_str));
            findings.push(drift_finding(
                "DRIFT_GATEWAY_NOT_RUNNING",
                format!("gateway_state.json reports gateway_state={state_str:?} for PID {pid_int}."),
                "Inspect `hermes gateway status` and restart if needed.".into(),
                details,
            ));
        }
    }

    let loaded_cfg_sha = gw_state.get("loaded_config_sha256").and_then(Value::as_str);
    let mut config_checked_by_hash = false;
    if let (Some(loaded), Some(on_disk)) = (loaded_cfg_sha, config_sha256) {
        if !loaded.is_empty() {
            config_checked_by_hash = true;
            meta.insert("loaded_config_sha256".into(), json!(loaded));
            if loaded != on_disk {
                let mut details = BTreeMap::new();
                details.insert("pid".into(), json!(pid_int));
                details.insert("loaded_config_sha256".into(), json!(loaded));
                details.insert("on_disk_config_sha256".into(), json!(on_disk));
                findings.push(drift_finding(
                    "DRIFT_CONFIG_SHA_MISMATCH",
                    format!(
                        "Gateway loaded config_sha256={}, but on-disk config.yaml is {}.",
                        loaded.chars().take(12).collect::<String>(),
                        on_disk.chars().take(12).collect::<String>()
                    ),
                    "Run `hermes gateway restart` from a separate shell to load the current config.".into(),
                    details,
                ));
            }
        }
    }

    let needs_mtime_check = (policy.drift_invariants.check_config_mtime_vs_gateway_start
        && !config_checked_by_hash)
        || policy.drift_invariants.check_env_mtime_vs_gateway_start;

    if let Some(ct) = create_time {
        let gw_iso = epoch_to_iso(ct);
        meta.insert("gateway_started_utc".into(), json!(gw_iso));

        if policy.drift_invariants.check_config_mtime_vs_gateway_start && !config_checked_by_hash {
            if let Some(cm) = cfg_mtime {
                if cm > ct {
                    let cfg_iso = epoch_to_iso(cm);
                    let mut details = BTreeMap::new();
                    details.insert("pid".into(), json!(pid_int));
                    details.insert("gateway_create_time".into(), json!(ct));
                    details.insert("config_mtime".into(), json!(cm));
                    findings.push(drift_finding(
                        "DRIFT_CONFIG_NEWER_THAN_GATEWAY",
                        format!(
                            "config.yaml was modified at {cfg_iso}, after gateway PID {pid_int} started at {gw_iso} (in-memory config/fallback_providers may be stale)."
                        ),
                        "Run `hermes gateway restart` from a separate shell to load the current config.".into(),
                        details,
                    ));
                }
            }
        }

        if policy.drift_invariants.check_env_mtime_vs_gateway_start {
            if let Some(em) = env_mtime {
                if em > ct {
                    let env_iso = epoch_to_iso(em);
                    let mut details = BTreeMap::new();
                    details.insert("pid".into(), json!(pid_int));
                    details.insert("gateway_create_time".into(), json!(ct));
                    details.insert("env_mtime".into(), json!(em));
                    findings.push(drift_finding(
                        "DRIFT_ENV_NEWER_THAN_GATEWAY",
                        format!(
                            ".env was modified at {env_iso}, after gateway PID {pid_int} started at {gw_iso}."
                        ),
                        "Run `/reload` or `hermes gateway restart` from a separate shell.".into(),
                        details,
                    ));
                }
            }
        }
    } else if needs_mtime_check {
        let mut details = BTreeMap::new();
        details.insert("pid".into(), json!(pid_int));
        findings.push(drift_finding(
            "DRIFT_GATEWAY_START_TIME_MISSING",
            format!("Could not determine start/create time for gateway PID {pid_int}."),
            "Ensure gateway.lifecycle.json or gateway_state.json records start_time, or restart the gateway.".into(),
            details,
        ));
    }

    if policy.drift_invariants.check_code_sha_vs_repo_head {
        let recorded_sha = lifecycle
            .get("code_sha")
            .or_else(|| gw_state.get("code_sha"))
            .and_then(Value::as_str);
        if let Some(rec) = recorded_sha {
            if !rec.is_empty() {
                if let Some(head) = git_head_fn(&hermes_home.join("hermes-agent")) {
                    meta.insert("recorded_code_sha".into(), json!(rec));
                    meta.insert("repo_head_sha".into(), json!(head));
                    if !head.starts_with(rec) && !rec.starts_with(&head) {
                        let mut details = BTreeMap::new();
                        details.insert("recorded_code_sha".into(), json!(rec));
                        details.insert("repo_head_sha".into(), json!(head));
                        findings.push(drift_finding(
                            "DRIFT_CODE_SHA_MISMATCH",
                            format!(
                                "Gateway running code_sha={}, but repo HEAD is {}.",
                                rec.chars().take(12).collect::<String>(),
                                head.chars().take(12).collect::<String>()
                            ),
                            "Restart the Hermes gateway so it runs the current checkout.".into(),
                            details,
                        ));
                    }
                }
            }
        }
    }

    let exit_code = if findings.iter().any(|f| f.severity == "error") {
        EXIT_DRIFT
    } else {
        EXIT_PASS
    };
    (exit_code, findings, meta)
}
