//! Hermes runtime verification tests: Layer 1 static/policy, Layer 2 live contract, Layer 3 drift.

use birkin::config_utils::{canonical_config_sha256, load_policy};
use birkin::constants::{EXIT_DRIFT, EXIT_LIVE_CONTRACT, EXIT_LIVE_TRANSIENT, EXIT_PASS, EXIT_STATIC};
use birkin::drift::verify_drift_with;
use birkin::live::verify_live;
use birkin::models::RuntimePolicy;
use birkin::static_check::verify_static;
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

fn valid_hermes_cfg(base_url: &str) -> Value {
    json!({
        "model": {
            "provider": "custom",
            "default": "group/lvmh",
            "base_url": base_url
        },
        "providers": {
            "custom": {
                "base_url": base_url,
                "api_key": "test-key",
                "models": {
                    "group/lvmh": { "context_length": 128000 }
                }
            }
        },
        "fallback_providers": [],
        "compression": {
            "enabled": true,
            "threshold": 0.75,
            "target_ratio": 0.50
        }
    })
}

fn spawn_mock_http(status_line: &'static str, body: &'static str, count: usize) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock http");
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        for _ in 0..count {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        }
    });
    (format!("http://{addr}/v1"), handle)
}

#[test]
fn static_passes_clean_config_and_rejects_forbidden_model_and_skill() {
    let tmp = TempDir::new().unwrap();
    let skills_dir = tmp.path().join("skills");
    fs::create_dir_all(skills_dir.join("good-skill")).unwrap();
    fs::write(
        skills_dir.join("good-skill").join("SKILL.md"),
        "---\nname: good-skill\n---\n# ok\n",
    )
    .unwrap();

    let policy = RuntimePolicy::default();
    let cfg = valid_hermes_cfg("http://127.0.0.1:3425/v1");
    let (code, findings) = verify_static(&cfg, &policy, None, Some(&skills_dir));
    assert_eq!(code, EXIT_PASS, "expected pass, got {findings:?}");

    // Negative: forbidden model pattern (*opus*)
    let mut bad_cfg = cfg.clone();
    bad_cfg["model"]["default"] = json!("anthropic/claude-opus-5");
    let (code2, f2) = verify_static(&bad_cfg, &policy, None, Some(&skills_dir));
    assert_eq!(code2, EXIT_STATIC);
    assert!(f2.iter().any(|f| f.rule == "POLICY_FORBIDDEN_DEFAULT_MODEL"));

    // Negative: forbidden skill name (*-hub)
    fs::create_dir_all(skills_dir.join("ops-hub")).unwrap();
    fs::write(
        skills_dir.join("ops-hub").join("SKILL.md"),
        "---\nname: ops-hub\n---\n# bad\n",
    )
    .unwrap();
    let (code3, f3) = verify_static(&cfg, &policy, None, Some(&skills_dir));
    assert_eq!(code3, EXIT_STATIC);
    assert!(f3.iter().any(|f| f.rule == "POLICY_FORBIDDEN_SKILL_NAME"));
}

#[test]
fn policy_loader_fails_closed_on_unknown_fields() {
    let tmp = TempDir::new().unwrap();
    let bad_policy = tmp.path().join("policy.yaml");
    fs::write(&bad_policy, "version: 1\nunknown_invented_key: true\n").unwrap();
    let err = load_policy(&bad_policy).unwrap_err();
    assert!(
        err.contains("unknown field"),
        "expected fail-closed unknown field error, got: {err}"
    );
}

#[test]
fn live_contract_pass_missing_model_and_transient() {
    let policy = RuntimePolicy::default();

    // Positive: /v1/models advertises group/lvmh with matching context_length
    let (url_ok, h_ok) = spawn_mock_http(
        "200 OK",
        r#"{"data":[{"id":"group/lvmh","context_length":128000}]}"#,
        1,
    );
    let (code, findings, _) = verify_live(&valid_hermes_cfg(&url_ok), &policy, None, false, Some(2.0));
    h_ok.join().unwrap();
    assert_eq!(code, EXIT_PASS, "expected live pass, got {findings:?}");

    // Negative contract: model absent from /v1/models -> EXIT_LIVE_CONTRACT
    let (url_miss, h_miss) = spawn_mock_http("200 OK", r#"{"data":[{"id":"other/model"}]}"#, 1);
    let (code_miss, f_miss, _) =
        verify_live(&valid_hermes_cfg(&url_miss), &policy, None, false, Some(2.0));
    h_miss.join().unwrap();
    assert_eq!(code_miss, EXIT_LIVE_CONTRACT);
    assert!(f_miss
        .iter()
        .any(|f| f.rule == "LIVE_DEFAULT_MODEL_NOT_IN_CATALOG"));

    // Negative transient: HTTP 429 -> EXIT_LIVE_TRANSIENT
    let (url_429, h_429) = spawn_mock_http("429 Too Many Requests", r#"{"error":"rate limit"}"#, 1);
    let (code_429, f_429, _) =
        verify_live(&valid_hermes_cfg(&url_429), &policy, None, false, Some(2.0));
    h_429.join().unwrap();
    assert_eq!(code_429, EXIT_LIVE_TRANSIENT);
    assert!(f_429.iter().any(|f| f.rule == "LIVE_TRANSIENT_HTTP"));
}

#[test]
fn drift_detects_stale_config_and_passes_when_current() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("state");
    fs::create_dir_all(&state_dir).unwrap();

    let cfg_path = home.join("config.yaml");
    let env_path = home.join(".env");
    fs::write(&cfg_path, "model:\n  default: group/lvmh\n").unwrap();
    fs::write(&env_path, "API_KEY=abc\n").unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let cfg_sha = canonical_config_sha256(&json!({"model": {"default": "group/lvmh"}}));

    // Positive: gateway started after config & .env, matching config_sha256, alive PID
    fs::write(
        state_dir.join("gateway.lifecycle.json"),
        serde_json::to_string(&json!({
            "pid": 4242,
            "create_time": now + 60.0,
            "config_sha256": cfg_sha,
            "code_sha": "abcdef123456"
        }))
        .unwrap(),
    )
    .unwrap();
    let policy = RuntimePolicy::default();
    let (code_ok, f_ok, _) = verify_drift_with(
        &cfg_path,
        &env_path,
        home,
        &policy,
        Some(&cfg_sha),
        |pid| pid == 4242,
        |_| Some("abcdef1234567890".into()),
    );
    assert_eq!(code_ok, EXIT_PASS, "expected drift pass, got {f_ok:?}");

    // Negative 1: gateway started BEFORE config.yaml mtime
    fs::write(
        state_dir.join("gateway.lifecycle.json"),
        serde_json::to_string(&json!({
            "pid": 4242,
            "create_time": now - 3600.0
        }))
        .unwrap(),
    )
    .unwrap();
    let (code_bad, f_bad, _) = verify_drift_with(
        &cfg_path,
        &env_path,
        home,
        &policy,
        Some(&cfg_sha),
        |pid| pid == 4242,
        |_| None,
    );
    assert_eq!(code_bad, EXIT_DRIFT);
    assert!(f_bad
        .iter()
        .any(|f| f.rule == "DRIFT_CONFIG_NEWER_THAN_GATEWAY"));

    // Negative 2: gateway_state.json records a mismatched loaded_config_sha256
    fs::write(
        home.join("gateway_state.json"),
        serde_json::to_string(&json!({
            "pid": 4242,
            "gateway_state": "running",
            "start_time": now + 60.0,
            "loaded_config_sha256": "000000000000deadbeef"
        }))
        .unwrap(),
    )
    .unwrap();
    let (code_sha, f_sha, _) = verify_drift_with(
        &cfg_path,
        &env_path,
        home,
        &policy,
        Some(&cfg_sha),
        |pid| pid == 4242,
        |_| None,
    );
    assert_eq!(code_sha, EXIT_DRIFT);
    assert!(f_sha.iter().any(|f| f.rule == "DRIFT_CONFIG_SHA_MISMATCH"));
}
