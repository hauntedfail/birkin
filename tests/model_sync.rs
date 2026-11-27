//! Integration tests for `birkin hermes sync-models` and `birkin sync-models`.
//!
//! Covers positive drift detection / atomic apply / 0600 backup / idempotent re-check,
//! plus negative tests for transient 503/transport errors, `--prune` protection of
//! `model.default` / `fallback_providers` / `auxiliary.*`, and automatic rollback on
//! post-apply `verify_live` failure.

use birkin::constants::{EXIT_LIVE_CONTRACT, EXIT_LIVE_TRANSIENT, EXIT_PASS};
use birkin::model_sync::{sync_provider_models, ModelSyncMode};
use birkin::models::RuntimePolicy;
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::thread;
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_birkin");

fn spawn_mock_responses(responses: Vec<(&'static str, &'static str)>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock http");
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        for (status_line, body) in responses {
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

fn run_birkin_json(args: &[&str], expected_exit: i32) -> Value {
    let out = Command::new(BIN).args(args).output().expect("spawn birkin");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        code, expected_exit,
        "unexpected exit code for {args:?}\nstdout={stdout}\nstderr={stderr}"
    );
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON for {args:?}: {e}\nstdout={stdout}\nstderr={stderr}"))
}

#[cfg(unix)]
fn assert_mode_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "expected 0600 on {}, got {:04o}", path.display(), mode);
}

#[cfg(not(unix))]
fn assert_mode_0600(_path: &Path) {}

#[test]
fn sync_models_check_apply_and_recheck_lifecycle() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("config.yaml");
    let env_path = tmp.path().join(".env");
    fs::write(&env_path, "CUSTOM_API_KEY=test-token\n").unwrap();

    // 4 HTTP calls:
    // 1. default --check (detects missing + stale high + stale low)
    // 2. --apply fetch /models
    // 3. --apply post-write verify_live /models
    // 4. re-run --check (now synced -> exit 0)
    let catalog_body = concat!(
        r#"{"data":["#,
        r#"{"id":"group/keep","context_length":256000},"#,
        r#"{"id":"group/shrink","context_length":262144},"#,
        r#"{"id":"group/new","context_length":1000000},"#,
        r#"{"id":"group/vllm","max_model_len":65536}"#,
        r#"]}"#
    );
    let (base_url, handle) = spawn_mock_responses(vec![
        ("200 OK", catalog_body),
        ("200 OK", catalog_body),
        ("200 OK", catalog_body),
        ("200 OK", catalog_body),
    ]);

    let initial_yaml = format!(
        "model:\n  provider: custom\n  default: group/keep\n  base_url: {base_url}\nproviders:\n  custom:\n    base_url: {base_url}\n    key_env: CUSTOM_API_KEY\n    models:\n      group/keep:\n        context_length: 128000\n      group/shrink:\n        context_length: 512000\nfallback_providers: []\n"
    );
    fs::write(&cfg_path, &initial_yaml).unwrap();

    // 1. Default mode (neither --check nor --apply) acts as read-only --check -> exit 2
    let check1 = run_birkin_json(
        &[
            "hermes",
            "sync-models",
            "--config",
            cfg_path.to_str().unwrap(),
            "--env",
            env_path.to_str().unwrap(),
            "--provider",
            "custom",
            "--json",
        ],
        EXIT_LIVE_CONTRACT,
    );
    assert_eq!(check1["status"], "DRIFT");
    assert_eq!(check1["provider"], "custom");
    assert_eq!(check1["added"]["group/new"], 1000000);
    assert_eq!(check1["added"]["group/vllm"], 65536);
    assert_eq!(check1["updated"].as_array().unwrap().len(), 2);
    assert!(check1["removed"].as_array().unwrap().is_empty());
    assert!(check1["backup_path"].is_null());
    assert!(check1["birkin_live_exit"].is_null());
    assert_eq!(check1["catalog_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(check1["full_sha256"].as_str().unwrap().len(), 64);
    // Read-only check must not modify config.yaml
    assert_eq!(fs::read_to_string(&cfg_path).unwrap(), initial_yaml);

    // 2. Top-level alias `birkin sync-models --apply` writes atomically, creates 0600 backup, passes verify_live
    let applied = run_birkin_json(
        &[
            "sync-models",
            "--config",
            cfg_path.to_str().unwrap(),
            "--env",
            env_path.to_str().unwrap(),
            "--provider",
            "custom",
            "--apply",
            "--json",
        ],
        EXIT_PASS,
    );
    assert_eq!(applied["status"], "PASS");
    assert_eq!(applied["birkin_live_exit"], EXIT_PASS);
    let backup_str = applied["backup_path"].as_str().expect("backup_path set");
    let backup_path = Path::new(backup_str);
    assert!(backup_path.is_file(), "backup file should exist");
    assert_mode_0600(backup_path);
    assert_mode_0600(&cfg_path);
    assert_eq!(fs::read_to_string(backup_path).unwrap(), initial_yaml);

    // Verify written YAML values
    let updated_val: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(&cfg_path).unwrap()).unwrap();
    let models_map = &updated_val["providers"]["custom"]["models"];
    assert_eq!(models_map["group/keep"]["context_length"].as_u64(), Some(256000));
    assert_eq!(models_map["group/shrink"]["context_length"].as_u64(), Some(262144));
    assert_eq!(models_map["group/new"]["context_length"].as_u64(), Some(1000000));
    assert_eq!(models_map["group/vllm"]["context_length"].as_u64(), Some(65536));

    // 3. Re-running --check now exits 0 with empty diff
    let check2 = run_birkin_json(
        &[
            "hermes",
            "sync-models",
            "--config",
            cfg_path.to_str().unwrap(),
            "--env",
            env_path.to_str().unwrap(),
            "--provider",
            "custom",
            "--check",
            "--json",
        ],
        EXIT_PASS,
    );
    assert_eq!(check2["status"], "PASS");
    assert!(check2["added"].as_object().unwrap().is_empty());
    assert!(check2["updated"].as_array().unwrap().is_empty());
    assert!(check2["removed"].as_array().unwrap().is_empty());
    assert_eq!(check2["catalog_sha256"], check1["catalog_sha256"]);
    assert_eq!(check2["full_sha256"], check1["full_sha256"]);

    handle.join().unwrap();
}

#[test]
fn sync_models_full_sha256_changes_on_context_length_update() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("config.yaml");
    let (base_url, handle) = spawn_mock_responses(vec![
        ("200 OK", r#"{"data":[{"id":"group/a","context_length":128000}]}"#),
        ("200 OK", r#"{"data":[{"id":"group/a","context_length":256000}]}"#),
    ]);
    fs::write(
        &cfg_path,
        format!(
            "model:\n  provider: custom\n  default: group/a\nproviders:\n  custom:\n    base_url: {base_url}\n    models:\n      group/a:\n        context_length: 128000\n"
        ),
    )
    .unwrap();

    let policy = RuntimePolicy::default();
    let r1 = sync_provider_models(&cfg_path, None, &policy, Some("custom"), ModelSyncMode::Check, false, Some(2.0));
    let r2 = sync_provider_models(&cfg_path, None, &policy, Some("custom"), ModelSyncMode::Check, false, Some(2.0));
    handle.join().unwrap();

    assert_eq!(r1.exit_code, EXIT_PASS);
    assert_eq!(r2.exit_code, EXIT_LIVE_CONTRACT);
    assert_eq!(r1.catalog_sha256, r2.catalog_sha256, "model IDs unchanged");
    assert_ne!(r1.full_sha256, r2.full_sha256, "context_length changed");
}

#[test]
fn sync_models_transient_503_exits_3_and_touches_nothing() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("config.yaml");
    let (base_url, handle) = spawn_mock_responses(vec![
        ("503 Service Unavailable", r#"{"error":"upstream overloaded"}"#),
        ("503 Service Unavailable", r#"{"error":"upstream overloaded"}"#),
    ]);
    let initial_yaml = format!(
        "model:\n  provider: custom\n  default: group/a\nproviders:\n  custom:\n    base_url: {base_url}\n    models:\n      group/a:\n        context_length: 128000\n"
    );
    fs::write(&cfg_path, &initial_yaml).unwrap();

    let res_check = run_birkin_json(
        &["hermes", "sync-models", "--config", cfg_path.to_str().unwrap(), "--check", "--json"],
        EXIT_LIVE_TRANSIENT,
    );
    let res_apply = run_birkin_json(
        &["hermes", "sync-models", "--config", cfg_path.to_str().unwrap(), "--apply", "--json"],
        EXIT_LIVE_TRANSIENT,
    );
    handle.join().unwrap();

    assert_eq!(res_check["status"], "FAIL");
    assert_eq!(res_apply["status"], "FAIL");
    assert!(res_apply["backup_path"].is_null());
    assert_eq!(fs::read_to_string(&cfg_path).unwrap(), initial_yaml);
    let files: Vec<_> = fs::read_dir(tmp.path()).unwrap().collect();
    assert_eq!(files.len(), 1, "no backup or temp files should be created on 503");
}

#[test]
fn sync_models_prune_protects_default_fallback_and_auxiliary_models() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("config.yaml");
    let catalog_body = r#"{"data":[{"id":"group/active","context_length":256000}]}"#;
    let (base_url, handle) = spawn_mock_responses(vec![
        ("200 OK", catalog_body),
        ("200 OK", catalog_body),
        ("200 OK", catalog_body),
    ]);

    // 1. --check --prune refuses to prune default, fallback_providers, and auxiliary.* models
    let protected_yaml = format!(
        concat!(
            "model:\n  provider: custom\n  default: group/default-stale\n  base_url: {url}\n",
            "fallback_providers:\n  - provider: custom\n    model: group/fb-stale\n",
            "auxiliary:\n  compression:\n    provider: auto\n    model: group/aux-auto-stale\n",
            "  vision:\n    provider: custom\n    model: group/aux-custom-stale\n",
            "providers:\n  custom:\n    base_url: {url}\n    models:\n",
            "      group/active:\n        context_length: 256000\n",
            "      group/default-stale:\n        context_length: 128000\n",
            "      group/fb-stale:\n        context_length: 128000\n",
            "      group/aux-auto-stale:\n        context_length: 128000\n",
            "      group/aux-custom-stale:\n        context_length: 128000\n",
            "      group/orphan-stale:\n        context_length: 128000\n"
        ),
        url = base_url
    );
    fs::write(&cfg_path, &protected_yaml).unwrap();

    let policy = RuntimePolicy::default();
    let check = sync_provider_models(&cfg_path, None, &policy, Some("custom"), ModelSyncMode::Check, true, Some(2.0));
    assert_eq!(check.exit_code, EXIT_LIVE_CONTRACT);
    assert_eq!(check.removed, vec!["group/orphan-stale".to_string()]);
    for expected in [
        "group/default-stale",
        "group/fb-stale",
        "group/aux-auto-stale",
        "group/aux-custom-stale",
    ] {
        assert!(
            check.protected_skipped.iter().any(|m| m == expected),
            "expected {expected} to be protected, got {:?}",
            check.protected_skipped
        );
    }

    // 2. --apply --prune deletes only unreferenced orphan while keeping referenced fallback model
    let apply_yaml = format!(
        concat!(
            "model:\n  provider: custom\n  default: group/active\n  base_url: {url}\n",
            "fallback_providers:\n  - provider: custom\n    model: group/fb-stale\n",
            "providers:\n  custom:\n    base_url: {url}\n    models:\n",
            "      group/active:\n        context_length: 256000\n",
            "      group/fb-stale:\n        context_length: 128000\n",
            "      group/orphan-stale:\n        context_length: 128000\n"
        ),
        url = base_url
    );
    fs::write(&cfg_path, &apply_yaml).unwrap();

    let applied = sync_provider_models(&cfg_path, None, &policy, Some("custom"), ModelSyncMode::Apply, true, Some(2.0));
    handle.join().unwrap();

    assert_eq!(applied.exit_code, EXIT_PASS);
    assert_eq!(applied.birkin_live_exit, Some(EXIT_PASS));
    assert_eq!(applied.removed, vec!["group/orphan-stale".to_string()]);
    assert_eq!(applied.protected_skipped, vec!["group/fb-stale".to_string()]);

    let written: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(&cfg_path).unwrap()).unwrap();
    let models_map = written["providers"]["custom"]["models"].as_mapping().unwrap();
    assert!(models_map.contains_key(serde_yaml::Value::String("group/active".into())));
    assert!(models_map.contains_key(serde_yaml::Value::String("group/fb-stale".into())));
    assert!(!models_map.contains_key(serde_yaml::Value::String("group/orphan-stale".into())));
}

#[test]
fn sync_models_apply_rolls_back_on_verify_live_failure() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("config.yaml");

    // Request 1 (/models during sync): advertises group/new (drift), omits model.default group/missing
    // Request 2 (/models during post-apply verify_live): fails with LIVE_DEFAULT_MODEL_NOT_IN_CATALOG (exit 2)
    let catalog_body = r#"{"data":[{"id":"group/new","context_length":512000}]}"#;
    let (base_url, handle) = spawn_mock_responses(vec![
        ("200 OK", catalog_body),
        ("200 OK", catalog_body),
    ]);

    let initial_yaml = format!(
        "model:\n  provider: custom\n  default: group/missing\n  base_url: {base_url}\nproviders:\n  custom:\n    base_url: {base_url}\n    models:\n      group/missing:\n        context_length: 128000\nfallback_providers: []\n"
    );
    fs::write(&cfg_path, &initial_yaml).unwrap();

    let res = run_birkin_json(
        &[
            "hermes",
            "sync-models",
            "--config",
            cfg_path.to_str().unwrap(),
            "--provider",
            "custom",
            "--apply",
            "--json",
        ],
        EXIT_LIVE_CONTRACT,
    );
    handle.join().unwrap();

    assert_eq!(res["status"], "FAIL");
    assert_eq!(res["birkin_live_exit"], EXIT_LIVE_CONTRACT);
    let backup_str = res["backup_path"].as_str().expect("backup_path present on rollback");
    assert_mode_0600(Path::new(backup_str));
    assert_mode_0600(&cfg_path);
    // Config must be restored byte-for-byte to original content
    assert_eq!(fs::read_to_string(&cfg_path).unwrap(), initial_yaml);
    let findings = res["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["rule"] == "LIVE_DEFAULT_MODEL_NOT_IN_CATALOG"));
    assert!(findings.iter().any(|f| f["rule"] == "SYNC_APPLY_ROLLED_BACK"));
}

#[test]
fn sync_models_help_works_for_hermes_subcommand_and_top_level_alias() {
    for args in [&["hermes", "sync-models", "--help"][..], &["sync-models", "--help"][..]] {
        let out = Command::new(BIN).args(args).output().expect("spawn birkin --help");
        assert!(out.status.success(), "{args:?} failed");
        let stdout = String::from_utf8_lossy(&out.stdout);
        for flag in ["--provider", "--check", "--apply", "--prune", "--timeout", "--json"] {
            assert!(stdout.contains(flag), "missing {flag} in help output for {args:?}:\n{stdout}");
        }
    }
}
