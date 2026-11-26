//! Isolated tempdir tests for deterministic cross-client adapter sync and drift detection.
//!
//! Never reads or writes live user home directories (`~/.hermes`, `~/.agents`, `~/.claude`, `~/.codex`).

use birkin::client_sync::{
    compute_bundle_sha256, render_adapters, run_client_sync, SyncMode, SyncState, SyncTarget,
    BIRKIN_VERSION, CONTRACT_VERSION, MANAGED_MARKER,
};
use birkin::config_utils::sha256_hex;
use birkin::constants::{EXIT_DRIFT, EXIT_PASS, EXIT_STATIC, EXIT_TOOL_ERROR};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_birkin");

fn run_birkin(args: &[&str], workdir: &Path, ledger_dir: &Path) -> Output {
    Command::new(BIN)
        .args(args)
        .current_dir(workdir)
        .env("BIRKIN_LEDGER_DIR", ledger_dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("spawn birkin binary")
}

fn run_sync_json(args: &[&str], workdir: &Path, ledger_dir: &Path, expected_code: i32) -> Value {
    let out = run_birkin(args, workdir, ledger_dir);
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        code, expected_code,
        "unexpected exit code for {args:?}\nstdout={stdout}\nstderr={stderr}"
    );
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON for {args:?}: {e}\nstdout={stdout}\nstderr={stderr}"))
}

#[test]
fn sync_check_empty_root_exits_drift_and_writes_nothing() {
    let tmp = TempDir::new().unwrap();
    let target_root = tmp.path().join("target");
    let ledger_dir = tmp.path().join("ledger");
    fs::create_dir_all(&target_root).unwrap();

    let report = run_sync_json(
        &[
            "sync",
            "--check",
            "--target-root",
            target_root.to_str().unwrap(),
            "--json",
            "--no-receipt",
        ],
        tmp.path(),
        &ledger_dir,
        EXIT_DRIFT,
    );

    assert_eq!(report["command"], "sync");
    assert_eq!(report["mode"], "check");
    assert_eq!(report["status"], "DRIFT");
    assert_eq!(report["exit_code"], EXIT_DRIFT);
    assert_eq!(report["contract_version"], CONTRACT_VERSION);
    assert_eq!(report["bundle_sha256"].as_str().unwrap().len(), 64);

    let targets = report["targets"].as_array().unwrap();
    assert_eq!(targets.len(), 10, "expected 1 git + 1 claude + 2 hermes + 6 skills");
    for entry in targets {
        assert_eq!(entry["state"], "missing", "entry={entry}");
        assert!(entry["actual_sha256"].is_null());
        assert_eq!(entry["expected_sha256"].as_str().unwrap().len(), 64);
        assert!(!entry["diff"].as_array().unwrap().is_empty());
    }

    // --check must be strictly read-only and create nothing inside target_root or ledger_dir.
    assert_eq!(fs::read_dir(&target_root).unwrap().count(), 0);
    assert!(!ledger_dir.exists());
}

#[test]
fn sync_apply_is_deterministic_idempotent_and_check_passes() {
    let tmp = TempDir::new().unwrap();
    let target_root = tmp.path().join("target");
    let ledger_dir = tmp.path().join("ledger");
    fs::create_dir_all(&target_root).unwrap();

    // 1. Initial --apply writes all managed adapters and exits 0.
    let first = run_sync_json(
        &[
            "sync",
            "--apply",
            "--target-root",
            target_root.to_str().unwrap(),
            "--json",
            "--no-receipt",
        ],
        tmp.path(),
        &ledger_dir,
        EXIT_PASS,
    );
    assert_eq!(first["status"], "PASS");
    assert_eq!(first["exit_code"], EXIT_PASS);
    let first_targets = first["targets"].as_array().unwrap();
    assert_eq!(first_targets.len(), 10);

    let mut snapshot: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for entry in first_targets {
        assert_eq!(entry["state"], "applied", "entry={entry}");
        let rel = entry["relative_path"].as_str().unwrap();
        let expected_sha = entry["expected_sha256"].as_str().unwrap();
        let template_sha = entry["template_sha256"].as_str().unwrap();
        assert_eq!(entry["actual_sha256"].as_str(), Some(expected_sha));

        let full = target_root.join(rel);
        let bytes = fs::read(&full).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.contains(MANAGED_MARKER), "{rel} missing managed marker");
        assert!(text.contains(BIRKIN_VERSION), "{rel} missing birkin version");
        assert!(text.contains(template_sha), "{rel} missing template_sha256");
        assert_eq!(sha256_hex(&bytes), expected_sha, "{rel} sha mismatch");

        #[cfg(unix)]
        if entry["executable"].as_bool().unwrap() {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::symlink_metadata(&full).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755, "{rel} should be 0o755");
        }
        snapshot.insert(rel.to_string(), bytes);
    }

    // Verify specific adapter payloads.
    let git_text = String::from_utf8(snapshot["git-hooks/pre-commit"].clone()).unwrap();
    assert!(git_text.contains("BIRKIN_SKIP_HOOK"));
    assert!(git_text.contains("birkin hook pre-commit"));

    let claude_json: Value = serde_json::from_slice(&snapshot["claude/birkin-hooks.json"]).unwrap();
    assert_eq!(claude_json["_birkin_managed"]["marker"], MANAGED_MARKER);
    assert_eq!(claude_json["_birkin_managed"]["version"], BIRKIN_VERSION);
    let claude_cmd = claude_json["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(claude_cmd.contains("birkin hook post-edit --surface claude"));

    for shim in [
        "skills/birkin/plan-verify.sh",
        "skills/birkin/unit-admit.sh",
        "skills/birkin/scope-check.sh",
        "skills/birkin/stage-verify.sh",
        "skills/birkin/sawyer-verify.sh",
        "skills/birkin/review-closure.sh",
    ] {
        assert!(snapshot.contains_key(shim), "missing skill shim {shim}");
    }

    // 2. Immediate second --apply is idempotent (byte-for-byte identical, exits 0).
    let second = run_sync_json(
        &[
            "sync",
            "--apply",
            "--target-root",
            target_root.to_str().unwrap(),
            "--json",
            "--no-receipt",
        ],
        tmp.path(),
        &ledger_dir,
        EXIT_PASS,
    );
    assert_eq!(second["status"], "PASS");
    assert_eq!(second["bundle_sha256"], first["bundle_sha256"]);
    for entry in second["targets"].as_array().unwrap() {
        assert_eq!(entry["state"], "synchronized", "entry={entry}");
        let rel = entry["relative_path"].as_str().unwrap();
        assert_eq!(fs::read(target_root.join(rel)).unwrap(), snapshot[rel]);
    }

    // 3. --check --json exits 0 with all targets synchronized.
    let check = run_sync_json(
        &[
            "sync",
            "--check",
            "--target-root",
            target_root.to_str().unwrap(),
            "--json",
            "--no-receipt",
        ],
        tmp.path(),
        &ledger_dir,
        EXIT_PASS,
    );
    assert_eq!(check["status"], "PASS");
    assert_eq!(check["exit_code"], EXIT_PASS);
    for entry in check["targets"].as_array().unwrap() {
        assert_eq!(entry["state"], "synchronized");
        assert!(entry["diff"].as_array().unwrap().is_empty());
    }

    // 4. Library API produces identical deterministic bundle hash on a fresh tempdir.
    let api_root = tmp.path().join("api-root");
    fs::create_dir_all(&api_root).unwrap();
    let expected_bundle = compute_bundle_sha256(&render_adapters(&SyncTarget::ALL));
    let api_apply = run_client_sync(&api_root, SyncMode::Apply, &SyncTarget::ALL).unwrap();
    assert_eq!(api_apply.exit_code, EXIT_PASS);
    assert_eq!(api_apply.bundle_sha256, expected_bundle);
    assert_eq!(api_apply.bundle_sha256, first["bundle_sha256"].as_str().unwrap());
    let api_check = run_client_sync(&api_root, SyncMode::Check, &SyncTarget::ALL).unwrap();
    assert_eq!(api_check.exit_code, EXIT_PASS);
    assert!(api_check.targets.iter().all(|t| t.state == SyncState::Synchronized));
}

#[test]
fn sync_tampered_managed_adapter_detected_and_repaired() {
    let tmp = TempDir::new().unwrap();
    let target_root = tmp.path().join("target");
    let ledger_dir = tmp.path().join("ledger");
    fs::create_dir_all(&target_root).unwrap();

    run_sync_json(
        &["sync", "--apply", "--target-root", target_root.to_str().unwrap(), "--json", "--no-receipt"],
        tmp.path(),
        &ledger_dir,
        EXIT_PASS,
    );

    let git_path = target_root.join("git-hooks/pre-commit");
    let original_git = fs::read_to_string(&git_path).unwrap();
    fs::write(&git_path, format!("{original_git}# local tamper line\n")).unwrap();

    let check = run_sync_json(
        &["sync", "--check", "--target-root", target_root.to_str().unwrap(), "--json", "--no-receipt"],
        tmp.path(),
        &ledger_dir,
        EXIT_DRIFT,
    );
    assert_eq!(check["status"], "DRIFT");
    let git_entry = check["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["relative_path"] == "git-hooks/pre-commit")
        .unwrap();
    assert_eq!(git_entry["state"], "stale");
    assert_ne!(git_entry["actual_sha256"], git_entry["expected_sha256"]);
    assert!(!git_entry["diff"].as_array().unwrap().is_empty());

    // --apply repairs the stale managed file back to exact canonical content.
    let repair = run_sync_json(
        &["sync", "--apply", "--target-root", target_root.to_str().unwrap(), "--json", "--no-receipt"],
        tmp.path(),
        &ledger_dir,
        EXIT_PASS,
    );
    let repaired_git = repair["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["relative_path"] == "git-hooks/pre-commit")
        .unwrap();
    assert_eq!(repaired_git["state"], "applied");
    assert_eq!(fs::read_to_string(&git_path).unwrap(), original_git);

    run_sync_json(
        &["sync", "--check", "--target-root", target_root.to_str().unwrap(), "--json", "--no-receipt"],
        tmp.path(),
        &ledger_dir,
        EXIT_PASS,
    );
}

#[test]
fn sync_unmanaged_regular_file_refused_without_overwrite() {
    let tmp = TempDir::new().unwrap();
    let target_root = tmp.path().join("target");
    let ledger_dir = tmp.path().join("ledger");
    fs::create_dir_all(target_root.join("git-hooks")).unwrap();

    let custom_hook = "#!/bin/sh\necho user-owned-pre-commit-hook\n";
    let hook_path = target_root.join("git-hooks/pre-commit");
    fs::write(&hook_path, custom_hook).unwrap();

    // --check reports drift (exit 4) with state=unmanaged.
    let check = run_sync_json(
        &["sync", "--check", "--target-root", target_root.to_str().unwrap(), "--target", "git", "--json", "--no-receipt"],
        tmp.path(),
        &ledger_dir,
        EXIT_DRIFT,
    );
    assert_eq!(check["targets"][0]["state"], "unmanaged");
    assert_eq!(fs::read_to_string(&hook_path).unwrap(), custom_hook);

    // --apply refuses to overwrite (exit 1) and preserves unmanaged content verbatim.
    let apply = run_sync_json(
        &["sync", "--apply", "--target-root", target_root.to_str().unwrap(), "--target", "git", "--json", "--no-receipt"],
        tmp.path(),
        &ledger_dir,
        EXIT_STATIC,
    );
    assert_eq!(apply["status"], "FAIL");
    assert_eq!(apply["targets"][0]["state"], "unmanaged");
    assert_eq!(fs::read_to_string(&hook_path).unwrap(), custom_hook);
}

#[cfg(unix)]
#[test]
fn unix_sync_symlink_refused_for_leaf_and_parent_dirs() {
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new().unwrap();
    let target_root = tmp.path().join("target");
    let outside = tmp.path().join("outside");
    let ledger_dir = tmp.path().join("ledger");
    fs::create_dir_all(target_root.join("git-hooks")).unwrap();
    fs::create_dir_all(target_root.join("claude")).unwrap();
    fs::create_dir_all(target_root.join("hermes")).unwrap();
    fs::create_dir_all(target_root.join("internal-real")).unwrap();
    fs::create_dir_all(outside.join("skills-outside")).unwrap();

    // 1. Leaf symlink pointing outside target_root.
    let outside_victim = outside.join("victim.sh");
    let sentinel = "#!/bin/sh\necho untouched-outside-target\n";
    fs::write(&outside_victim, sentinel).unwrap();
    symlink(&outside_victim, target_root.join("git-hooks/pre-commit")).unwrap();

    // 2. Dangling leaf symlink.
    let dangling_dest = outside.join("must-never-be-created.json");
    symlink(&dangling_dest, target_root.join("claude/birkin-hooks.json")).unwrap();

    // 3. Parent directory symlink pointing outside target_root.
    symlink(outside.join("skills-outside"), target_root.join("skills")).unwrap();

    // 4. Intermediate directory symlink pointing inside target_root.
    symlink(target_root.join("internal-real"), target_root.join("hermes/plugins")).unwrap();

    // --check must exit 4 and mark every single target symlink_refused without reading/writing targets.
    let check = run_sync_json(
        &["sync", "--check", "--target-root", target_root.to_str().unwrap(), "--json", "--no-receipt"],
        tmp.path(),
        &ledger_dir,
        EXIT_DRIFT,
    );
    assert_eq!(check["targets"].as_array().unwrap().len(), 10);
    for entry in check["targets"].as_array().unwrap() {
        assert_eq!(entry["state"], "symlink_refused", "entry={entry}");
        assert!(entry["actual_sha256"].is_null());
    }

    // --apply must exit 1 and refuse every single target without touching any symlink destination.
    let apply = run_sync_json(
        &["sync", "--apply", "--target-root", target_root.to_str().unwrap(), "--json", "--no-receipt"],
        tmp.path(),
        &ledger_dir,
        EXIT_STATIC,
    );
    assert_eq!(apply["status"], "FAIL");
    for entry in apply["targets"].as_array().unwrap() {
        assert_eq!(entry["state"], "symlink_refused", "entry={entry}");
    }

    // Verify zero side effects on symlink targets.
    assert_eq!(fs::read_to_string(&outside_victim).unwrap(), sentinel);
    assert!(!dangling_dest.exists(), "dangling symlink destination must not be created");
    assert_eq!(fs::read_dir(outside.join("skills-outside")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(target_root.join("internal-real")).unwrap().count(), 0);

    // 5. Symlinked --target-root itself fails closed with EXIT_TOOL_ERROR (5).
    let root_link = tmp.path().join("root-link");
    symlink(&outside, &root_link).unwrap();
    let bad_root = run_sync_json(
        &["sync", "--apply", "--target-root", root_link.to_str().unwrap(), "--json", "--no-receipt"],
        tmp.path(),
        &ledger_dir,
        EXIT_TOOL_ERROR,
    );
    assert_eq!(bad_root["exit_code"], EXIT_TOOL_ERROR);
}

#[test]
fn sync_target_filtering_invalid_flags_and_optional_receipt() {
    let tmp = TempDir::new().unwrap();
    let target_root = tmp.path().join("target");
    let ledger_dir = tmp.path().join("ledger");
    fs::create_dir_all(&target_root).unwrap();

    // 1. --target git filters to only git adapter and leaves other dirs absent.
    let git_only = run_sync_json(
        &[
            "sync", "--apply", "--target-root", target_root.to_str().unwrap(),
            "--target", "git", "--json", "--no-receipt",
        ],
        tmp.path(),
        &ledger_dir,
        EXIT_PASS,
    );
    assert_eq!(git_only["targets"].as_array().unwrap().len(), 1);
    assert_eq!(git_only["targets"][0]["target"], "git");
    assert!(target_root.join("git-hooks/pre-commit").is_file());
    assert!(!target_root.join("claude").exists());
    assert!(!target_root.join("hermes").exists());
    assert!(!target_root.join("skills").exists());

    // 2. Unknown --target -> exit 5.
    let bad_target = run_sync_json(
        &[
            "sync", "--check", "--target-root", target_root.to_str().unwrap(),
            "--target", "nonexistent", "--json", "--no-receipt",
        ],
        tmp.path(),
        &ledger_dir,
        EXIT_TOOL_ERROR,
    );
    assert_eq!(bad_target["exit_code"], EXIT_TOOL_ERROR);

    // 3. Neither --check nor --apply -> exit 5.
    let neither = run_sync_json(
        &["sync", "--target-root", target_root.to_str().unwrap(), "--json"],
        tmp.path(),
        &ledger_dir,
        EXIT_TOOL_ERROR,
    );
    assert_eq!(neither["exit_code"], EXIT_TOOL_ERROR);

    // 4. Both --check and --apply -> exit 5.
    let both = run_sync_json(
        &["sync", "--check", "--apply", "--target-root", target_root.to_str().unwrap(), "--json"],
        tmp.path(),
        &ledger_dir,
        EXIT_TOOL_ERROR,
    );
    assert_eq!(both["exit_code"], EXIT_TOOL_ERROR);

    // 5. Missing --target-root -> exit 5 (never defaults to $HOME).
    let no_root = run_sync_json(&["sync", "--check", "--json"], tmp.path(), &ledger_dir, EXIT_TOOL_ERROR);
    assert_eq!(no_root["exit_code"], EXIT_TOOL_ERROR);

    // 6. Non-existent --target-root -> exit 5.
    let missing_root = tmp.path().join("does-not-exist");
    let bad_dir = run_sync_json(
        &["sync", "--check", "--target-root", missing_root.to_str().unwrap(), "--json"],
        tmp.path(),
        &ledger_dir,
        EXIT_TOOL_ERROR,
    );
    assert_eq!(bad_dir["exit_code"], EXIT_TOOL_ERROR);

    // 7. Optional --repo records receipt even when --target-root is outside --repo and not a Git repo.
    let repo_dir = tmp.path().join("sample-repo");
    fs::create_dir_all(repo_dir.join(".birkin")).unwrap();
    fs::write(tmp.path().join("empty.gitconfig"), "").unwrap();
    fs::write(
        repo_dir.join(".birkin/config.yaml"),
        "version: 1\nproject:\n  name: sync-receipt-demo\n  languages: [rust]\ntelemetry:\n  enabled: true\n",
    )
    .unwrap();
    let run_git = |args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .current_dir(&repo_dir)
            .env("GIT_CONFIG_GLOBAL", tmp.path().join("empty.gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "Birkin Test")
            .env("GIT_COMMITTER_NAME", "Birkin Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    };
    run_git(&["init", "-q", "-b", "main"]);
    run_git(&["add", "."]);
    run_git(&["commit", "-qm", "init"]);

    let with_receipt = run_sync_json(
        &[
            "sync", "--check", "--target-root", target_root.to_str().unwrap(),
            "--target", "git", "--repo", repo_dir.to_str().unwrap(), "--json",
        ],
        tmp.path(),
        &ledger_dir,
        EXIT_PASS,
    );
    assert!(
        with_receipt["receipt_sha256"].as_str().is_some_and(|s| s.len() == 64),
        "expected recorded receipt_sha256: {with_receipt}"
    );
    assert!(with_receipt["receipt_error"].is_null());

    // 8. Also test unix mode drift detection and repair (chmod 0644 -> --check stale -> --apply 0755).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let hook = target_root.join("git-hooks/pre-commit");
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o644)).unwrap();
        let mode_drift = run_sync_json(
            &[
                "sync", "--check", "--target-root", target_root.to_str().unwrap(),
                "--target", "git", "--json", "--no-receipt",
            ],
            tmp.path(),
            &ledger_dir,
            EXIT_DRIFT,
        );
        assert_eq!(mode_drift["targets"][0]["state"], "stale");
        assert!(!mode_drift["targets"][0]["diff"].as_array().unwrap().is_empty());

        let repaired = run_sync_json(
            &[
                "sync", "--apply", "--target-root", target_root.to_str().unwrap(),
                "--target", "git", "--json", "--no-receipt",
            ],
            tmp.path(),
            &ledger_dir,
            EXIT_PASS,
        );
        assert_eq!(repaired["targets"][0]["state"], "applied");
        let mode = fs::symlink_metadata(&hook).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }
}
