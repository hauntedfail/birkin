//! Project-universal engine tests: multi-language DAG/cycle checks, invariants, guides,
//! hash-chained ledger receipts, telemetry/GC, hooks, and CLI binary end-to-end tests.

use birkin::constants::{EXIT_PASS, EXIT_STATIC};
use birkin::gc::run_gc_scan;
use birkin::guides::audit_guides;
use birkin::hooks::{install_claude_hook, install_git_pre_commit_hook, install_hermes_plugin};
use birkin::ledger::{append_receipt, read_receipts, resolve_ledger_path, verify_chain, verify_receipts_for_current_state};
use birkin::project_models::{load_project_spec, LayerSpec};
use birkin::sensors::{evaluate_regex_rules, find_layer_dag_cycles, run_project_sensors};
use birkin::steer::analyze_telemetry;
use chrono::NaiveDate;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn git(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Birkin Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Birkin Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

fn init_sample_repo() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    git(root, &["init", "-q"]);
    fs::create_dir_all(root.join(".birkin")).unwrap();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("AGENTS.md"),
        "# AGENTS.md\n\nLast reviewed: 2026-11-26\n\nSee [README.md](README.md).\n",
    )
    .unwrap();
    fs::write(root.join("README.md"), "# Sample\n").unwrap();
    fs::write(root.join("src/core.rs"), "pub fn version() -> u32 { 1 }\n").unwrap();
    fs::write(
        root.join("src/app.rs"),
        "use crate::core::version;\npub fn run() -> u32 { version() }\n",
    )
    .unwrap();
    fs::write(
        root.join(".birkin/config.yaml"),
        r#"version: 1
project:
  name: sample
  languages: [rust]
orientation:
  entry_docs: [AGENTS.md]
  max_entry_doc_lines: 100
  verify_markdown_links: true
  required_docs: [README.md]
  require_committed_spec: true
architecture:
  max_file_lines: 100
  layers:
    - name: core
      paths: ["src/core.rs"]
      allowed_dependencies: []
    - name: app
      paths: ["src/app.rs"]
      allowed_dependencies: [core]
verify:
  commands:
    - name: ok-cmd
      cmd: "true"
      kind: test
  check_ci_parity: false
invariants:
  forbid_secrets: true
  english_prose_only: true
  forbid_debug_leftovers: true
  custom_regex_rules:
    - id: no-unwrap-in-app
      globs: ["src/app.rs"]
      pattern: "\\.unwrap\\(\\)"
      severity: error
      message: "Avoid unwrap() in app."
      remediation: "Handle Result explicitly."
      examples_pass: ["let x = res?;"]
      examples_fail: ["let x = res.unwrap();"]
"#,
    )
    .unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "initial"]);
    tmp
}

#[test]
fn sensors_enforce_layer_dag_cycles_violations_and_invariants() {
    let tmp = init_sample_repo();
    let root = tmp.path();
    let (spec, _) = load_project_spec(root, None).unwrap();

    // Positive: clean repo passes sensors, guides, and eval-rules
    let (sf, _) = run_project_sensors(root, &spec, None);
    assert!(sf.is_empty(), "expected zero sensor findings, got {sf:?}");
    let gf = audit_guides(root, &spec, Some(NaiveDate::from_ymd_opt(2026, 11, 26).unwrap()));
    assert!(gf.is_empty(), "expected zero guide findings, got {gf:?}");
    assert_eq!(evaluate_regex_rules(&spec)["status"], "PASS");

    // Negative: upward layer violation (core -> app) + secret + debug + custom regex + non-English comment
    fs::write(
        root.join("src/core.rs"),
        concat!(
            "use crate::app::run;\n",
            "// 日本語コメント\n",
            "const TOK: &str = \"ghp_123456789012345678901234567890123456\";\n",
            "pub fn x() { ",
            "db",
            "g!(run()); }\n"
        ),
    )
    .unwrap();
    fs::write(
        root.join("src/app.rs"),
        "pub fn run() -> u32 { Some(1u32).unwrap() }\n",
    )
    .unwrap();
    let (bad, _) = run_project_sensors(root, &spec, None);
    let rules: Vec<&str> = bad.iter().map(|f| f.rule.as_str()).collect();
    assert!(rules.contains(&"ARCH_LAYER_VIOLATION"), "missing layer violation: {rules:?}");
    assert!(rules.iter().any(|r| r.starts_with("INVARIANT_SECRET_LEAK")), "missing secret leak: {rules:?}");
    assert!(rules.iter().any(|r| r.starts_with("INVARIANT_DEBUG_LEFTOVER")), "missing debug leftover: {rules:?}");
    assert!(rules.contains(&"INVARIANT_NON_ENGLISH_PROSE"), "missing prose rule: {rules:?}");
    assert!(rules.contains(&"CUSTOM_REGEX:no-unwrap-in-app"), "missing custom regex: {rules:?}");

    // Negative: cycle in declared layer DAG
    let cyclic = vec![
        LayerSpec {
            name: "a".into(),
            paths: vec!["src/a.rs".into()],
            allowed_dependencies: vec!["b".into()],
            remediation: String::new(),
        },
        LayerSpec {
            name: "b".into(),
            paths: vec!["src/b.rs".into()],
            allowed_dependencies: vec!["a".into()],
            remediation: String::new(),
        },
    ];
    assert!(!find_layer_dag_cycles(&cyclic).is_empty());
}

#[test]
fn ledger_hash_chain_tamper_detection_and_revision_pinning() {
    let tmp = init_sample_repo();
    let root = tmp.path();
    let (spec, _) = load_project_spec(root, None).unwrap();

    // Clean receipt recorded for exact HEAD + tree
    append_receipt(
        root,
        &spec,
        "check",
        "cli",
        "PASS",
        EXIT_PASS,
        12,
        &[],
        &[],
        serde_json::Map::new(),
    )
    .unwrap();
    let verified = verify_receipts_for_current_state(root, &spec, &["check".into()], true);
    assert_eq!(verified["status"], "PASS", "got {verified}");
    assert_eq!(verified["chain_ok"], true);

    // Dirtying a tracked file must invalidate the revision-pinned receipt
    fs::write(root.join("src/core.rs"), "pub fn version() -> u32 { 2 }\n").unwrap();
    let after_edit = verify_receipts_for_current_state(root, &spec, &["check".into()], false);
    assert_eq!(after_edit["status"], "FAIL");
    let after_edit_clean = verify_receipts_for_current_state(root, &spec, &["check".into()], true);
    assert_eq!(after_edit_clean["status"], "FAIL");

    // Tampering with ledger JSONL breaks hash chain fail-closed
    let ledger_path = resolve_ledger_path(root, &spec);
    let text = fs::read_to_string(&ledger_path).unwrap();
    fs::write(&ledger_path, text.replace("\"PASS\"", "\"TAMPERED\"")).unwrap();
    let entries = read_receipts(&ledger_path);
    let (ok, errs) = verify_chain(&entries);
    assert!(!ok && !errs.is_empty());

    // Telemetry and GC still run cleanly and report broken chain recommendation
    let steer = analyze_telemetry(root, &spec);
    assert_eq!(steer["chain_ok"], false);
    let gc = run_gc_scan(root, &spec, Some(NaiveDate::from_ymd_opt(2026, 11, 26).unwrap()));
    assert!(gc.get("buckets").is_some());
}

#[test]
fn hook_installers_are_idempotent_and_cli_binary_works() {
    let tmp = init_sample_repo();
    let root = tmp.path();

    // Idempotent git, claude, and hermes hook installation
    git(root, &["config", "core.hooksPath", ".git/hooks"]);
    let g1 = install_git_pre_commit_hook(root).unwrap();
    let g2 = install_git_pre_commit_hook(root).unwrap();
    assert_eq!(g1["status"], "created");
    assert_eq!(g2["status"], "already_installed");

    let claude_cfg = root.join(".claude/settings.local.json");
    let c1 = install_claude_hook(&claude_cfg).unwrap();
    let c2 = install_claude_hook(&claude_cfg).unwrap();
    assert_eq!(c1["status"], "installed");
    assert_eq!(c2["status"], "already_installed");

    let hermes_plugins = tmp.path().join("hermes-plugins");
    let h1 = install_hermes_plugin(&hermes_plugins, None).unwrap();
    assert_eq!(h1["status"], "installed");
    assert!(hermes_plugins.join("birkin/plugin.yaml").is_file());
    assert!(hermes_plugins.join("birkin/__init__.py").is_file());

    // End-to-end binary invocation on sample repo
    let bin = env!("CARGO_BIN_EXE_birkin");
    let out = Command::new(bin)
        .args(["check", root.to_str().unwrap(), "--no-receipt", "--json"])
        .output()
        .expect("run birkin check");
    assert_eq!(
        out.status.code(),
        Some(EXIT_PASS),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["status"], "PASS");

    // Broken link triggers EXIT_STATIC
    fs::write(root.join("AGENTS.md"), "# Map\n\nSee [missing.md](missing.md).\n").unwrap();
    let out2 = Command::new(bin)
        .args(["check", root.to_str().unwrap(), "--no-receipt", "--json"])
        .output()
        .expect("run birkin check bad");
    assert_eq!(out2.status.code(), Some(EXIT_STATIC));
    let parsed2: Value = serde_json::from_slice(&out2.stdout).unwrap();
    assert_eq!(parsed2["status"], "FAIL");
    let _ = json!({});
}

#[test]
fn ci_parity_ignores_release_workflows_and_matches_bun_and_birkin_invocations() {
    let tmp = init_sample_repo();
    let root = tmp.path();
    let wf_dir = root.join(".github/workflows");
    fs::create_dir_all(&wf_dir).unwrap();
    fs::write(
        wf_dir.join("release.yml"),
        "name: Release\non:\n  push:\n    tags: ['v*']\njobs:\n  pub:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          [[ \"$out\" == \"birkin 0.5.0\" ]]\n          gh release create v0.5.0 --title \"Birkin v0.5.0\"\n",
    )
    .unwrap();
    fs::write(
        wf_dir.join("ci.yml"),
        "name: CI\non:\n  push:\n    branches: [main]\n  pull_request:\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"Birkin banner\"\n      - run: bun run verify\n      - run: birkin check --no-receipt\n",
    )
    .unwrap();

    let (mut spec, _) = load_project_spec(root, None).unwrap();
    spec.verify.check_ci_parity = true;
    spec.verify.commands = vec![];
    let findings = audit_guides(root, &spec, Some(NaiveDate::from_ymd_opt(2026, 11, 26).unwrap()));
    assert!(
        findings.iter().any(|f| f.rule == "ADMISSION_NO_LOCAL_VERIFY_DECLARED"),
        "expected missing verify finding, got {findings:?}"
    );

    spec.verify.commands = vec![birkin::project_models::VerifyCommand {
        name: "verify".into(),
        cmd: "bun run verify".into(),
        kind: "test".into(),
        timeout_seconds: 120,
    }];
    let findings = audit_guides(root, &spec, Some(NaiveDate::from_ymd_opt(2026, 11, 26).unwrap()));
    let drift_cmds: Vec<&str> = findings
        .iter()
        .filter(|f| f.rule == "ADMISSION_CI_LOCAL_DRIFT")
        .map(|f| f.message.as_str())
        .collect();
    assert_eq!(drift_cmds.len(), 1, "expected only birkin check drift, got {drift_cmds:?}");
    assert!(drift_cmds[0].contains("birkin check --no-receipt"));
    assert!(
        !findings.iter().any(|f| f.file.as_deref() == Some(".github/workflows/release.yml")),
        "release-only workflow must not trigger CI parity findings: {findings:?}"
    );
}

#[test]
fn detect_project_spec_recognizes_bun_runner() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    fs::write(root.join("tsconfig.json"), "{}\n").unwrap();
    fs::write(root.join("bun.lock"), "").unwrap();
    fs::write(
        root.join("package.json"),
        "{\"name\":\"app\",\"packageManager\":\"bun@1.3.13\",\"scripts\":{\"verify\":\"bun test\"}}\n",
    )
    .unwrap();
    let spec = birkin::project_init::detect_project_spec(root);
    assert!(spec.project.languages.contains(&"typescript".to_string()));
    assert_eq!(spec.verify.commands.len(), 1);
    assert_eq!(spec.verify.commands[0].cmd, "bun run verify");
}
