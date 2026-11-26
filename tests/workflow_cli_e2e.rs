//! End-to-end CLI tests for workflow contract subcommands via the compiled `birkin` binary.

use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_birkin");

struct TestRepo {
    temp: TempDir,
    root: PathBuf,
    ledger_dir: PathBuf,
}

impl TestRepo {
    fn new(config_yaml: &str) -> Self {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("repo");
        let ledger_dir = temp.path().join("ledger");
        fs::create_dir_all(root.join(".birkin")).unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join(".sawyer")).unwrap();
        fs::write(temp.path().join("empty.gitconfig"), "").unwrap();
        let repo = Self { temp, root, ledger_dir };
        repo.git(&["init", "-q", "-b", "main"]);
        fs::write(repo.root.join(".birkin/config.yaml"), config_yaml).unwrap();
        fs::write(repo.root.join("AGENTS.md"), "# AGENTS\n\nLast reviewed: 2026-11-26\n").unwrap();
        fs::write(repo.root.join("README.md"), "# Sample\n").unwrap();
        fs::write(repo.root.join("rust-toolchain.toml"), "1.85.0\n").unwrap();
        fs::write(repo.root.join(".sawyer/exclude-whitelist.txt"), "local.txt\n").unwrap();
        fs::write(repo.root.join("src/ok.rs"), "pub fn ok() -> u32 { 1 }\n").unwrap();
        fs::write(repo.root.join("src/outside.rs"), "pub fn outside() -> u32 { 2 }\n").unwrap();
        repo.git(&["add", "."]);
        repo.git(&["commit", "-qm", "initial"]);
        repo
    }

    fn git_cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new("git");
        cmd.args(args)
            .current_dir(&self.root)
            .env("GIT_CONFIG_GLOBAL", self.temp.path().join("empty.gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "Birkin Test")
            .env("GIT_COMMITTER_NAME", "Birkin Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE");
        cmd
    }

    fn git(&self, args: &[&str]) -> String {
        let out = self.git_cmd(args).output().unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap().trim_end().to_string()
    }

    fn run_birkin(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(&self.root)
            .env("BIRKIN_LEDGER_DIR", &self.ledger_dir)
            .env("GIT_CONFIG_GLOBAL", self.temp.path().join("empty.gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .output()
            .unwrap()
    }

    fn run_json(&self, args: &[&str], expected_code: i32) -> (Value, String) {
        let out = self.run_birkin(args);
        let code = out.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert_eq!(code, expected_code, "args={args:?}\nstdout={stdout}\nstderr={stderr}");
        let val: Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("invalid JSON for {args:?}: {e}\nstdout={stdout}"));
        (val, stderr)
    }

    fn write_fixture(&self, name: &str, body: &str) -> PathBuf {
        let p = self.temp.path().join(name);
        fs::write(&p, body).unwrap();
        p
    }
}

const WORKFLOW_CONFIG: &str = r#"version: 1
project:
  name: wf-demo
  languages: [rust]
orientation:
  entry_docs: [AGENTS.md]
  required_docs: [README.md]
  verify_markdown_links: true
  require_committed_spec: true
verify:
  check_ci_parity: false
telemetry:
  enabled: true
workflow:
  enabled_contracts: [plan, scope, authority, stage, sawyer, review_closure]
  toolchain_pin_files: [rust-toolchain.toml]
  exclude_whitelist_path: .sawyer/exclude-whitelist.txt
  test_runners:
    - name: cargo-unit
      parser: cargo_test
"#;

const LEGACY_CONFIG: &str = r#"version: 1
project:
  name: legacy-demo
  languages: [rust]
orientation:
  entry_docs: [AGENTS.md]
  required_docs: [README.md]
  verify_markdown_links: true
  require_committed_spec: true
verify:
  check_ci_parity: false
telemetry:
  enabled: true
"#;

fn valid_plan(intent: &str, checkout_root: &Path) -> Value {
    json!({
        "version": 1,
        "intent": intent,
        "outcome": "Deliver verified CLI workflow contracts.",
        "non_goals": ["Mutate global workstation files"],
        "constraints": ["Keep all changes scoped"],
        "evidence": ["src/ok.rs:1"],
        "questions": [],
        "tasks": [{
            "id": "unit-1",
            "title": "Update ok.rs",
            "checkout_root": checkout_root.to_string_lossy(),
            "context": "Demo unit",
            "expected_behavior": "Updates src/ok.rs safely.",
            "status": "ready",
            "depends_on": [],
            "allowed_paths": ["src/ok.rs"],
            "forbidden_paths": ["src/outside.rs"],
            "verification_output_paths": ["target/"],
            "acceptance": ["Unit passes tests"],
            "verification": [{"method": "cargo test", "expected": "0 failed"}],
            "stop_conditions": ["Any unexpected failure"],
            "owner": "impl",
            "completion_evidence": []
        }]
    })
}

fn closed_review_state() -> Value {
    json!({
        "canonical_review_items": [{
            "item_key": "r-1",
            "classification": "must_fix",
            "replied": true,
            "reply_url": "https://review.example/comment/1",
            "resolved": true,
            "fix_verified": true
        }],
        "request_re_review": true
    })
}

#[test]
fn plan_unit_review_closure_and_no_receipt_e2e() {
    let repo = TestRepo::new(WORKFLOW_CONFIG);
    let plan_ok = repo.write_fixture("plan-ok.json", &valid_plan("implement", &repo.root).to_string());
    let plan_only = repo.write_fixture("plan-only.json", &valid_plan("plan-only", &repo.root).to_string());
    let mut bad_plan_val = valid_plan("implement", &repo.root);
    let dup_task = bad_plan_val["tasks"][0].clone();
    bad_plan_val["tasks"].as_array_mut().unwrap().push(dup_task);
    let plan_dup = repo.write_fixture("plan-dup.json", &bad_plan_val.to_string());
    let bad_json = repo.write_fixture("bad.json", "{not valid");

    // --no-receipt must not create or write ledger files
    let (v, _) = repo.run_json(&["plan", "verify", plan_ok.to_str().unwrap(), "--repo", repo.root.to_str().unwrap(), "--no-receipt", "--json"], 0);
    assert_eq!(v["valid"], true);
    assert_eq!(v["status"], "PASS");
    assert!(v["receipt_sha256"].is_null());
    assert!(!repo.ledger_dir.exists(), "--no-receipt created ledger dir");

    // plan verify pass (0), violation (1), schema/IO error (5)
    let (v, _) = repo.run_json(&["plan", "verify", plan_ok.to_str().unwrap(), "--repo", repo.root.to_str().unwrap(), "--json"], 0);
    assert_eq!(v["command"], "plan-verify");
    assert_eq!(v["valid"], true);
    assert_eq!(v["ready_tasks"], json!(["unit-1"]));
    assert!(v["receipt_sha256"].as_str().is_some());

    let (v, _) = repo.run_json(&["plan", "verify", plan_dup.to_str().unwrap(), "--repo", repo.root.to_str().unwrap(), "--json"], 1);
    assert_eq!(v["valid"], false);
    assert!(!v["errors"].as_array().unwrap().is_empty());

    let (v, _) = repo.run_json(&["plan", "verify", bad_json.to_str().unwrap(), "--repo", repo.root.to_str().unwrap(), "--json"], 5);
    assert_eq!(v["status"], "ERROR");
    assert_eq!(v["exit_code"], 5);

    // unit admit: implement W passes; plan-only refuses; review same-model refuses; bad tier -> 5
    let (v, _) = repo.run_json(&[
        "unit", "admit", "--plan", plan_ok.to_str().unwrap(), "--task", "unit-1",
        "--role", "implement", "--tier", "W", "--model", "worker-a", "--runtime", "codex",
        "--repo", repo.root.to_str().unwrap(), "--json",
    ], 0);
    assert_eq!(v["admitted"], true);
    assert_eq!(v["plan_admitted"], true);
    assert_eq!(v["authority_admitted"], true);

    let (v, _) = repo.run_json(&[
        "unit", "admit", "--plan", plan_only.to_str().unwrap(), "--task", "unit-1",
        "--role", "implement", "--tier", "W", "--repo", repo.root.to_str().unwrap(), "--json",
    ], 1);
    assert_eq!(v["admitted"], false);
    assert_eq!(v["plan_admitted"], false);

    let (v, _) = repo.run_json(&[
        "unit", "admit", "--plan", plan_ok.to_str().unwrap(), "--task", "unit-1",
        "--role", "review", "--tier", "R", "--model", "m1", "--runtime", "rt1",
        "--implementer-model", "m1", "--implementer-runtime", "rt1",
        "--repo", repo.root.to_str().unwrap(), "--json",
    ], 1);
    assert_eq!(v["admitted"], false);
    assert_eq!(v["authority_admitted"], false);

    let (v, _) = repo.run_json(&[
        "unit", "admit", "--plan", plan_ok.to_str().unwrap(), "--task", "unit-1",
        "--role", "implement", "--tier", "W", "--refusal", "--prev-tier", "R",
        "--repo", repo.root.to_str().unwrap(), "--json",
    ], 1);
    assert_eq!(v["admitted"], false);

    let (v, _) = repo.run_json(&[
        "unit", "admit", "--plan", plan_ok.to_str().unwrap(), "--task", "unit-1",
        "--role", "implement", "--tier", "F", "--repo", repo.root.to_str().unwrap(), "--json",
    ], 1);
    assert_eq!(v["admitted"], false);
    let (v, _) = repo.run_json(&[
        "unit", "admit", "--plan", plan_ok.to_str().unwrap(), "--task", "unit-1",
        "--role", "implement", "--tier", "F", "--explicit-f",
        "--forbidden-model", "*opus*", "--model", "claude-opus",
        "--repo", repo.root.to_str().unwrap(), "--json",
    ], 1);
    assert_eq!(v["admitted"], false);
    let (v, _) = repo.run_json(&[
        "unit", "admit", "--plan", plan_ok.to_str().unwrap(), "--task", "unit-1",
        "--role", "implement", "--tier", "F", "--explicit-f",
        "--forbidden-model", "*opus*", "--model", "group/makima",
        "--repo", repo.root.to_str().unwrap(), "--json",
    ], 0);
    assert_eq!(v["admitted"], true);

    let (v, _) = repo.run_json(&[
        "unit", "admit", "--plan", plan_ok.to_str().unwrap(), "--task", "unit-1",
        "--role", "implement", "--tier", "Z", "--repo", repo.root.to_str().unwrap(), "--json",
    ], 5);
    assert_eq!(v["exit_code"], 5);

    // review-closure verify: pass (0), violation (1), invalid JSON (5)
    let rev_ok = repo.write_fixture("rev-ok.json", &closed_review_state().to_string());
    let rev_bad = repo.write_fixture("rev-bad.json", &json!({
        "canonical_review_items": [{
            "item_key": "r-2",
            "classification": "needs_clarification",
            "replied": true,
            "resolved": false
        }],
        "request_re_review": true
    }).to_string());
    let (v, _) = repo.run_json(&["review-closure", "verify", rev_ok.to_str().unwrap(), "--repo", repo.root.to_str().unwrap(), "--json"], 0);
    assert_eq!(v["closed"], true);
    assert_eq!(v["item_count"], 1);

    let (v, _) = repo.run_json(&["review-closure", "verify", rev_bad.to_str().unwrap(), "--repo", repo.root.to_str().unwrap(), "--json"], 1);
    assert_eq!(v["closed"], false);
    assert!(v["error"].as_str().unwrap().contains("Clarification"));

    let (v, _) = repo.run_json(&["review-closure", "verify", bad_json.to_str().unwrap(), "--repo", repo.root.to_str().unwrap(), "--json"], 5);
    assert_eq!(v["exit_code"], 5);

    // Verify full hash chain in ledger for commands recorded on this exact tree
    let (rv, _) = repo.run_json(&[
        "receipt", "verify", repo.root.to_str().unwrap(),
        "--require", "plan-verify,unit-admit,review-closure-verify", "--json",
    ], 0);
    assert_eq!(rv["status"], "PASS");
    assert_eq!(rv["chain_ok"], true);
    assert_eq!(rv["missing"], json!([]));
}

#[test]
fn unit_verify_scope_staged_authority_and_active_overlap_e2e() {
    let repo = TestRepo::new(WORKFLOW_CONFIG);
    let plan = repo.write_fixture("plan.json", &valid_plan("implement", &repo.root).to_string());
    let active = repo.write_fixture("active.json", &json!([{
        "task_id": "unit-2",
        "checkout_root": repo.root.to_string_lossy(),
        "write_paths": ["src/ok.rs"]
    }]).to_string());

    // Staged edit inside allowed_paths passes
    fs::write(repo.root.join("src/ok.rs"), "pub fn ok() -> u32 { 42 }\n").unwrap();
    repo.git(&["add", "src/ok.rs"]);
    let (v, _) = repo.run_json(&[
        "unit", "verify-scope", "--plan", plan.to_str().unwrap(), "--task", "unit-1",
        "--repo", repo.root.to_str().unwrap(), "--staged", "--json",
    ], 0);
    assert_eq!(v["admitted"], true);
    assert_eq!(v["staged_only"], true);
    assert_eq!(v["checked_paths"], json!(["src/ok.rs"]));

    // Same staged edit fails when overlapping with an active unit
    let (v, _) = repo.run_json(&[
        "unit", "verify-scope", "--plan", plan.to_str().unwrap(), "--task", "unit-1",
        "--repo", repo.root.to_str().unwrap(), "--staged", "--active-units", active.to_str().unwrap(), "--json",
    ], 1);
    assert_eq!(v["admitted"], false);
    assert_eq!(v["overlapping_writes"], json!(["src/ok.rs"]));

    // Staged change outside allowed_paths fails
    fs::write(repo.root.join("src/outside.rs"), "pub fn outside() -> u32 { 99 }\n").unwrap();
    repo.git(&["add", "src/outside.rs"]);
    let (v, _) = repo.run_json(&[
        "unit", "verify-scope", "--plan", plan.to_str().unwrap(), "--task", "unit-1",
        "--repo", repo.root.to_str().unwrap(), "--staged", "--json",
    ], 1);
    assert_eq!(v["admitted"], false);
    assert!(v["findings"].as_array().unwrap().iter().any(|f| f["rule"] == "SCOPE_FORBIDDEN_PATH"));

    // Verification output path rejected for source authority, admitted for verification-output
    let (v, _) = repo.run_json(&[
        "unit", "verify-scope", "--plan", plan.to_str().unwrap(), "--task", "unit-1",
        "--repo", repo.root.to_str().unwrap(), "--path", "target/out.txt", "--authority", "source", "--json",
    ], 1);
    assert_eq!(v["admitted"], false);
    let (v, _) = repo.run_json(&[
        "unit", "verify-scope", "--plan", plan.to_str().unwrap(), "--task", "unit-1",
        "--repo", repo.root.to_str().unwrap(), "--path", "target/out.txt", "--authority", "verification-output", "--json",
    ], 0);
    assert_eq!(v["admitted"], true);

    // Invalid authority exits 5
    let (v, _) = repo.run_json(&[
        "unit", "verify-scope", "--plan", plan.to_str().unwrap(), "--task", "unit-1",
        "--repo", repo.root.to_str().unwrap(), "--authority", "bogus", "--json",
    ], 5);
    assert_eq!(v["exit_code"], 5);
}

#[test]
fn stage_and_sawyer_verify_observed_vs_attested_e2e() {
    let repo = TestRepo::new(WORKFLOW_CONFIG);
    let remote = repo.temp.path().join("remote.git");
    let init_bare = repo.git_cmd(&["init", "-q", "--bare", remote.to_str().unwrap()]).output().unwrap();
    assert!(init_bare.status.success());
    repo.git(&["remote", "add", "origin", remote.to_str().unwrap()]);
    repo.git(&["push", "-q", "origin", "main"]);

    let good_log = repo.write_fixture(
        "cargo-pass.log",
        "running 2 tests\ntest a ... ok\ntest b ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n",
    );
    let zero_log = repo.write_fixture(
        "cargo-zero.log",
        "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
    );
    let fail_log = repo.write_fixture(
        "cargo-fail.log",
        "running 2 tests\ntest a ... ok\ntest b ... FAILED\ntest result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n",
    );
    let review_ev = repo.write_fixture("review.json", &closed_review_state().to_string());
    let ci_ev = repo.write_fixture("ci.json", r#"{"run_id": 1001, "conclusion": "success"}"#);
    let rel_ev = repo.write_fixture("release.txt", "Authorized by owner for v0.5.0\n");

    let root_s = repo.root.to_str().unwrap();
    let stage_call = |stage: &str, log: &Path, pin: &str, extra: &[&str], code: i32| {
        let mut args = vec![
            "stage", "verify", "--stage", stage, "--repo", root_s,
            "--test-transcript", log.to_str().unwrap(),
            "--toolchain-pin", pin, "--json",
        ];
        args.extend_from_slice(extra);
        repo.run_json(&args, code).0
    };

    // Stage verified fails before any check receipt exists
    let v = stage_call("verified", &good_log, "rust-toolchain.toml=1.85.0", &[], 1);
    assert_eq!(v["admitted"], false);
    assert_eq!(v["evidence"]["observed"]["receipt_chain_ok"], false);

    // Record passing check receipt on current tree
    repo.run_json(&["check", root_s, "--json"], 0);

    // Zero-test, failed transcript, and mismatched toolchain pin fail stage verified
    let v = stage_call("verified", &zero_log, "rust-toolchain.toml=1.85.0", &[], 1);
    assert_eq!(v["admitted"], false);
    assert_eq!(v["evidence"]["observed"]["discovered_tests"], 0);

    let v = stage_call("verified", &fail_log, "rust-toolchain.toml=1.85.0", &[], 1);
    assert_eq!(v["admitted"], false);

    let v = stage_call("verified", &good_log, "rust-toolchain.toml=1.80.0", &[], 1);
    assert_eq!(v["admitted"], false);
    assert_eq!(v["evidence"]["observed"]["toolchain_matched"], false);

    // Passing stage verified with observed transcript + pin + check receipt
    let v = stage_call("verified", &good_log, "rust-toolchain.toml=1.85.0", &[], 0);
    assert_eq!(v["admitted"], true);
    assert_eq!(v["evidence"]["observed"]["provenance"], "observed");
    assert_eq!(v["evidence"]["observed"]["discovered_tests"], 2);
    assert_eq!(v["evidence"]["observed"]["executed_tests"], 2);
    assert_eq!(v["evidence"]["attested"]["review_passed"]["provenance"], "attested");
    assert_eq!(v["evidence"]["attested"]["review_passed"]["value"], false);

    // Prepare staged approved file + whitelisted excluded file for Sawyer + committed
    fs::write(repo.root.join("src/ok.rs"), "pub fn ok() -> u32 { 7 }\n").unwrap();
    fs::write(repo.root.join("local.txt"), "private\n").unwrap();
    let mut pack = json!({
        "repo_root": repo.root.to_string_lossy(),
        "target_branch": "main",
        "remote": "origin",
        "approved_files": ["src/ok.rs"],
        "excluded_files": ["local.txt"],
        "require_signed": false
    });
    let pack_path = repo.write_fixture("sawyer-pack.json", &pack.to_string());
    let pack_s = pack_path.to_str().unwrap();

    // Sawyer preflight passes, staged fails before git add, invalid phase exits 5
    let (v, _) = repo.run_json(&["sawyer", "verify", "--pack", pack_s, "--phase", "preflight", "--repo", root_s, "--json"], 0);
    assert_eq!(v["admitted"], true);
    let (v, _) = repo.run_json(&["sawyer", "verify", "--pack", pack_s, "--phase", "staged", "--repo", root_s, "--json"], 1);
    assert_eq!(v["admitted"], false);
    let (v, _) = repo.run_json(&["sawyer", "verify", "--pack", pack_s, "--phase", "invalid", "--repo", root_s, "--json"], 5);
    assert_eq!(v["exit_code"], 5);

    repo.git(&["add", "src/ok.rs"]);
    let (v, _) = repo.run_json(&["sawyer", "verify", "--pack", pack_s, "--phase", "staged", "--repo", root_s, "--json"], 0);
    assert_eq!(v["admitted"], true);

    // Merely staged changes (not yet committed) must NOT admit stage committed even with review evidence
    repo.run_json(&["check", root_s, "--json"], 0);
    let v = stage_call("committed", &good_log, "rust-toolchain.toml=1.85.0", &["--sawyer-pack", pack_s, "--review-evidence", review_ev.to_str().unwrap()], 1);
    assert_eq!(v["admitted"], false);
    assert!(v["findings"].as_array().unwrap().iter().any(|f| f["rule"] == "STAGE_SAWYER_COMMIT_SHA_MISSING"));

    // Commit and pin pack SHA + check receipt on committed HEAD
    repo.git(&["commit", "-qm", "approved change"]);
    let head = repo.git(&["rev-parse", "HEAD"]);
    pack["expected_commit_sha"] = json!(head);
    fs::write(&pack_path, pack.to_string()).unwrap();
    repo.run_json(&["check", root_s, "--json"], 0);

    // Committed fails WITHOUT review evidence, and fails WITH unclosed review-state JSON
    let v = stage_call("committed", &good_log, "rust-toolchain.toml=1.85.0", &["--sawyer-pack", pack_s], 1);
    assert_eq!(v["admitted"], false);
    assert!(v["findings"].as_array().unwrap().iter().any(|f| f["rule"] == "STAGE_REVIEW_EVIDENCE_MISSING"));

    let unclosed_rev = repo.write_fixture("unclosed-rev.json", &json!({
        "canonical_review_items": [{"item_key": "r-open", "classification": "must_fix", "replied": true, "resolved": false, "fix_verified": false}]
    }).to_string());
    let v = stage_call("committed", &good_log, "rust-toolchain.toml=1.85.0", &["--sawyer-pack", pack_s, "--review-evidence", unclosed_rev.to_str().unwrap()], 1);
    assert_eq!(v["admitted"], false);
    assert!(v["findings"].as_array().unwrap().iter().any(|f| f["rule"] == "STAGE_REVIEW_CLOSURE_FAILED"));
    // Caller-asserted boolean/count flags are rejected by clap
    assert!(!repo.run_birkin(&["stage", "verify", "--stage", "verified", "--discovered-tests", "5"]).status.success());

    // Committed passes with closed review evidence; pushed still fails before git push
    let v = stage_call("committed", &good_log, "rust-toolchain.toml=1.85.0", &["--sawyer-pack", pack_s, "--review-evidence", review_ev.to_str().unwrap()], 0);
    assert_eq!(v["admitted"], true);
    assert_eq!(v["evidence"]["attested"]["review_passed"]["provenance"], "attested");
    assert_eq!(v["evidence"]["attested"]["review_passed"]["value"], true);

    let v = stage_call("pushed", &good_log, "rust-toolchain.toml=1.85.0", &["--sawyer-pack", pack_s, "--review-evidence", review_ev.to_str().unwrap()], 1);
    assert_eq!(v["admitted"], false);

    // Push -> post-push and released pass
    repo.git(&["push", "-q", "origin", "main"]);
    let (v, _) = repo.run_json(&["sawyer", "verify", "--pack", pack_s, "--phase", "post-push", "--repo", root_s, "--json"], 0);
    assert_eq!(v["admitted"], true);

    let v = stage_call("released", &good_log, "rust-toolchain.toml=1.85.0", &[
        "--sawyer-pack", pack_s,
        "--review-evidence", review_ev.to_str().unwrap(),
        "--ci-evidence", ci_ev.to_str().unwrap(),
        "--release-evidence", rel_ev.to_str().unwrap(),
    ], 0);
    assert_eq!(v["admitted"], true);
    assert_eq!(v["evidence"]["observed"]["remote_head_matches"], true);
    assert_eq!(v["evidence"]["attested"]["ci_passed"]["provenance"], "attested");
    assert_eq!(v["evidence"]["attested"]["release_authorized"]["provenance"], "attested");

    // Verify receipt ledger chain and confirm attested provenance is persisted in the receipt
    let (rv, _) = repo.run_json(&[
        "receipt", "verify", repo.root.to_str().unwrap(),
        "--require", "check,sawyer-verify,stage-verify", "--json",
    ], 0);
    assert_eq!(rv["status"], "PASS");
    assert_eq!(rv["chain_ok"], true);
    let ledger_file = fs::read_dir(&repo.ledger_dir).unwrap().next().unwrap().unwrap().path();
    let ledger_lines: Vec<Value> = fs::read_to_string(&ledger_file)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let last_stage = ledger_lines.iter().rev().find(|e| e["command"] == "stage-verify").unwrap();
    assert_eq!(last_stage["meta"]["evidence"]["attested"]["release_authorized"]["provenance"], "attested");
    assert_eq!(last_stage["meta"]["evidence"]["observed"]["provenance"], "observed");
}

#[test]
fn legacy_config_guide_audit_and_receipt_error_surfacing() {
    // Legacy config without workflow: still passes check and reports OPT_IN in audit/guide
    let legacy = TestRepo::new(LEGACY_CONFIG);
    let (chk, _) = legacy.run_json(&["check", legacy.root.to_str().unwrap(), "--no-receipt", "--json"], 0);
    assert_eq!(chk["status"], "PASS");
    assert_eq!(chk["findings"], json!([]));

    let (aud, _) = legacy.run_json(&["audit", legacy.root.to_str().unwrap(), "--json"], 0);
    assert_eq!(aud["scorecard"]["workflow"]["status"], "OPT_IN");
    assert_eq!(aud["scorecard"]["workflow"]["enabled_contracts"], json!([]));

    let (gd, _) = legacy.run_json(&["guide", legacy.root.to_str().unwrap(), "--json"], 0);
    assert!(gd["guide"].as_str().unwrap().contains("none enabled"));

    // Repo with workflow: surfaces enabled contracts and configured inputs in guide + audit
    let wf = TestRepo::new(WORKFLOW_CONFIG);
    let (aud, _) = wf.run_json(&["audit", wf.root.to_str().unwrap(), "--json"], 0);
    assert_eq!(aud["scorecard"]["workflow"]["status"], "PASS");
    assert_eq!(aud["scorecard"]["workflow"]["inputs_configured"]["exclude_whitelist_exists"], true);
    assert_eq!(aud["scorecard"]["workflow"]["inputs_configured"]["test_runners"], json!(["cargo-unit"]));

    let (gd, _) = wf.run_json(&["guide", wf.root.to_str().unwrap(), "--json"], 0);
    let gtxt = gd["guide"].as_str().unwrap();
    assert!(gtxt.contains("rust-toolchain.toml (ok)"));
    assert!(gtxt.contains("cargo-unit [cargo_test]"));

    // Missing workflow input triggers warning in audit
    fs::remove_file(wf.root.join("rust-toolchain.toml")).unwrap();
    let (aud_warn, _) = wf.run_json(&["audit", wf.root.to_str().unwrap(), "--json"], 0);
    assert_eq!(aud_warn["scorecard"]["workflow"]["status"], "WARN");
    assert!(aud_warn["findings"].as_array().unwrap().iter().any(|f| f["rule"] == "WORKFLOW_MISSING_TOOLCHAIN_PIN"));

    // Receipt write failure is surfaced on stderr and JSON receipt_error (never swallowed)
    let broken_ledger = wf.temp.path().join("ledger-is-dir");
    fs::create_dir_all(&broken_ledger).unwrap();
    fs::write(
        wf.root.join(".birkin/config.yaml"),
        format!("version: 1\nproject: {{name: err-demo}}\ntelemetry: {{enabled: true, ledger_path: {:?}}}\n", broken_ledger.to_string_lossy()),
    ).unwrap();
    let rev_ok = wf.write_fixture("rev.json", &closed_review_state().to_string());
    let (v, stderr) = wf.run_json(&["review-closure", "verify", rev_ok.to_str().unwrap(), "--repo", wf.root.to_str().unwrap(), "--json"], 0);
    assert_eq!(v["closed"], true);
    assert!(v["receipt_sha256"].is_null());
    assert!(v["receipt_error"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(stderr.contains("[birkin] warning: failed recording receipt (review-closure-verify):"), "stderr={stderr}");
}
