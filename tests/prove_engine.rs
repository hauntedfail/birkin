//! End-to-end positive and negative (Proof-of-Life) tests for `birkin prove`.
//!
//! Exercises Lean 4 kernel verification of per-repository architecture DAGs,
//! extracted import-graph compliance, forbidden imports, declarative state machines,
//! boundary policies, custom Lean project axiom audits, and receipt pinning.

use birkin::constants::{EXIT_PASS, EXIT_STATIC};
use birkin::ledger::{append_receipt, verify_receipts_for_current_state};
use birkin::project_models::load_project_spec;
use birkin::prove::run_prove;
use birkin::prove_audit::parse_print_axioms;
use birkin::prove_lean::compute_layer_ranks;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn git(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false"])
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

fn init_provable_repo() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    git(root, &["init", "-q"]);
    fs::create_dir_all(root.join(".birkin")).unwrap();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/core.py"), "VALUE = 42\n").unwrap();
    fs::write(
        root.join("src/app.py"),
        "from src.core import VALUE\n\ndef run():\n    return VALUE\n",
    )
    .unwrap();
    fs::write(
        root.join(".birkin/config.yaml"),
        r#"version: 1
project:
  name: provable-demo
  languages: [python]
architecture:
  layers:
    - name: core
      paths: ["src/core.py"]
      allowed_dependencies: []
    - name: app
      paths: ["src/app.py"]
      allowed_dependencies: [core]
  forbidden_imports:
    - id: no-http-in-core
      from_globs: ["src/core.py"]
      forbid_patterns: ["requests*", "httpx*"]
      message: "Core must stay offline."
      remediation: "Remove HTTP client import."
proofs:
  timeout_seconds: 120
  require_zero_sorry: true
  require_standard_axioms_only: true
  prove_architecture: true
  state_machines:
    - id: task-lifecycle
      states: [pending, claimed, running, done, failed]
      initial: pending
      terminal: [done, failed]
      transitions:
        - { from: pending, to: claimed, label: claim }
        - { from: claimed, to: running, label: start }
        - { from: running, to: done, label: finish }
        - { from: running, to: failed, label: fail }
      forbidden_transitions:
        - { from: claimed, to: claimed }
        - { from: running, to: running }
      require_terminal_sink: true
      require_all_states_reachable: true
    - id: proposal-delta
      states: [draft, applied, reverted]
      initial: draft
      terminal: []
      transitions:
        - { from: draft, to: applied, label: apply }
        - { from: applied, to: reverted, label: revert }
        - { from: reverted, to: applied, label: apply }
      reversible_pairs:
        - { forward: apply, backward: revert }
      require_terminal_sink: false
      require_all_states_reachable: false
  policies:
    - id: model-boundary
      deny_patterns: ["*opus*"]
      allow_patterns: ["group/makima", "group/lvmh"]
      must_deny: ["claude-opus-5-5", "opus"]
      must_allow: ["group/makima", "group/lvmh"]
      require_deny_dominance: true
"#,
    )
    .unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "initial"]);
    tmp
}

#[test]
fn prove_positive_full_stack_and_receipt_pinning() {
    let tmp = init_provable_repo();
    let root = tmp.path();
    let (spec, _) = load_project_spec(root, None).unwrap();

    // Note: reversible pair in proposal-delta has (draft->applied, applied->reverted),
    // so update proposal-delta to exact reversible pair (applied <-> reverted) for clean proof.
    let mut clean_spec = spec.clone();
    clean_spec.proofs.state_machines[1].transitions = vec![
        birkin::proof_models::StateTransitionSpec {
            from: "draft".into(),
            to: "applied".into(),
            label: "stage".into(),
        },
        birkin::proof_models::StateTransitionSpec {
            from: "applied".into(),
            to: "reverted".into(),
            label: "apply".into(),
        },
        birkin::proof_models::StateTransitionSpec {
            from: "reverted".into(),
            to: "applied".into(),
            label: "revert".into(),
        },
    ];
    clean_spec.proofs.state_machines[1].require_all_states_reachable = true;

    let emit_tmp = TempDir::new().unwrap();
    let emitted = emit_tmp.path().join("obligations.lean");
    let outcome = run_prove(root, &clean_spec, Some(&emitted), false);
    assert_eq!(
        outcome.exit_code, EXIT_PASS,
        "expected PASS, got findings={:?}",
        outcome.findings
    );
    assert!(outcome.architecture_dag_proved);
    assert!(outcome.theorems_proved.len() >= 10);
    assert!(emitted.is_file());
    assert!(outcome.axioms_audited.contains_key("BirkinProof.repo_dag_acyclic"));
    assert!(outcome
        .axioms_audited
        .contains_key("BirkinProof.repo_imports_respect_layers"));
    assert!(outcome
        .axioms_audited
        .contains_key("BirkinProof.pol_model_boundary_deny_dominates"));

    // Record prove receipt and verify revision-pinned admission gate
    append_receipt(
        root,
        &clean_spec,
        "prove",
        "cli",
        "PASS",
        EXIT_PASS,
        outcome.duration_ms,
        &[],
        &outcome.files_checked,
        serde_json::Map::new(),
    )
    .unwrap();
    let gate = verify_receipts_for_current_state(root, &clean_spec, &["prove".into()], true);
    assert_eq!(gate["status"], "PASS", "got {gate}");
}

#[test]
fn prove_negative_rejects_upward_import_and_forbidden_import() {
    let tmp = init_provable_repo();
    let root = tmp.path();
    let (mut spec, _) = load_project_spec(root, None).unwrap();
    spec.proofs.state_machines.clear();
    spec.proofs.policies.clear();

    // Insert both an upward layer import (core -> app) and a forbidden import (requests)
    fs::write(
        root.join("src/core.py"),
        "import requests\nfrom src.app import run\nVALUE = run()\n",
    )
    .unwrap();

    let outcome = run_prove(root, &spec, None, false);
    assert_eq!(outcome.exit_code, EXIT_STATIC);
    let rules: Vec<&str> = outcome.findings.iter().map(|f| f.rule.as_str()).collect();
    assert!(
        rules.contains(&"PROOF_ARCH_LAYER_VIOLATION"),
        "expected layer violation: {rules:?}"
    );
    assert!(
        rules.contains(&"PROOF_FORBIDDEN_IMPORT:no-http-in-core"),
        "expected forbidden import: {rules:?}"
    );
    assert!(
        rules.contains(&"PROOF_KERNEL_REJECTED"),
        "expected Lean kernel rejection: {rules:?}"
    );
}

#[test]
fn prove_negative_rejects_cyclic_layers_state_machine_and_policy_breaches() {
    let tmp = init_provable_repo();
    let root = tmp.path();
    let (base, _) = load_project_spec(root, None).unwrap();

    // 1. Cyclic layer DAG fails closed before Lean
    let mut cyclic_spec = base.clone();
    cyclic_spec.proofs.state_machines.clear();
    cyclic_spec.proofs.policies.clear();
    cyclic_spec.architecture.layers[0]
        .allowed_dependencies
        .push("app".into());
    assert!(compute_layer_ranks(&cyclic_spec.architecture.layers).is_err());
    let cyc_out = run_prove(root, &cyclic_spec, None, false);
    assert_eq!(cyc_out.exit_code, EXIT_STATIC);
    assert!(cyc_out
        .findings
        .iter()
        .any(|f| f.rule == "PROOF_ARCH_DAG_CYCLE"));

    // 2. Broken state machine (terminal outgoing edge + forbidden transition) rejected by Lean kernel
    let mut bad_sm = base.clone();
    bad_sm.proofs.prove_architecture = false;
    bad_sm.proofs.policies.clear();
    bad_sm.proofs.state_machines.truncate(1);
    bad_sm.proofs.state_machines[0]
        .transitions
        .push(birkin::proof_models::StateTransitionSpec {
            from: "done".into(),
            to: "running".into(),
            label: "reopen".into(),
        });
    let sm_out = run_prove(root, &bad_sm, None, false);
    assert_eq!(sm_out.exit_code, EXIT_STATIC);
    assert!(sm_out
        .findings
        .iter()
        .any(|f| f.rule == "PROOF_KERNEL_REJECTED"));

    // 3. Broken policy (denied model listed in must_allow) rejected by Lean kernel
    let mut bad_pol = base.clone();
    bad_pol.proofs.prove_architecture = false;
    bad_pol.proofs.state_machines.clear();
    bad_pol.proofs.policies[0]
        .must_allow
        .push("claude-opus-5-5".into());
    let pol_out = run_prove(root, &bad_pol, None, false);
    assert_eq!(pol_out.exit_code, EXIT_STATIC);
    assert!(pol_out
        .findings
        .iter()
        .any(|f| f.rule == "PROOF_KERNEL_REJECTED"));

    // 4. Empty proof obligations fails closed
    let mut empty_spec = base;
    empty_spec.proofs.prove_architecture = false;
    empty_spec.proofs.state_machines.clear();
    empty_spec.proofs.policies.clear();
    empty_spec.proofs.lean_projects.clear();
    let empty_out = run_prove(root, &empty_spec, None, false);
    assert_eq!(empty_out.exit_code, EXIT_STATIC);
    assert!(empty_out
        .findings
        .iter()
        .any(|f| f.rule == "PROOF_NO_OBLIGATIONS"));
}

#[test]
fn prove_rejects_unknown_yaml_key_and_parses_axioms() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join(".birkin")).unwrap();
    fs::write(
        tmp.path().join(".birkin/config.yaml"),
        "version: 1\nproofs:\n  unknown_knob: true\n",
    )
    .unwrap();
    let err = load_project_spec(tmp.path(), None).unwrap_err();
    assert!(
        err.contains("unknown field"),
        "expected deny_unknown_fields error, got: {err}"
    );

    let parsed = parse_print_axioms(
        "'BirkinSpec.a' does not depend on any axioms\n'BirkinSpec.b' depends on axioms: [propext,\n Classical.choice,\n Quot.sound]\n",
    );
    assert_eq!(parsed.get("BirkinSpec.a"), Some(&Vec::new()));
    assert_eq!(
        parsed.get("BirkinSpec.b"),
        Some(&vec![
            "propext".to_string(),
            "Classical.choice".to_string(),
            "Quot.sound".to_string()
        ])
    );
}

#[test]
fn prove_custom_lean_project_rejects_sorry_and_custom_axiom() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join(".birkin")).unwrap();
    fs::create_dir_all(root.join("spec")).unwrap();
    fs::write(
        root.join("spec/lakefile.toml"),
        "name = \"bad-spec\"\nversion = \"0.1.0\"\ndefaultTargets = [\"BadSpec\"]\n\n[[lean_lib]]\nname = \"BadSpec\"\n",
    )
    .unwrap();
    fs::write(
        root.join("spec/BadSpec.lean"),
        "axiom cheat : False\ntheorem broken : True := by sorry\n",
    )
    .unwrap();
    fs::write(
        root.join(".birkin/config.yaml"),
        r#"version: 1
project:
  name: bad-lean
  languages: [lean]
proofs:
  prove_architecture: false
  lean_projects:
    - name: bad-spec
      dir: spec
      modules: [BadSpec]
      theorems: [broken]
"#,
    )
    .unwrap();

    let (spec, _) = load_project_spec(root, None).unwrap();
    let out = run_prove(root, &spec, None, false);
    assert_eq!(out.exit_code, EXIT_STATIC);
    let rules: Vec<&str> = out.findings.iter().map(|f| f.rule.as_str()).collect();
    assert!(rules.contains(&"PROOF_LEAN_SORRY"), "got {rules:?}");
    assert!(
        rules.contains(&"PROOF_CUSTOM_AXIOM_DECL"),
        "got {rules:?}"
    );
}

#[test]
fn prove_cli_dogfoods_birkin_repository() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bin = env!("CARGO_BIN_EXE_birkin");
    let out = Command::new(bin)
        .args(["prove", "--no-receipt", "--json"])
        .current_dir(&repo_root)
        .output()
        .expect("run birkin prove");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "birkin prove failed on self: stdout={stdout}\nstderr={stderr}"
    );
    let parsed: Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(parsed["status"], "PASS");
    assert_eq!(parsed["architecture_dag_proved"], true);
    assert!(parsed["theorems_proved"].as_array().unwrap().len() >= 10);
}
