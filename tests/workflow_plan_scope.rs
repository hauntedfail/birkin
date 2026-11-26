//! Workflow plan and scope contract tests: differential parity against the Lean 4 oracle,
//! plan-contract structural rules, config schema, symlink escapes, bracket-route scoping,
//! and concurrent write overlap. Tests named `diff_*` require the built Lean oracle.

mod common;

use birkin::plan_contract::{
    can_dispatch_mutating, is_valid_scoped_path, load_plan_document, validate_plan_document,
};
use birkin::project_models::load_project_spec;
use birkin::scope_contract::{
    collect_git_changed_paths, path_admitted_bool, verify_task_scope, write_paths_overlap,
    PathAuthority, ScopeOutcome,
};
use birkin::workflow_models::{
    ActiveUnitRecord, PlanDocument, PlanQuestionSpec, PlanTaskSpec, PlanVerificationSpec,
};
use common::{assert_matches_oracle, bit, joined};
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const STATUSES: [&str; 5] = ["ready", "blocked", "in_progress", "done", "superseded"];

fn task(id: &str, status: &str, deps: &[&str], evidence: bool) -> PlanTaskSpec {
    PlanTaskSpec {
        id: id.into(),
        title: format!("Task {id}"),
        context: "Current behavior.".into(),
        expected_behavior: "Expected behavior.".into(),
        status: status.into(),
        depends_on: deps.iter().map(|d| d.to_string()).collect(),
        allowed_paths: vec!["src/".into()],
        forbidden_paths: vec![],
        verification_output_paths: vec![],
        checkout_root: None,
        acceptance: vec!["An observable assertion.".into()],
        verification: vec![PlanVerificationSpec {
            method: "cargo test".into(),
            expected: "exit 0".into(),
        }],
        stop_conditions: vec!["A required decision is missing.".into()],
        owner: "implementation".into(),
        completion_evidence: if evidence {
            vec!["cargo test: 3 passed".into()]
        } else {
            vec![]
        },
    }
}

fn question(id: &str, blocks: &[&str]) -> PlanQuestionSpec {
    PlanQuestionSpec {
        id: id.into(),
        question: "Which option?".into(),
        blocks: blocks.iter().map(|b| b.to_string()).collect(),
    }
}

fn plan(intent: &str, tasks: Vec<PlanTaskSpec>, questions: Vec<PlanQuestionSpec>) -> PlanDocument {
    PlanDocument {
        version: 1,
        intent: intent.into(),
        outcome: "An observable outcome.".into(),
        non_goals: vec![],
        constraints: vec!["A constraint.".into()],
        evidence: vec!["src/lib.rs".into()],
        questions,
        tasks,
    }
}

fn encode_plan(p: &PlanDocument) -> (String, String) {
    let tasks: Vec<String> = p
        .tasks
        .iter()
        .map(|t| {
            format!(
                "{},{},{},{},{},{}",
                t.id,
                t.status,
                joined(&t.depends_on, "|"),
                bit(!t.completion_evidence.is_empty()),
                bit(!t.allowed_paths.is_empty()),
                bit(!t.verification.is_empty())
            )
        })
        .collect();
    let questions: Vec<String> = p
        .questions
        .iter()
        .map(|q| format!("{},{}", q.id, joined(&q.blocks, "|")))
        .collect();
    (joined(&tasks, ";"), joined(&questions, ";"))
}

fn push_plan_cases(base: &PlanDocument, queries: &mut Vec<String>, rust: &mut Vec<bool>) {
    let (tasks, questions) = encode_plan(base);
    queries.push(format!("plan_valid {tasks} {questions}"));
    rust.push(validate_plan_document(base).valid);
    for intent in ["plan-only", "implement"] {
        let mut p = base.clone();
        p.intent = intent.into();
        for tid in ["t1", "t2", "t3", "t9"] {
            queries.push(format!("plan_dispatch {intent} {tid} {tasks} {questions}"));
            rust.push(can_dispatch_mutating(&p, tid).is_ok());
        }
    }
}

#[test]
fn diff_plan_validity_and_dispatch_match_lean() {
    let mut queries = Vec::new();
    let mut rust = Vec::new();

    // Two-task matrix: every status pair, dependency shape, evidence flag, and blocking question.
    for s1 in STATUSES {
        for s2 in STATUSES {
            for dep_shape in 0..4 {
                for evidence in 0..4 {
                    for blocked_by_question in 0..3 {
                        let (d1, d2): (&[&str], &[&str]) = match dep_shape {
                            0 => (&[], &[]),
                            1 => (&[], &["t1"]),
                            2 => (&["t2"], &[]),
                            _ => (&[], &["t9"]),
                        };
                        let tasks = vec![
                            task("t1", s1, d1, evidence & 1 == 1),
                            task("t2", s2, d2, evidence & 2 == 2),
                        ];
                        let questions = match blocked_by_question {
                            0 => vec![],
                            1 => vec![question("q1", &["t1"])],
                            _ => vec![question("q1", &["t2"])],
                        };
                        push_plan_cases(
                            &plan("implement", tasks, questions),
                            &mut queries,
                            &mut rust,
                        );
                    }
                }
            }
        }
    }

    // Three-task chain: a block must travel through every dependent unit.
    for s2 in STATUSES {
        for s3 in STATUSES {
            let tasks = vec![
                task("t1", "blocked", &[], false),
                task("t2", s2, &["t1"], false),
                task("t3", s3, &["t2"], false),
            ];
            push_plan_cases(
                &plan("implement", tasks, vec![question("q1", &["t1"])]),
                &mut queries,
                &mut rust,
            );
        }
    }

    // Structural edge cases.
    let mut no_paths = task("t1", "ready", &[], false);
    no_paths.allowed_paths.clear();
    let mut no_verification = task("t1", "ready", &[], false);
    no_verification.verification.clear();
    for tasks in [
        vec![],
        vec![
            task("t1", "ready", &[], false),
            task("t1", "ready", &[], false),
        ],
        vec![task("t1", "ready", &["t1"], false)],
        vec![no_paths],
        vec![no_verification],
        vec![
            task("t1", "done", &[], true),
            task("t2", "ready", &["t1"], false),
        ],
    ] {
        push_plan_cases(&plan("implement", tasks, vec![]), &mut queries, &mut rust);
    }
    push_plan_cases(
        &plan(
            "implement",
            vec![task("t1", "ready", &[], false)],
            vec![question("q1", &[])],
        ),
        &mut queries,
        &mut rust,
    );

    assert!(rust.iter().any(|v| *v) && rust.iter().any(|v| !*v));
    assert_matches_oracle(&queries, &rust);
}

#[test]
fn plan_contract_enforces_dispatch_and_structural_rules() {
    // A ready unit whose prerequisite is done is dispatchable only under intent=implement.
    let tasks = vec![
        task("t1", "done", &[], true),
        task("t2", "ready", &["t1"], false),
    ];
    assert!(can_dispatch_mutating(&plan("implement", tasks.clone(), vec![]), "t2").is_ok());
    let reasons = can_dispatch_mutating(&plan("plan-only", tasks, vec![]), "t2").unwrap_err();
    assert!(
        reasons.iter().any(|r| r.contains("plan-only")),
        "{reasons:?}"
    );

    // A blocked prerequisite must propagate; a ready dependent is a contract violation.
    let leaked = plan(
        "implement",
        vec![
            task("t1", "blocked", &[], false),
            task("t2", "ready", &["t1"], false),
        ],
        vec![question("q1", &["t1"])],
    );
    let outcome = validate_plan_document(&leaked);
    assert!(!outcome.valid);
    assert!(outcome
        .findings
        .iter()
        .any(|f| f.rule == "PLAN_BLOCK_PROPAGATION"));
    assert!(can_dispatch_mutating(&leaked, "t2").is_err());

    let rule_for = |p: &PlanDocument| -> Vec<String> {
        validate_plan_document(p)
            .findings
            .into_iter()
            .map(|f| f.rule)
            .collect()
    };
    let single = |t: PlanTaskSpec| plan("implement", vec![t], vec![]);

    assert!(
        rule_for(&single(task("t1", "done", &[], false))).contains(&"PLAN_DONE_EVIDENCE".into())
    );
    let mut relative_root = task("t1", "ready", &[], false);
    relative_root.checkout_root = Some("relative/checkout".into());
    assert!(rule_for(&single(relative_root)).contains(&"PLAN_CHECKOUT_ROOT".into()));
    let mut bracket = task("t1", "ready", &[], false);
    bracket.allowed_paths = vec!["src/routes/api/items/[id].ts".into()];
    assert!(rule_for(&single(bracket)).contains(&"PLAN_SCOPE_PATH".into()));
    let mut bad_version = single(task("t1", "ready", &[], false));
    bad_version.version = 2;
    assert!(rule_for(&bad_version).contains(&"PLAN_VERSION".into()));
    let mut bad_intent = single(task("t1", "ready", &[], false));
    bad_intent.intent = "ship-it".into();
    assert!(rule_for(&bad_intent).contains(&"PLAN_INTENT".into()));
    let unblocked_target = plan(
        "implement",
        vec![task("t1", "superseded", &[], false)],
        vec![question("q1", &["t1"])],
    );
    assert!(rule_for(&unblocked_target).contains(&"PLAN_QUESTION_TARGET".into()));

    for ok in ["src/lib.rs", "src/routes/api/items/", "docs/a b.md"] {
        assert!(is_valid_scoped_path(ok), "{ok}");
    }
    for bad in [
        "",
        "/abs",
        "~/home",
        "../up",
        "a/../b",
        "a//b",
        "src/*.rs",
        "src/[id].ts",
        ".",
        "a\\b",
    ] {
        assert!(!is_valid_scoped_path(bad), "{bad}");
    }
}

#[test]
fn plan_loader_keeps_extension_fields_and_fails_closed_on_malformed_input() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("plan.json");
    let mut value = serde_json::to_value(plan(
        "plan-only",
        vec![task("t1", "ready", &[], false)],
        vec![],
    ))
    .unwrap();
    value["assumptions"] = serde_json::json!(["An extension field outside the base contract."]);
    value["tasks"][0]["verification_output_paths"] = serde_json::json!(["target/"]);
    fs::write(&path, serde_json::to_string(&value).unwrap()).unwrap();
    let loaded = load_plan_document(&path).unwrap();
    assert!(validate_plan_document(&loaded).valid);
    assert_eq!(loaded.tasks[0].verification_output_paths, ["target/"]);

    fs::write(&path, "[]").unwrap();
    assert!(load_plan_document(&path).is_err());
    fs::write(&path, "{not json").unwrap();
    assert!(load_plan_document(&path).is_err());
    assert!(load_plan_document(&tmp.path().join("missing.json")).is_err());
}

#[test]
fn workflow_config_defaults_are_backward_compatible_and_unknown_values_fail_closed() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join(".birkin")).unwrap();
    let cfg = root.join(".birkin/config.yaml");
    let load = |body: &str| {
        fs::write(&cfg, body).unwrap();
        load_project_spec(root, None).map(|(spec, _)| spec.workflow)
    };

    let legacy = load("version: 1\nproject: {name: legacy}\n").unwrap();
    assert!(legacy.enabled_contracts.is_empty() && !legacy.require_plan_receipt);

    let opted_in = load(concat!(
        "version: 1\nworkflow:\n  enabled_contracts: [plan, scope, sawyer]\n",
        "  toolchain_pin_files: [lean/lean-toolchain]\n",
        "  test_runners:\n    - {name: unit, parser: cargo_test, require_nonzero: true}\n",
    ))
    .unwrap();
    assert!(opted_in.contract_enabled("scope") && !opted_in.contract_enabled("authority"));

    for bad in [
        "version: 1\nworkflow: {unknown_knob: true}\n",
        "version: 1\nworkflow: {enabled_contracts: [telepathy]}\n",
        "version: 1\nworkflow: {enabled_contracts: [plan, plan]}\n",
        "version: 1\nworkflow: {test_runners: [{name: unit, parser: tea_leaves}]}\n",
        "version: 1\nworkflow: {test_runners: [{name: a, parser: pytest}, {name: a, parser: pytest}]}\n",
    ] {
        assert!(load(bad).is_err(), "expected schema rejection for: {bad}");
    }
}

fn encode_scope(auth: PathAuthority, outcome: &ScopeOutcome, writes: &[String]) -> String {
    let decisions: Vec<String> = outcome
        .decisions
        .iter()
        .map(|d| {
            format!(
                "{},{},{},{}",
                bit(d.inside_root),
                bit(d.matched_allowed),
                bit(d.matched_forbidden),
                bit(d.matched_verify_output)
            )
        })
        .collect();
    let auth = match auth {
        PathAuthority::SourceEdit => "source",
        PathAuthority::VerificationOutput => "verification_output",
    };
    format!(
        "scope_admit {auth} {} {} {}",
        joined(&decisions, ";"),
        joined(writes, "|"),
        joined(&outcome.overlapping_writes, "|")
    )
}

fn scope_fixture() -> (TempDir, PlanTaskSpec) {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("checkout");
    for dir in ["src/routes/api/items", "src/private", "target"] {
        fs::create_dir_all(root.join(dir)).unwrap();
    }
    fs::create_dir_all(tmp.path().join("outside")).unwrap();
    fs::write(root.join("src/ok.rs"), "").unwrap();
    fs::write(root.join("src/routes/api/items/[id].ts"), "").unwrap();
    fs::write(root.join("src/private/key.rs"), "").unwrap();
    fs::write(root.join("target/out.bin"), "").unwrap();
    fs::write(root.join("README.md"), "").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(tmp.path().join("outside"), root.join("src/link")).unwrap();

    let mut unit = task("t1", "ready", &[], false);
    unit.allowed_paths = vec!["src/".into()];
    unit.forbidden_paths = vec!["src/private/".into()];
    unit.verification_output_paths = vec!["target/".into()];
    (tmp, unit)
}

fn rules(outcome: &ScopeOutcome) -> Vec<&str> {
    outcome.findings.iter().map(|f| f.rule.as_str()).collect()
}

#[test]
fn scope_engine_enforces_real_tree_boundaries() {
    let (tmp, unit) = scope_fixture();
    let root = tmp.path().join("checkout");
    let check = |paths: &[&str], auth: PathAuthority, others: &[ActiveUnitRecord]| {
        let paths: Vec<String> = paths.iter().map(|p| p.to_string()).collect();
        verify_task_scope(&root, &unit, &paths, auth, others)
    };
    let source = PathAuthority::SourceEdit;

    // Existing files, bracket-named dynamic routes, and not-yet-created paths inside the scope.
    let inside = check(
        &[
            "src/ok.rs",
            "src/routes/api/items/[id].ts",
            "src/new/deep/file.rs",
        ],
        source,
        &[],
    );
    assert!(inside.admitted, "{:?}", inside.findings);

    assert_eq!(
        rules(&check(&["src/private/key.rs"], source, &[])),
        ["SCOPE_FORBIDDEN_PATH"]
    );
    assert_eq!(
        rules(&check(&["README.md"], source, &[])),
        ["SCOPE_OUT_OF_BOUNDS"]
    );
    assert_eq!(
        rules(&check(&["../outside/x.rs"], source, &[])),
        ["SCOPE_ROOT_ESCAPE"]
    );
    assert_eq!(
        rules(&check(&["src/../../outside/x.rs"], source, &[])),
        ["SCOPE_ROOT_ESCAPE"]
    );
    let absolute_outside = tmp.path().join("outside/x.rs");
    assert_eq!(
        rules(&check(&[absolute_outside.to_str().unwrap()], source, &[])),
        ["SCOPE_ROOT_ESCAPE"]
    );
    #[cfg(unix)]
    for escaped in ["src/link/evil.rs", "src/link"] {
        assert_eq!(
            rules(&check(&[escaped], source, &[])),
            ["SCOPE_ROOT_ESCAPE"],
            "{escaped}"
        );
    }

    // Generated-output permission never grants source-edit authority.
    assert_eq!(
        rules(&check(&["target/out.bin"], source, &[])),
        ["SCOPE_VERIFY_OUTPUT_SOURCE_EDIT"]
    );
    assert!(check(&["target/out.bin"], PathAuthority::VerificationOutput, &[]).admitted);
    assert!(
        !check(
            &["src/private/key.rs"],
            PathAuthority::VerificationOutput,
            &[]
        )
        .admitted
    );

    // One bad path fails the whole unit.
    assert!(!check(&["src/ok.rs", "README.md"], source, &[]).admitted);

    // Concurrent writers on the same checkout must be disjoint, by file or directory prefix.
    let other = |task_id: &str, checkout: &Path, paths: &[&str]| ActiveUnitRecord {
        task_id: task_id.into(),
        checkout_root: checkout.to_string_lossy().into_owned(),
        write_paths: paths.iter().map(|p| p.to_string()).collect(),
    };
    let clash = check(&["src/ok.rs"], source, &[other("t2", &root, &["src/"])]);
    assert_eq!(rules(&clash), ["SCOPE_CONCURRENT_WRITE_OVERLAP"]);
    assert_eq!(clash.overlapping_writes, ["src/ok.rs"]);
    assert!(
        !check(
            &["src/ok.rs"],
            source,
            &[other("t2", &root, &["src/ok.rs"])]
        )
        .admitted
    );
    assert!(
        check(
            &["src/ok.rs"],
            source,
            &[other("t2", &root, &["src/okay.rs", "docs/"])]
        )
        .admitted
    );
    assert!(check(&["src/ok.rs"], source, &[other("t1", &root, &["src/"])]).admitted);
    let elsewhere = tmp.path().join("outside");
    assert!(
        check(
            &["src/ok.rs"],
            source,
            &[other("t2", &elsewhere, &["src/"])]
        )
        .admitted
    );

    assert!(write_paths_overlap("src", "src/a.rs") && write_paths_overlap("src/a.rs", "src/"));
    assert!(
        !write_paths_overlap("src/a.rs", "src/a.rs.bak") && !write_paths_overlap("src", "srcs/a")
    );
}

#[test]
fn diff_scope_decisions_match_lean() {
    let mut queries = Vec::new();
    let mut rust = Vec::new();

    // Exhaustive decision table for a single path, with and without a conflicting writer.
    for (auth, auth_name) in [
        (PathAuthority::SourceEdit, "source"),
        (PathAuthority::VerificationOutput, "verification_output"),
    ] {
        for mask in 0..16u8 {
            let flags = [mask & 1 != 0, mask & 2 != 0, mask & 4 != 0, mask & 8 != 0];
            let admitted = path_admitted_bool(auth, flags[0], flags[1], flags[2], flags[3]);
            let decision = flags.map(bit).join(",");
            for (other, overlap) in [("-", false), ("b", false), ("a", true), ("b|a", true)] {
                queries.push(format!("scope_admit {auth_name} {decision} a {other}"));
                rust.push(admitted && !overlap);
            }
        }
    }
    queries.push("scope_admit source - - -".into());
    rust.push(true);

    // Decisions extracted from a real tree: the Rust verdict must equal the Lean verdict
    // computed from the same extracted facts.
    let (tmp, unit) = scope_fixture();
    let root = tmp.path().join("checkout");
    let other = ActiveUnitRecord {
        task_id: "t2".into(),
        checkout_root: root.to_string_lossy().into_owned(),
        write_paths: vec!["src/routes/".into()],
    };
    let path_sets: [&[&str]; 7] = [
        &["src/ok.rs"],
        &["src/ok.rs", "src/new.rs"],
        &["src/ok.rs", "src/private/key.rs"],
        &["target/out.bin"],
        &["README.md", "../outside/x.rs"],
        &["src/routes/api/items/[id].ts"],
        &[],
    ];
    for paths in path_sets {
        let paths: Vec<String> = paths.iter().map(|p| p.to_string()).collect();
        for auth in [PathAuthority::SourceEdit, PathAuthority::VerificationOutput] {
            for others in [vec![], vec![other.clone()]] {
                let outcome = verify_task_scope(&root, &unit, &paths, auth, &others);
                let writes: Vec<String> = paths
                    .iter()
                    .filter(|p| !p.starts_with(".."))
                    .cloned()
                    .collect();
                queries.push(encode_scope(auth, &outcome, &writes));
                rust.push(outcome.admitted);
            }
        }
    }

    assert!(rust.iter().any(|v| *v) && rust.iter().any(|v| !*v));
    assert_matches_oracle(&queries, &rust);
}

#[test]
fn git_changed_paths_cover_untracked_and_staged_files() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .expect("run git");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    git(&["init", "-q"]);
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/staged.rs"), "").unwrap();
    fs::write(root.join("notes with space.txt"), "").unwrap();
    git(&["add", "src/staged.rs"]);

    assert_eq!(
        collect_git_changed_paths(root, true).unwrap(),
        ["src/staged.rs"]
    );
    assert_eq!(
        collect_git_changed_paths(root, false).unwrap(),
        ["notes with space.txt", "src/staged.rs"]
    );
    assert!(collect_git_changed_paths(&tmp.path().join("missing"), false).is_err());
}
