use birkin::lean_certify::{certify_obligation, resolve_lean_lib_dir, CertObligation};
use birkin::lean_kernel::{
    eval_authority, eval_plan, eval_plan_dispatch, eval_review_closure, eval_scope, eval_stage,
    KernelAuthorityRequest, KernelBlockingQuestion, KernelPathDecision, KernelPlanDispatchRequest,
    KernelPlanRequest, KernelPlanTask, KernelReviewClosureRequest, KernelReviewItem,
    KernelScopeRequest, KernelStageRequest,
};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;

fn birkin_bin() -> &'static str {
    env!("CARGO_BIN_EXE_birkin")
}

fn init_git_repo(dir: &Path) {
    let run = |args: &[&str]| {
        let out = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .expect("git");
        assert!(out.status.success(), "git {:?} failed", args);
    };
    run(&["init", "-b", "main"]);
    run(&["config", "user.name", "Birkin Test"]);
    run(&["config", "user.email", "test@birkin.local"]);
    run(&["config", "commit.gpgsign", "false"]);
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(dir.join("src/app.rs"), "pub fn ok() {}\n").unwrap();
    fs::create_dir_all(dir.join(".birkin")).unwrap();
    fs::write(
        dir.join(".birkin/config.yaml"),
        "version: 1\nproject:\n  name: cert-e2e\n  languages: [rust]\ntelemetry:\n  enabled: true\nworkflow:\n  enabled_contracts: [plan, scope, authority, stage, sawyer, review_closure]\n",
    )
    .unwrap();
    run(&["add", "-A"]);
    run(&["commit", "-m", "init"]);
}

fn sample_plan_req() -> KernelPlanRequest {
    KernelPlanRequest {
        tasks: vec![
            KernelPlanTask {
                id: "t-1".into(),
                status: "done".into(),
                depends_on: vec![],
                has_completion_evidence: true,
                allowed_paths_nonempty: true,
                verification_nonempty: true,
            },
            KernelPlanTask {
                id: "t-2".into(),
                status: "ready".into(),
                depends_on: vec!["t-1".into()],
                has_completion_evidence: false,
                allowed_paths_nonempty: true,
                verification_nonempty: true,
            },
        ],
        questions: vec![],
    }
}

#[test]
fn mode_a_evaluates_all_five_contracts_and_rejects_violations() {
    let plan_ok = eval_plan(&sample_plan_req()).expect("plan kernel pass");
    assert!(plan_ok.verdict.admitted);
    assert_eq!(plan_ok.done_tasks, vec!["t-1"]);
    assert_eq!(plan_ok.ready_tasks, vec!["t-2"]);

    let dispatch_plan_only = eval_plan_dispatch(&KernelPlanDispatchRequest {
        intent: "plan-only".into(),
        task_id: "t-2".into(),
        tasks: sample_plan_req().tasks,
        questions: vec![],
    })
    .expect("plan_dispatch kernel");
    assert!(!dispatch_plan_only.admitted);
    assert!(!dispatch_plan_only.reasons.is_empty());

    let scope_special = eval_scope(&KernelScopeRequest {
        authority: "source".into(),
        decisions: vec![KernelPathDecision {
            inside_root: true,
            matched_allowed: true,
            matched_forbidden: false,
            matched_verify_output: false,
        }],
        my_writes: vec!["src/a b,c|d;\"e\".rs".into()],
        other_active_writes: vec!["docs/readme.md".into()],
    })
    .expect("scope special chars");
    assert!(scope_special.verdict.admitted);
    assert_eq!(scope_special.path_admitted, vec![true]);
    assert!(scope_special.overlapping_writes.is_empty());

    let scope_overlap = eval_scope(&KernelScopeRequest {
        authority: "source".into(),
        decisions: vec![KernelPathDecision {
            inside_root: true,
            matched_allowed: true,
            matched_forbidden: false,
            matched_verify_output: false,
        }],
        my_writes: vec!["src/routes/api/items/[id].ts".into()],
        other_active_writes: vec!["src/routes/".into()],
    })
    .expect("scope overlap");
    assert!(!scope_overlap.verdict.admitted);
    assert_eq!(
        scope_overlap.overlapping_writes,
        vec!["src/routes/api/items/[id].ts"]
    );

    let auth_denied = eval_authority(&KernelAuthorityRequest {
        role: "review".into(),
        requested_tier: "W".into(),
        explicit_f_auth: false,
        is_refusal_retry: false,
        prev_tier: "R".into(),
        retries_after_first: 0,
        forbidden_model: false,
        same_impl_runtime: false,
        same_impl_model: false,
    })
    .expect("authority kernel");
    assert!(!auth_denied.admitted);
    assert!(!auth_denied.reasons.is_empty());

    let stage_zero_tests = eval_stage(&KernelStageRequest {
        stage: "verified".into(),
        discovered_tests: 0,
        executed_tests: 0,
        toolchain_matched: true,
        receipt_chain_ok: true,
        tree_bound_ok: true,
        review_passed: false,
        sawyer_staged_exact: false,
        sawyer_excluded_clean: false,
        gpg_sign_required: false,
        gpg_sig_valid: false,
        remote_head_matches: false,
        ci_passed: false,
        release_authorized: false,
    })
    .expect("stage kernel");
    assert!(!stage_zero_tests.admitted);

    let review_blocked = eval_review_closure(&KernelReviewClosureRequest {
        request_re_review: true,
        items: vec![KernelReviewItem {
            item_key: "pr-1#c1".into(),
            classification: "needs_clarification".into(),
            replied: true,
            resolved: false,
            fix_verified: false,
        }],
    })
    .expect("review closure kernel");
    assert!(!review_blocked.admitted);
}

#[test]
fn mode_b_certifies_valid_obligations_and_rejects_violations_in_lean_kernel() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let emitted = tmp.path().join("authority.lean");

    let ok_auth = KernelAuthorityRequest {
        role: "implement".into(),
        requested_tier: "W".into(),
        explicit_f_auth: false,
        is_refusal_retry: false,
        prev_tier: "R".into(),
        retries_after_first: 0,
        forbidden_model: false,
        same_impl_runtime: false,
        same_impl_model: false,
    };
    let outcome = certify_obligation(&CertObligation::Authority(ok_auth), Some(&emitted))
        .expect("certify authority");
    assert!(outcome.certified, "expected certified: {:?}", outcome.detail);
    assert!(outcome.kernel_axioms.is_empty());
    assert_eq!(outcome.proof_sha256.len(), 64);
    assert!(emitted.is_file());

    // Re-verify the emitted .lean certificate directly with standalone `lean`.
    let lib_dir = resolve_lean_lib_dir().expect("lean lib dir");
    let recheck = Command::new("lean")
        .arg(&emitted)
        .env("LEAN_PATH", &lib_dir)
        .output()
        .expect("run standalone lean");
    assert!(
        recheck.status.success(),
        "standalone lean failed: {}",
        String::from_utf8_lossy(&recheck.stderr)
    );

    // Violating obligation must be rejected by the Lean kernel as unprovable.
    let bad_plan = KernelPlanRequest {
        tasks: vec![KernelPlanTask {
            id: "t-1".into(),
            status: "ready".into(),
            depends_on: vec![],
            has_completion_evidence: false,
            allowed_paths_nonempty: true,
            verification_nonempty: true,
        }],
        questions: vec![KernelBlockingQuestion {
            id: "q-1".into(),
            blocks: vec!["t-1".into()],
        }],
    };
    let rejected = certify_obligation(&CertObligation::Plan(bad_plan), None)
        .expect("certify rejected plan");
    assert!(!rejected.certified);
    assert!(rejected.detail.is_some());

    // Certify remaining contracts (Plan, Scope, Stage, ReviewClosure).
    assert!(certify_obligation(&CertObligation::Plan(sample_plan_req()), None)
        .expect("certify plan")
        .certified);
    assert!(certify_obligation(
        &CertObligation::PlanDispatch(KernelPlanDispatchRequest {
            intent: "implement".into(),
            task_id: "t-2".into(),
            tasks: sample_plan_req().tasks,
            questions: vec![],
        }),
        None,
    )
    .expect("certify plan dispatch")
    .certified);
    assert!(certify_obligation(
        &CertObligation::Scope(KernelScopeRequest {
            authority: "source".into(),
            decisions: vec![KernelPathDecision {
                inside_root: true,
                matched_allowed: true,
                matched_forbidden: false,
                matched_verify_output: false,
            }],
            my_writes: vec!["src/main.rs".into()],
            other_active_writes: vec!["docs/guide.md".into()],
        }),
        None,
    )
    .expect("certify scope")
    .certified);
    assert!(certify_obligation(
        &CertObligation::Stage(KernelStageRequest {
            stage: "verified".into(),
            discovered_tests: 4,
            executed_tests: 4,
            toolchain_matched: true,
            receipt_chain_ok: true,
            tree_bound_ok: true,
            review_passed: false,
            sawyer_staged_exact: false,
            sawyer_excluded_clean: false,
            gpg_sign_required: false,
            gpg_sig_valid: false,
            remote_head_matches: false,
            ci_passed: false,
            release_authorized: false,
        }),
        None,
    )
    .expect("certify stage")
    .certified);
    assert!(certify_obligation(
        &CertObligation::ReviewClosure(KernelReviewClosureRequest {
            request_re_review: true,
            items: vec![KernelReviewItem {
                item_key: "pr-7#r1".into(),
                classification: "must_fix".into(),
                replied: true,
                resolved: true,
                fix_verified: true,
            }],
        }),
        None,
    )
    .expect("certify review closure")
    .certified);
}

#[test]
fn cli_e2e_mode_a_mode_b_certify_ledger_and_fail_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("repo");
    let ledger_dir = tmp.path().join("ledger");
    fs::create_dir_all(&repo).unwrap();
    init_git_repo(&repo);

    let plan_path = tmp.path().join("plan.json");
    let plan_json = serde_json::json!({
        "version": 1,
        "intent": "implement",
        "outcome": "Verify Mode A and Mode B CLI end-to-end",
        "non_goals": [],
        "constraints": ["Lean kernel is sole authority"],
        "evidence": ["src/app.rs:1"],
        "questions": [],
        "tasks": [{
            "id": "t-1",
            "title": "Edit app.rs",
            "checkout_root": repo.to_string_lossy(),
            "context": "Demo unit",
            "expected_behavior": "Updates app.rs",
            "status": "ready",
            "depends_on": [],
            "allowed_paths": ["src/app.rs"],
            "forbidden_paths": [],
            "verification_output_paths": [],
            "acceptance": ["app.rs updated"],
            "verification": [{"method": "cargo test", "expected": "exit 0"}],
            "stop_conditions": ["missing kernel"],
            "owner": "implementation",
            "completion_evidence": []
        }]
    });
    fs::write(&plan_path, serde_json::to_string_pretty(&plan_json).unwrap()).unwrap();

    let review_path = tmp.path().join("review.json");
    let review_json = serde_json::json!({
        "request_re_review": true,
        "canonical_review_items": [{
            "item_key": "pr-9#c1",
            "classification": "must_fix",
            "replied": true,
            "reply_url": "https://github.com/hauntedfail/birkin/pull/9#discussion_r1",
            "resolved": true,
            "fix_verified": true
        }]
    });
    fs::write(&review_path, serde_json::to_string_pretty(&review_json).unwrap()).unwrap();

    // 1. Mode A: plan verify -> verification_mode=lean_kernel
    let out_a = Command::new(birkin_bin())
        .args(["plan", "verify", plan_path.to_str().unwrap(), "--repo", repo.to_str().unwrap(), "--no-receipt", "--json"])
        .output()
        .expect("run plan verify mode A");
    assert_eq!(out_a.status.code(), Some(0), "{}", String::from_utf8_lossy(&out_a.stdout));
    let val_a: Value = serde_json::from_slice(&out_a.stdout).unwrap();
    assert_eq!(val_a["verification_mode"], "lean_kernel");
    assert_eq!(val_a["valid"], true);

    // 2. Mode B: plan verify --certify --emit-proof + ledger receipt
    let emitted_plan = tmp.path().join("plan_cert.lean");
    let out_b = Command::new(birkin_bin())
        .env("BIRKIN_LEDGER_DIR", &ledger_dir)
        .args([
            "plan", "verify", plan_path.to_str().unwrap(),
            "--repo", repo.to_str().unwrap(),
            "--certify", "--emit-proof", emitted_plan.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run plan verify mode B");
    assert_eq!(out_b.status.code(), Some(0), "{}", String::from_utf8_lossy(&out_b.stdout));
    let val_b: Value = serde_json::from_slice(&out_b.stdout).unwrap();
    assert_eq!(val_b["verification_mode"], "lean_certified");
    let std_axioms = ["propext", "Classical.choice", "Quot.sound"];
    assert!(val_b["kernel_axioms"]
        .as_array()
        .unwrap()
        .iter()
        .all(|a| std_axioms.contains(&a.as_str().unwrap())));
    assert_eq!(val_b["proof_sha256"].as_str().unwrap().len(), 64);
    assert!(val_b["receipt_sha256"].as_str().is_some());
    assert!(emitted_plan.is_file());

    // Verify receipt ledger chain binds plan-verify on the clean repo.
    let rcpt = Command::new(birkin_bin())
        .env("BIRKIN_LEDGER_DIR", &ledger_dir)
        .args(["receipt", "verify", repo.to_str().unwrap(), "--require", "plan-verify", "--require-clean", "--json"])
        .output()
        .expect("verify receipt");
    assert_eq!(rcpt.status.code(), Some(0), "{}", String::from_utf8_lossy(&rcpt.stdout));

    // 3. Mode B: unit admit (combined PlanDispatch + Authority certificate)
    let emitted_admit = tmp.path().join("admit_cert.lean");
    let out_admit = Command::new(birkin_bin())
        .args([
            "unit", "admit", "--plan", plan_path.to_str().unwrap(),
            "--task", "t-1", "--role", "implement", "--tier", "W",
            "--repo", repo.to_str().unwrap(),
            "--certify", "--emit-proof", emitted_admit.to_str().unwrap(),
            "--no-receipt", "--json",
        ])
        .output()
        .expect("run unit admit mode B");
    assert_eq!(out_admit.status.code(), Some(0), "{}", String::from_utf8_lossy(&out_admit.stdout));
    let val_admit: Value = serde_json::from_slice(&out_admit.stdout).unwrap();
    assert_eq!(val_admit["verification_mode"], "lean_certified");
    assert_eq!(val_admit["admitted"], true);

    // Re-check emitted combined certificate directly with standalone `lean`.
    let lib_dir = resolve_lean_lib_dir().expect("lean lib dir");
    let standalone = Command::new("lean")
        .arg(&emitted_admit)
        .env("LEAN_PATH", &lib_dir)
        .output()
        .expect("standalone lean");
    assert!(standalone.status.success(), "{}", String::from_utf8_lossy(&standalone.stderr));

    // 4. Mode B: unit verify-scope and review-closure verify
    let out_scope = Command::new(birkin_bin())
        .args([
            "unit", "verify-scope", "--plan", plan_path.to_str().unwrap(),
            "--task", "t-1", "--repo", repo.to_str().unwrap(),
            "--path", "src/app.rs", "--certify", "--no-receipt", "--json",
        ])
        .output()
        .expect("unit verify-scope mode B");
    assert_eq!(out_scope.status.code(), Some(0), "{}", String::from_utf8_lossy(&out_scope.stdout));
    let val_scope: Value = serde_json::from_slice(&out_scope.stdout).unwrap();
    assert_eq!(val_scope["verification_mode"], "lean_certified");

    let out_rc = Command::new(birkin_bin())
        .args([
            "review-closure", "verify", review_path.to_str().unwrap(),
            "--repo", repo.to_str().unwrap(),
            "--certify", "--no-receipt", "--json",
        ])
        .output()
        .expect("review-closure mode B");
    assert_eq!(out_rc.status.code(), Some(0), "{}", String::from_utf8_lossy(&out_rc.stdout));
    let val_rc: Value = serde_json::from_slice(&out_rc.stdout).unwrap();
    assert_eq!(val_rc["verification_mode"], "lean_certified");

    // 5. Fail-closed Proof-of-Life: missing BIRKIN_KERNEL_BIN exits 5 (NO silent Rust fallback)
    for args in [
        vec!["plan", "verify", plan_path.to_str().unwrap(), "--repo", repo.to_str().unwrap(), "--no-receipt", "--json"],
        vec!["unit", "admit", "--plan", plan_path.to_str().unwrap(), "--task", "t-1", "--role", "implement", "--tier", "W", "--repo", repo.to_str().unwrap(), "--no-receipt", "--json"],
        vec!["unit", "verify-scope", "--plan", plan_path.to_str().unwrap(), "--task", "t-1", "--repo", repo.to_str().unwrap(), "--path", "src/app.rs", "--no-receipt", "--json"],
        vec!["review-closure", "verify", review_path.to_str().unwrap(), "--repo", repo.to_str().unwrap(), "--no-receipt", "--json"],
    ] {
        let missing = Command::new(birkin_bin())
            .env("BIRKIN_KERNEL_BIN", "/nonexistent/birkin-kernel")
            .args(&args)
            .output()
            .expect("run with missing kernel");
        assert_eq!(missing.status.code(), Some(5), "expected exit 5 for {:?}, got {:?}", args, String::from_utf8_lossy(&missing.stdout));
    }

    // 6. Fail-closed Mode B: missing BIRKIN_LEAN_LIB exits 5
    let missing_lib = Command::new(birkin_bin())
        .env("BIRKIN_LEAN_LIB", "/nonexistent/birkin-lean-lib")
        .args(["plan", "verify", plan_path.to_str().unwrap(), "--repo", repo.to_str().unwrap(), "--certify", "--no-receipt", "--json"])
        .output()
        .expect("run certify with missing lean lib");
    assert_eq!(missing_lib.status.code(), Some(5));
}
