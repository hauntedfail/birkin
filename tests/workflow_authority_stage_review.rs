//! Compare workflow decisions with Lean and exercise their evidence adapters on real inputs.
mod common;

use birkin::authority_contract::verify_dispatch;
use birkin::review_closure::verify_review_closure;
use birkin::stage_contract::{
    parse_test_counts, stage_admitted, verify_sawyer, verify_toolchain_pins, SawyerPhase,
    TestCounts,
};
use birkin::workflow_models::*;
use common::{assert_matches_oracle, bit};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn dispatch(role: AgentRole, tier: ApprovalTier) -> DispatchManifest {
    DispatchManifest {
        role,
        requested_tier: tier,
        explicit_f_auth: false,
        is_refusal_retry: false,
        prev_tier: ApprovalTier::R,
        retries_after_first: 0,
        model: Some("worker".into()),
        runtime: Some("local".into()),
        implementer_model: Some("impl".into()),
        implementer_runtime: Some("local".into()),
        forbidden_model_patterns: vec![],
    }
}

#[test]
fn diff_authority() {
    use AgentRole::*;
    use ApprovalTier::*;
    let mut queries = vec![];
    let mut verdicts = vec![];
    for role in [
        Scope,
        Review,
        Research,
        Docs,
        Investigate,
        Implement,
        Finalize,
    ] {
        for tier in [R, W, F] {
            for previous in [R, W, F] {
                for flags in 0..64 {
                    let flag = |i: u32| (flags & (1 << i)) != 0;
                    let mut req = dispatch(role, tier);
                    req.explicit_f_auth = flag(0);
                    req.is_refusal_retry = flag(1);
                    req.prev_tier = previous;
                    req.retries_after_first = if flag(2) { 3 } else { 2 };
                    if flag(3) {
                        req.forbidden_model_patterns.push("w*r?er".into());
                    }
                    if !flag(4) {
                        req.implementer_runtime = Some("other".into());
                    }
                    if flag(5) {
                        req.implementer_model = req.model.clone();
                    }
                    queries.push(format!(
                        "authority_admit {} {} {} {} {} {} {} {} {}",
                        role.as_str(),
                        tier.as_str(),
                        bit(flag(0)),
                        bit(flag(1)),
                        previous.as_str(),
                        req.retries_after_first,
                        bit(flag(3)),
                        bit(flag(4)),
                        bit(flag(5))
                    ));
                    verdicts.push(verify_dispatch(&req, &[]).is_ok());
                }
            }
        }
    }
    assert_matches_oracle(&queries, &verdicts);
}

#[test]
fn unknown_identity_and_independent_policy_cannot_grant_authority() {
    let mut r = dispatch(AgentRole::Review, ApprovalTier::R);
    r.implementer_model = None;
    assert!(verify_dispatch(&r, &[]).is_err());
    r.implementer_runtime = Some("different".into());
    assert!(verify_dispatch(&r, &[]).is_ok());
    let forbidden = ["*ORK*".into()];
    assert!(verify_dispatch(&r, &forbidden).is_err());
    r.model = None;
    assert!(verify_dispatch(&r, &forbidden).is_err());
}

#[test]
fn diff_stage_and_review_predecessor() {
    use LifecycleStage::*;
    let mut queries = vec![];
    let mut verdicts = vec![];
    let stages = [
        Implemented,
        Verified,
        Reviewed,
        Committed,
        Pushed,
        CiPassed,
        Released,
    ];
    for flags in 0..2048 {
        let b = |i: u32| flags & (1 << i) != 0;
        for (discovered, executed) in [(0, 0), (2, 1), (2, 2)] {
            let ev = StageEvidenceInput {
                discovered_tests: discovered,
                executed_tests: executed,
                toolchain_matched: b(0),
                receipt_chain_ok: b(1),
                tree_bound_ok: b(2),
                review_passed: b(3),
                sawyer_staged_exact: b(4),
                sawyer_excluded_clean: b(5),
                gpg_sign_required: b(6),
                gpg_sig_valid: b(7),
                remote_head_matches: b(8),
                ci_passed: b(9),
                release_authorized: b(10),
            };
            let bits = (0..11).map(|i| bit(b(i))).collect::<Vec<_>>().join(" ");
            let mut predecessor = true;
            for stage in stages {
                let admitted = stage_admitted(stage, &ev);
                assert!(
                    !admitted || predecessor,
                    "{stage:?} skipped its predecessor"
                );
                predecessor = admitted;
                queries.push(format!(
                    "stage_admit {} {discovered} {executed} {bits}",
                    stage.as_str()
                ));
                verdicts.push(admitted);
            }
        }
    }
    assert_matches_oracle(&queries, &verdicts);
}

#[test]
fn diff_review_closure() {
    use ReviewClassification::*;
    let mut queries = vec![];
    let mut verdicts = vec![];
    for class in [
        Unclassified,
        MustFix,
        AlreadyFixed,
        NotValid,
        OutOfScope,
        NeedsClarification,
    ] {
        for flags in 0..64 {
            let b = |i: u32| flags & (1 << i) != 0;
            let item = CanonicalReviewItemSpec {
                item_key: "item".into(),
                classification: class,
                replied: b(0),
                resolved: b(1),
                fix_verified: b(2),
                reply_url: b(3).then(|| "https://review.example/replies/1".into()),
            };
            let mut items = vec![item.clone()];
            let effective_reply = b(0) && (!b(1) || b(3));
            let row = format!(
                "item,{},{},{},{}",
                class.as_str(),
                bit(effective_reply),
                bit(b(1)),
                bit(b(2))
            );
            let mut rows = vec![row.clone()];
            if b(4) {
                items.push(item);
                rows.push(row);
            }
            queries.push(format!(
                "review_closure {} {}",
                if b(5) { "rereview" } else { "valid" },
                rows.join(";")
            ));
            verdicts.push(
                verify_review_closure(&ReviewStateDocument {
                    canonical_review_items: items,
                    request_re_review: b(5),
                })
                .is_ok(),
            );
        }
    }
    assert_matches_oracle(&queries, &verdicts);
}

#[test]
fn review_keys_classifications_and_reply_urls() {
    let mut state: ReviewStateDocument = serde_json::from_str(r#"{"canonicalReviewItems":[{"itemKey":"x","classification":"already_fixed","resolved":true,"replied":true,"reply_url":"https://review.example/comment/1"}]}"#).unwrap();
    assert!(verify_review_closure(&state).is_ok());
    for url in ["", " ", "not a URL", "https:///missing-host"] {
        state.canonical_review_items[0].reply_url = Some(url.into());
        assert!(verify_review_closure(&state).is_err());
    }
    state.canonical_review_items[0].resolved = false;
    state.canonical_review_items[0].item_key = " ".into();
    assert!(verify_review_closure(&state).is_err());
    assert!(serde_json::from_str::<ReviewStateDocument>(
        r#"{"canonicalReviewItems":[{"itemKey":"x","classification":"approved"}]}"#
    )
    .is_err());
}

#[test]
fn runner_transcripts_require_positive_complete_passing_results() {
    let cargo = "running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n";
    let combined = cargo.repeat(2);
    let cases = [
        ("cargo_test", combined.as_str(), 2),
        (
            "go_test",
            "=== RUN   TestA\n--- PASS: TestA (0.00s)\nPASS\nok\texample\t0.1s",
            1,
        ),
        (
            "pytest",
            "collected 2 items\n====== 2 passed in 0.01s ======",
            2,
        ),
        ("pytest", "2 passed in 0.01s", 2),
        (
            "vitest",
            " Test Files  1 passed (1)\n      Tests  2 passed (2)",
            2,
        ),
        (
            "playwright",
            "Running 2 tests using 1 worker\n  2 passed (2.0s)",
            2,
        ),
        ("lake", "Running 2 tests\n2 tests passed", 2),
    ];
    for (parser, text, n) in cases {
        assert_eq!(
            parse_test_counts(parser, text, 0).unwrap(),
            TestCounts {
                discovered: n,
                executed: n
            }
        );
        for bad in [
            "1 failed",
            "1 skipped",
            "FAILED example",
            "SKIPPED: example",
        ] {
            assert!(
                parse_test_counts(parser, &format!("{text}\n{bad}"), 0).is_err(),
                "{parser}: {bad}"
            );
        }
        assert!(parse_test_counts(parser, text, 1).is_err());
        assert!(parse_test_counts(parser, "", 0).is_err());
    }
    for (parser, text) in [
        ("cargo_test", cargo.trim_start_matches("running 1 test\n")),
        ("cargo_test", &format!("{cargo}running 2 tests")),
        ("go_test", "ok example (cached)"),
        ("go_test", "=== RUN   TestA\nPASS"),
        ("go_test", "=== RUN   TestA\n--- SKIP: TestA (0.00s)\nPASS"),
        ("pytest", "collected 3 items\n2 passed in 0.01s"),
        ("pytest", "2 passed, 1 deselected in 0.01s"),
        ("vitest", "Tests  2 passed (3)"),
        ("vitest", "Tests  0 passed (0)"),
        (
            "playwright",
            "Running 3 tests using 1 worker\n2 passed (1s)",
        ),
        (
            "playwright",
            "Running 3 tests using 1 worker\n2 passed (1s)\n1 did not run",
        ),
        ("lake", "Build completed successfully (36 jobs)."),
        ("lake", "Running 2 tests\n1 test passed"),
    ] {
        assert!(
            parse_test_counts(parser, text, 0).is_err(),
            "{parser}: {text}"
        );
    }
}

#[test]
fn toolchain_pins_bind_every_configured_file() {
    let t = tempdir().unwrap();
    let root = t.path();
    fs::write(root.join("lean-toolchain"), "leanprover/lean4:v4.36.0\n").unwrap();
    fs::write(root.join(".tool-versions"), "node 24\npython 3.13\n").unwrap();
    let mut observed = BTreeMap::from([
        ("lean-toolchain".into(), "leanprover/lean4:v4.36.0".into()),
        (".tool-versions".into(), "node 24\npython 3.13".into()),
    ]);
    let files: Vec<_> = observed.keys().cloned().collect();
    assert!(verify_toolchain_pins(root, &files, &observed).is_ok());
    observed.remove(".tool-versions");
    assert!(verify_toolchain_pins(root, &files, &observed).is_err());
    observed.insert(".tool-versions".into(), "node 23\npython 3.13".into());
    assert!(verify_toolchain_pins(root, &files, &observed).is_err());
    for name in ["missing", "../outside", ""] {
        assert!(verify_toolchain_pins(root, &[name.into()], &observed).is_err());
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let o = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout).unwrap().trim_end().into()
}

#[test]
fn sawyer_reads_the_index_signature_and_actual_remote_ref() {
    // Isolate both the fixture Git commands and every command spawned by the engine.
    if std::env::var_os("BIRKIN_SAWYER_TEST_CHILD").is_none() {
        let o = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sawyer_reads_the_index_signature_and_actual_remote_ref",
                "--nocapture",
            ])
            .env("BIRKIN_SAWYER_TEST_CHILD", "1")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        return;
    }
    use SawyerPhase::*;
    let tmp = tempdir().unwrap();
    let root = tmp.path().join("work");
    let remote = tmp.path().join("remote.git");
    git(tmp.path(), &["init", "-q", "-b", "main", "work"]);
    git(tmp.path(), &["init", "-q", "--bare", "remote.git"]);
    git(&root, &["config", "user.email", "fixture@example.invalid"]);
    git(&root, &["config", "user.name", "Fixture"]);
    git(
        &root,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    fs::write(root.join("exclusions"), "local.txt\n").unwrap();
    git(&root, &["add", "exclusions"]);
    git(&root, &["commit", "-qm", "baseline"]);
    let base = git(&root, &["rev-parse", "HEAD"]);
    fs::write(root.join("local.txt"), "private fixture").unwrap();
    fs::write(root.join("route[1].rs"), "approved\n").unwrap();
    let mut p = SawyerContextPack {
        repo_root: root.to_str().unwrap().into(),
        target_branch: "main".into(),
        remote: Some("origin".into()),
        target_ref: None,
        approved_files: vec!["route[1].rs".into()],
        excluded_files: vec!["local.txt".into()],
        expected_commit_sha: None,
        require_signed: Some(false),
    };
    let check = |p: &SawyerContextPack, phase| verify_sawyer(&root, p, phase, Some("exclusions"));
    check(&p, Preflight).unwrap();
    assert!(verify_sawyer(&root, &p, Preflight, None).is_err());
    assert!(check(&p, Staged).is_err());
    p.target_branch = "wrong".into();
    assert!(check(&p, Preflight).is_err());
    p.target_branch = "main".into();
    p.excluded_files.push("unlisted.txt".into());
    assert!(check(&p, Preflight).is_err());
    p.excluded_files.pop();
    git(&root, &["add", "."]);
    assert!(check(&p, Staged).is_err());
    git(&root, &["reset", "-q", "--", "local.txt"]);
    check(&p, Staged).unwrap();
    git(&root, &["commit", "-qm", "approved"]);
    p.expected_commit_sha = Some(git(&root, &["rev-parse", "HEAD"]));
    assert!(check(&p, PostPush).is_err());
    git(&root, &["push", "-q", "origin", "main"]);
    check(&p, PostPush).unwrap();
    git(&remote, &["update-ref", "refs/heads/main", &base]);
    assert_eq!(
        git(&root, &["rev-parse", "origin/main"]),
        *p.expected_commit_sha.as_ref().unwrap()
    );
    assert!(check(&p, PostPush).is_err());
    git(&root, &["push", "-q", "origin", "main"]);
    git(&root, &["config", "commit.gpgsign", "true"]);
    assert!(check(&p, PostPush).is_err());
    let key = tmp.path().join("signing-key");
    let o = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f", key.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(o.status.success());
    let trusted = tmp.path().join("allowed-signers");
    fs::write(
        &trusted,
        format!(
            "fixture@example.invalid {}",
            fs::read_to_string(key.with_extension("pub")).unwrap()
        ),
    )
    .unwrap();
    git(&root, &["config", "gpg.format", "ssh"]);
    git(
        &root,
        &[
            "config",
            "gpg.ssh.allowedSignersFile",
            trusted.to_str().unwrap(),
        ],
    );
    git(&root, &["config", "user.signingkey", key.to_str().unwrap()]);
    fs::write(root.join("route[1].rs"), "signed\n").unwrap();
    git(&root, &["commit", "-qam", "signed change"]);
    git(&root, &["push", "-q", "origin", "main"]);
    assert!(check(&p, PostPush).is_err());
    p.expected_commit_sha = Some(git(&root, &["rev-parse", "HEAD"]));
    check(&p, PostPush).unwrap();
    fs::write(root.join("route[1].rs"), "pending change").unwrap();
    assert!(check(&p, PostPush).is_err());
    fs::write(root.join("route[1].rs"), "signed\n").unwrap();
    p.approved_files.push("extra".into());
    assert!(check(&p, PostPush).is_err());
}
