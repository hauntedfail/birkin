//! Stage-admission and Sawyer CLI handlers: observes ledger, Git tree, toolchain pins,
//! test transcripts, Sawyer state, and explicitly attested external evidence.

use crate::config_utils::sha256_hex;
use crate::constants::{EXIT_PASS, EXIT_STATIC};
use crate::lean_certify::{attach_attestation, CertObligation};
use crate::ledger::{read_receipts, resolve_ledger_path, verify_receipts_for_current_state};
use crate::project_models::{ProjectFinding, ProjectSpec};
use crate::review_closure::verify_review_closure;
use crate::stage_contract::{
    parse_test_counts, verify_sawyer, verify_stage_admission, verify_toolchain_pins, SawyerPhase,
};
use crate::workflow_cli::{
    emit_output, emit_tool_error, format_findings, load_workflow_repo, maybe_certify,
    record_workflow_receipt, workflow_finding, WorkflowRepoArgs,
};
use crate::workflow_models::{
    LifecycleStage, ReviewStateDocument, SawyerContextPack, StageEvidenceInput,
};
use clap::Args;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Instant;

#[derive(Args, Debug, Clone)]
pub struct StageVerifyArgs {
    /// Target lifecycle stage (implemented|verified|reviewed|committed|pushed|ci_passed|released)
    #[arg(long)]
    pub stage: String,
    #[command(flatten)]
    pub common: WorkflowRepoArgs,
    /// Comma-separated receipt commands required for current tree binding (default: check)
    #[arg(long)]
    pub require_commands: Option<String>,
    /// Require clean Git working tree when checking receipts
    #[arg(long)]
    pub require_clean: bool,
    /// Path to a test runner transcript file parsed via workflow.test_runners
    #[arg(long)]
    pub test_transcript: Option<PathBuf>,
    /// Configured runner name under workflow.test_runners (optional when only one is declared)
    #[arg(long)]
    pub test_runner: Option<String>,
    /// Process exit code recorded for the test runner invocation
    #[arg(long, default_value_t = 0)]
    pub test_exit_code: i32,
    /// JSON file mapping configured toolchain pin file paths to observed runner pin contents
    #[arg(long)]
    pub toolchain_manifest: Option<PathBuf>,
    /// Observed toolchain pin entry in `relative/path=content` form (repeatable)
    #[arg(long = "toolchain-pin")]
    pub toolchain_pins: Vec<String>,
    /// Sawyer context pack JSON file used to observe staging, commit, signature, and remote head
    #[arg(long)]
    pub sawyer_pack: Option<PathBuf>,
    /// Attested review evidence file (or review-state.json validated via review closure)
    #[arg(long)]
    pub review_evidence: Option<PathBuf>,
    /// Attested CI pass evidence file
    #[arg(long)]
    pub ci_evidence: Option<PathBuf>,
    /// Attested release authorization evidence file
    #[arg(long)]
    pub release_evidence: Option<PathBuf>,
}

struct AttestedRecord {
    value: bool,
    source: Option<String>,
    sha256: Option<String>,
}

impl AttestedRecord {
    fn absent() -> Self {
        Self { value: false, source: None, sha256: None }
    }

    fn to_json(&self) -> Value {
        json!({"value": self.value, "provenance": "attested", "source": self.source, "sha256": self.sha256})
    }
}

fn read_attested_evidence(
    path: Option<&Path>,
    label: &str,
    validate_review_doc: bool,
    findings: &mut Vec<ProjectFinding>,
) -> Result<AttestedRecord, String> {
    let Some(path) = path else {
        return Ok(AttestedRecord::absent());
    };
    let text = fs::read_to_string(path)
        .map_err(|e| format!("Failed reading {label} evidence {}: {e}", path.display()))?;
    let source = Some(path.to_string_lossy().into_owned());
    let sha256 = Some(sha256_hex(text.as_bytes()));
    if text.trim().is_empty() {
        findings.push(workflow_finding(
            "STAGE_EMPTY_EVIDENCE", source.clone(),
            format!("Attested {label} evidence file is empty."),
            "Provide non-empty evidence documenting the completed gate.",
        ));
        return Ok(AttestedRecord { value: false, source, sha256 });
    }
    if validate_review_doc {
        if let Ok(val) = serde_json::from_str::<Value>(&text) {
            let is_review_state = val.as_object().is_some_and(|m| {
                m.contains_key("canonical_review_items") || m.contains_key("canonicalReviewItems")
            });
            if is_review_state {
                let doc: ReviewStateDocument = serde_json::from_value(val)
                    .map_err(|e| format!("Invalid review-state schema in {}: {e}", path.display()))?;
                if let Err(err) = verify_review_closure(&doc) {
                    findings.push(workflow_finding(
                        "STAGE_REVIEW_CLOSURE_FAILED", source.clone(), err,
                        "Close all canonical review items before claiming the reviewed stage.",
                    ));
                    return Ok(AttestedRecord { value: false, source, sha256 });
                }
            }
        }
    }
    Ok(AttestedRecord { value: true, source, sha256 })
}

fn git_cmd(root: &Path, args: &[&str]) -> Result<Output, String> {
    Command::new("git")
        .current_dir(root)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .args(args)
        .output()
        .map_err(|e| format!("Failed running git {}: {e}", args[0]))
}

fn observe_signing_required(root: &Path, pack: &SawyerContextPack) -> Result<bool, String> {
    let out = git_cmd(root, &["config", "--type=bool", "--get", "commit.gpgsign"])?;
    let policy = match (out.status.code(), out.stdout.as_slice()) {
        (Some(0), b"true\n") => true,
        (Some(0), b"false\n") | (Some(1), b"") => false,
        _ => return Err("Invalid commit.gpgsign configuration".into()),
    };
    Ok(policy || pack.require_signed.unwrap_or(false))
}

fn verify_local_committed_pack(
    root: &Path,
    pack: &SawyerContextPack,
    whitelist: Option<&str>,
    gpg_required: bool,
) -> Result<bool, String> {
    verify_sawyer(root, pack, SawyerPhase::Preflight, whitelist)?;
    let approved: BTreeSet<&str> = pack.approved_files.iter().map(String::as_str).collect();
    let status = git_cmd(root, &["status", "--porcelain=v1", "-z", "--no-renames", "-uall"])?;
    if !status.status.success() {
        return Err("Failed reading Git status".into());
    }
    for rec in String::from_utf8(status.stdout).map_err(|e| e.to_string())?.split_terminator('\0') {
        let p = rec.get(3..).ok_or("Invalid Git status")?;
        if approved.contains(p) {
            return Err(format!("Approved path still has uncommitted changes: {p}"));
        }
    }
    let staged = git_cmd(root, &["diff", "--cached", "--name-only", "-z", "--"])?;
    if !staged.status.success() || !staged.stdout.is_empty() {
        return Err("Index still contains uncommitted staged changes".into());
    }
    let head_out = git_cmd(root, &["rev-parse", "--verify", "HEAD"])?;
    if !head_out.status.success() {
        return Err("Cannot resolve HEAD commit".into());
    }
    let head = String::from_utf8(head_out.stdout).map_err(|e| e.to_string())?.trim_end().to_string();
    if pack.expected_commit_sha.as_deref() != Some(head.as_str()) {
        return Err("Expected commit SHA differs from HEAD".into());
    }
    let diff = git_cmd(
        root,
        &["diff-tree", "--root", "--no-commit-id", "--name-only", "--no-renames", "-r", "-z", &head, "--"],
    )?;
    if !diff.status.success() {
        return Err("Failed inspecting committed files in HEAD".into());
    }
    let diff_txt = String::from_utf8(diff.stdout).map_err(|e| e.to_string())?;
    let committed: BTreeSet<&str> = diff_txt.split_terminator('\0').collect();
    if committed != approved {
        return Err("Committed paths differ from approved files".into());
    }
    if gpg_required {
        let sig = git_cmd(root, &["verify-commit", &head])?;
        if !sig.status.success() {
            return Err("Commit signature verification failed for HEAD".into());
        }
        return Ok(true);
    }
    Ok(false)
}

fn load_observed_pins(args: &StageVerifyArgs) -> Result<BTreeMap<String, String>, String> {
    let mut pins = BTreeMap::new();
    if let Some(ref manifest) = args.toolchain_manifest {
        let raw = fs::read_to_string(manifest)
            .map_err(|e| format!("Failed reading toolchain manifest {}: {e}", manifest.display()))?;
        let parsed: BTreeMap<String, String> = serde_json::from_str(&raw)
            .map_err(|e| format!("Invalid toolchain manifest JSON in {}: {e}", manifest.display()))?;
        pins.extend(parsed);
    }
    for item in &args.toolchain_pins {
        let Some((k, v)) = item.split_once('=') else {
            return Err(format!("Invalid --toolchain-pin '{item}' (expected `relative/path=content`)"));
        };
        if k.trim().is_empty() {
            return Err("Empty path in --toolchain-pin".into());
        }
        pins.insert(k.trim().to_string(), v.to_string());
    }
    Ok(pins)
}

fn stage_rank(stage: LifecycleStage) -> u8 {
    match stage {
        LifecycleStage::Implemented => 0,
        LifecycleStage::Verified => 1,
        LifecycleStage::Reviewed => 2,
        LifecycleStage::Committed => 3,
        LifecycleStage::Pushed => 4,
        LifecycleStage::CiPassed => 5,
        LifecycleStage::Released => 6,
    }
}

fn observe_tests(
    args: &StageVerifyArgs,
    spec: &ProjectSpec,
    stage: LifecycleStage,
    checked_files: &mut Vec<String>,
    findings: &mut Vec<ProjectFinding>,
) -> Result<(usize, usize, Option<String>), String> {
    let Some(ref transcript_path) = args.test_transcript else {
        if stage_rank(stage) >= stage_rank(LifecycleStage::Verified) {
            findings.push(workflow_finding(
                "STAGE_TEST_TRANSCRIPT_MISSING", None,
                "Verified stage requires an observed test transcript (--test-transcript).".into(),
                "Pass --test-transcript <file> matching a configured workflow.test_runners parser.",
            ));
        }
        return Ok((0, 0, None));
    };
    checked_files.push(transcript_path.to_string_lossy().into_owned());
    let text = fs::read_to_string(transcript_path)
        .map_err(|e| format!("Failed reading test transcript {}: {e}", transcript_path.display()))?;
    let runner = match &args.test_runner {
        Some(name) => spec.workflow.test_runners.iter().find(|r| &r.name == name),
        None if spec.workflow.test_runners.len() == 1 => Some(&spec.workflow.test_runners[0]),
        None => None,
    };
    let Some(r) = runner else {
        let msg = if spec.workflow.test_runners.is_empty() {
            "No workflow.test_runners configured in .birkin/config.yaml.".into()
        } else if let Some(ref name) = args.test_runner {
            format!("Configured workflow.test_runners does not contain '{name}'.")
        } else {
            "Multiple workflow.test_runners configured; pass --test-runner <name>.".into()
        };
        findings.push(workflow_finding(
            "STAGE_TEST_RUNNER_UNAVAILABLE", None, msg,
            "Configure workflow.test_runners in .birkin/config.yaml and select a runner.",
        ));
        return Ok((0, 0, None));
    };
    match parse_test_counts(&r.parser, &text, args.test_exit_code) {
        Ok(counts) => Ok((counts.discovered, counts.executed, Some(r.parser.clone()))),
        Err(err) => {
            findings.push(workflow_finding(
                "STAGE_TEST_TRANSCRIPT_INVALID", Some(transcript_path.to_string_lossy().into_owned()), err,
                "Provide a complete passing transcript with nonzero executed tests.",
            ));
            Ok((0, 0, Some(r.parser.clone())))
        }
    }
}

#[derive(Default)]
struct ObservedSawyer {
    staged_exact: bool,
    excluded_clean: bool,
    gpg_required: bool,
    gpg_valid: bool,
    remote_head_matches: bool,
}

fn observe_sawyer(
    repo_root: &Path,
    spec: &ProjectSpec,
    stage: LifecycleStage,
    pack_path: Option<&Path>,
    checked_files: &mut Vec<String>,
    findings: &mut Vec<ProjectFinding>,
) -> Result<ObservedSawyer, String> {
    let Some(pack_path) = pack_path else {
        if stage_rank(stage) >= stage_rank(LifecycleStage::Committed) {
            findings.push(workflow_finding(
                "STAGE_SAWYER_PACK_MISSING", None,
                "Committed and later stages require Sawyer observation via --sawyer-pack.".into(),
                "Provide --sawyer-pack <pack.json> to observe Git staging, commit, and remote state.",
            ));
        }
        return Ok(ObservedSawyer::default());
    };
    let pack_str = pack_path.to_string_lossy().into_owned();
    checked_files.push(pack_str.clone());
    let raw = fs::read_to_string(pack_path)
        .map_err(|e| format!("Failed reading Sawyer pack {}: {e}", pack_path.display()))?;
    let pack: SawyerContextPack = serde_json::from_str(&raw)
        .map_err(|e| format!("Invalid Sawyer pack JSON in {}: {e}", pack_path.display()))?;
    let whitelist = spec.workflow.exclude_whitelist_path.as_deref();
    let mut obs = ObservedSawyer::default();
    match observe_signing_required(repo_root, &pack) {
        Ok(req) => obs.gpg_required = req,
        Err(err) => {
            obs.gpg_required = true;
            findings.push(workflow_finding("STAGE_SAWYER_CONFIG_ERROR", Some(pack_str.clone()), err, "Fix commit.gpgsign Git configuration before stage verification."));
        }
    }
    if stage_rank(stage) >= stage_rank(LifecycleStage::Pushed) {
        match verify_sawyer(repo_root, &pack, SawyerPhase::PostPush, whitelist) {
            Ok(()) => {
                obs.staged_exact = true;
                obs.excluded_clean = true;
                obs.gpg_valid = obs.gpg_required;
                obs.remote_head_matches = true;
            }
            Err(err) => findings.push(workflow_finding("STAGE_SAWYER_POST_PUSH_FAILED", Some(pack_str), err, "Ensure committed files, commit signature, and remote ref match the Sawyer pack.")),
        }
    } else if stage == LifecycleStage::Committed {
        if pack.expected_commit_sha.is_some() {
            match verify_local_committed_pack(repo_root, &pack, whitelist, obs.gpg_required) {
                Ok(sig_ok) => {
                    obs.staged_exact = true;
                    obs.excluded_clean = true;
                    obs.gpg_valid = sig_ok;
                }
                Err(err) => findings.push(workflow_finding(
                    "STAGE_SAWYER_COMMIT_FAILED",
                    Some(pack_str),
                    err,
                    "Ensure HEAD commit, committed files, exclusions, and signature match the pack.",
                )),
            }
        } else {
            findings.push(workflow_finding(
                "STAGE_SAWYER_COMMIT_SHA_MISSING",
                Some(pack_str),
                "Committed stage requires an actual commit with expected_commit_sha matching HEAD."
                    .into(),
                "Commit the staged changes, set expected_commit_sha to HEAD, and re-run stage verify.",
            ));
        }
    }
    Ok(obs)
}

pub fn handle_sawyer_verify(pack_path: &Path, phase_raw: &str, common: &WorkflowRepoArgs) -> i32 {
    let t0 = Instant::now();
    let (phase, phase_label) = match phase_raw.trim() {
        "preflight" => (SawyerPhase::Preflight, "preflight"),
        "staged" => (SawyerPhase::Staged, "staged"),
        "post-push" | "post_push" => (SawyerPhase::PostPush, "post-push"),
        other => return emit_tool_error("sawyer-verify", &format!("Invalid --phase '{other}' (expected preflight, staged, or post-push)"), common.as_json),
    };
    let (repo_root, spec, _) = match load_workflow_repo(&common.repo, common.spec.as_deref()) {
        Ok(v) => v,
        Err(e) => return emit_tool_error("sawyer-verify", &e, common.as_json),
    };
    let raw = match fs::read_to_string(pack_path) {
        Ok(s) => s,
        Err(e) => return emit_tool_error("sawyer-verify", &format!("Failed reading Sawyer pack {}: {e}", pack_path.display()), common.as_json),
    };
    let pack: SawyerContextPack = match serde_json::from_str(&raw) {
        Ok(p) => p,
        Err(e) => return emit_tool_error("sawyer-verify", &format!("Invalid Sawyer pack JSON in {}: {e}", pack_path.display()), common.as_json),
    };
    let pack_str = pack_path.to_string_lossy().into_owned();
    let res = verify_sawyer(&repo_root, &pack, phase, spec.workflow.exclude_whitelist_path.as_deref());
    let sawyer_ok = res.is_ok();
    let error = res.err();
    let mut findings = Vec::new();
    if let Some(ref msg) = error {
        findings.push(workflow_finding("SAWYER_CONTRACT_VIOLATION", Some(pack_str.clone()), msg.clone(), "Fix repository branch, staging, exclusions, signature, or remote push state."));
    }
    let stage = match phase {
        SawyerPhase::Preflight => LifecycleStage::Implemented,
        SawyerPhase::Staged => LifecycleStage::Committed,
        SawyerPhase::PostPush => LifecycleStage::Pushed,
    };
    let ev = StageEvidenceInput {
        discovered_tests: 1, executed_tests: 1, toolchain_matched: true, receipt_chain_ok: true,
        tree_bound_ok: sawyer_ok, review_passed: true, sawyer_staged_exact: sawyer_ok,
        sawyer_excluded_clean: sawyer_ok, gpg_sign_required: pack.require_signed.unwrap_or(false),
        gpg_sig_valid: sawyer_ok, remote_head_matches: sawyer_ok && phase == SawyerPhase::PostPush,
        ci_passed: false, release_authorized: false,
    };
    let (stage_kreq, kernel_verdict) = match verify_stage_admission(stage, &ev) {
        Ok(v) => v,
        Err(e) => return emit_tool_error("sawyer-verify", &e, common.as_json),
    };
    let cert = match maybe_certify(common.certify, common.emit_proof.as_deref(), CertObligation::Stage(stage_kreq)) {
        Ok(c) => c,
        Err(e) => return emit_tool_error("sawyer-verify", &e, common.as_json),
    };
    let admitted = sawyer_ok && kernel_verdict.admitted && cert.as_ref().is_none_or(|c| c.certified);
    let exit_code = if admitted { EXIT_PASS } else { EXIT_STATIC };
    let dur_ms = t0.elapsed().as_millis();
    let mut meta = Map::new();
    meta.insert("pack".into(), json!(pack_str));
    meta.insert("phase".into(), json!(phase_label));
    meta.insert("target_branch".into(), json!(pack.target_branch));
    meta.insert("admitted".into(), json!(admitted));
    let mut report = json!({
        "command": "sawyer-verify", "project": spec.project.name, "repo": repo_root.to_string_lossy(),
        "pack": pack_str, "phase": phase_label, "target_branch": pack.target_branch,
        "status": if admitted { "PASS" } else { "FAIL" }, "exit_code": exit_code,
        "duration_ms": dur_ms as u64, "admitted": admitted, "error": error, "findings": findings,
        "contract_enabled": spec.workflow.contract_enabled("sawyer"),
    });
    attach_attestation(&mut meta, &mut report, cert.as_ref());
    let (receipt_sha, receipt_error) = record_workflow_receipt(
        &repo_root, &spec, "sawyer-verify", &common.surface, common.no_receipt,
        exit_code, dur_ms, &findings, std::slice::from_ref(&pack_str), meta,
    );
    report["receipt_sha256"] = json!(receipt_sha);
    report["receipt_error"] = json!(receipt_error);
    let mut lines = vec![format!(
        "birkin sawyer verify ({}): phase={phase_label} branch={} status={} ({dur_ms}ms)",
        spec.project.name, pack.target_branch, if admitted { "PASS" } else { "FAIL" }
    )];
    lines.extend(format_findings(&findings));
    emit_output(&report, common.as_json, &lines.join("\n"));
    exit_code
}

pub fn handle_stage_verify(args: StageVerifyArgs) -> i32 {
    let t0 = Instant::now();
    let stage = match LifecycleStage::parse_str(&args.stage) {
        Ok(s) => s,
        Err(e) => return emit_tool_error("stage-verify", &e, args.common.as_json),
    };
    let (repo_root, spec, _) = match load_workflow_repo(&args.common.repo, args.common.spec.as_deref()) {
        Ok(v) => v,
        Err(e) => return emit_tool_error("stage-verify", &e, args.common.as_json),
    };
    let observed_pins = match load_observed_pins(&args) {
        Ok(p) => p,
        Err(e) => return emit_tool_error("stage-verify", &e, args.common.as_json),
    };
    let mut required_cmds: Vec<String> = match &args.require_commands {
        Some(csv) => {
            let list: Vec<String> = csv.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            if list.is_empty() {
                return emit_tool_error("stage-verify", "--require-commands must list at least one command", args.common.as_json);
            }
            list
        }
        None => vec!["check".into()],
    };
    if spec.workflow.require_plan_receipt && !required_cmds.iter().any(|c| c == "plan-verify") {
        required_cmds.push("plan-verify".into());
    }
    let mut findings = Vec::new();
    let mut checked_files = Vec::new();
    let ledger_entries = read_receipts(&resolve_ledger_path(&repo_root, &spec));
    let receipt_res = verify_receipts_for_current_state(&repo_root, &spec, &required_cmds, args.require_clean);
    let chain_ok = receipt_res["chain_ok"].as_bool().unwrap_or(false);
    let has_tree = receipt_res["tree_digest"].is_string();
    let receipts_pass = receipt_res["status"].as_str() == Some("PASS");
    let strict_receipt_gate = stage_rank(stage) >= stage_rank(LifecycleStage::Verified)
        || args.require_commands.is_some()
        || args.require_clean
        || spec.workflow.require_plan_receipt;
    let receipt_chain_ok = chain_ok && !ledger_entries.is_empty() && receipts_pass;
    let tree_bound_ok = if strict_receipt_gate { has_tree && receipts_pass } else { has_tree };
    if !tree_bound_ok {
        let msg = receipt_res["reason"].as_str().map(str::to_owned).unwrap_or_else(|| {
            format!("Working tree is not bound to passing receipts for [{}].", required_cmds.join(", "))
        });
        findings.push(workflow_finding("STAGE_TREE_BINDING_FAILED", None, msg, "Run the required Birkin checks on the current Git tree before verifying this stage."));
    } else if strict_receipt_gate && !receipt_chain_ok {
        findings.push(workflow_finding("STAGE_RECEIPT_CHAIN_INVALID", None, "Receipt ledger chain is empty, broken, or missing required passing entries.".into(), "Repair or regenerate hash-chained receipts for the current tree."));
    }
    let toolchain_matched = if spec.workflow.toolchain_pin_files.is_empty() {
        true
    } else {
        match verify_toolchain_pins(&repo_root, &spec.workflow.toolchain_pin_files, &observed_pins) {
            Ok(()) => true,
            Err(err) => {
                if stage_rank(stage) >= stage_rank(LifecycleStage::Verified) {
                    findings.push(workflow_finding("STAGE_TOOLCHAIN_PIN_MISMATCH", None, err, "Provide matching --toolchain-manifest or --toolchain-pin observations for workflow.toolchain_pin_files."));
                }
                false
            }
        }
    };
    let (discovered_tests, executed_tests, test_parser_used) =
        match observe_tests(&args, &spec, stage, &mut checked_files, &mut findings) {
            Ok(v) => v,
            Err(e) => return emit_tool_error("stage-verify", &e, args.common.as_json),
        };
    let sawyer = match observe_sawyer(&repo_root, &spec, stage, args.sawyer_pack.as_deref(), &mut checked_files, &mut findings) {
        Ok(v) => v,
        Err(e) => return emit_tool_error("stage-verify", &e, args.common.as_json),
    };
    let review_att = match read_attested_evidence(args.review_evidence.as_deref(), "review", true, &mut findings) {
        Ok(v) => v,
        Err(e) => return emit_tool_error("stage-verify", &e, args.common.as_json),
    };
    let ci_att = match read_attested_evidence(args.ci_evidence.as_deref(), "ci", false, &mut findings) {
        Ok(v) => v,
        Err(e) => return emit_tool_error("stage-verify", &e, args.common.as_json),
    };
    let release_att = match read_attested_evidence(args.release_evidence.as_deref(), "release", false, &mut findings) {
        Ok(v) => v,
        Err(e) => return emit_tool_error("stage-verify", &e, args.common.as_json),
    };
    if stage_rank(stage) >= stage_rank(LifecycleStage::Reviewed) && args.review_evidence.is_none() {
        findings.push(workflow_finding("STAGE_REVIEW_EVIDENCE_MISSING", None, "Stage requires attested review evidence (--review-evidence).".into(), "Supply --review-evidence <file> documenting independent review passage."));
    }
    if stage_rank(stage) >= stage_rank(LifecycleStage::CiPassed) && args.ci_evidence.is_none() {
        findings.push(workflow_finding("STAGE_CI_EVIDENCE_MISSING", None, "Stage requires attested CI evidence (--ci-evidence).".into(), "Supply --ci-evidence <file> documenting CI completion."));
    }
    if stage == LifecycleStage::Released && args.release_evidence.is_none() {
        findings.push(workflow_finding("STAGE_RELEASE_EVIDENCE_MISSING", None, "Released stage requires attested release authorization (--release-evidence).".into(), "Supply --release-evidence <file> documenting explicit release authorization."));
    }

    let ev = StageEvidenceInput {
        discovered_tests, executed_tests, toolchain_matched, receipt_chain_ok, tree_bound_ok,
        review_passed: review_att.value, sawyer_staged_exact: sawyer.staged_exact,
        sawyer_excluded_clean: sawyer.excluded_clean, gpg_sign_required: sawyer.gpg_required,
        gpg_sig_valid: sawyer.gpg_valid, remote_head_matches: sawyer.remote_head_matches,
        ci_passed: ci_att.value, release_authorized: release_att.value,
    };
    let (stage_kreq, kernel_verdict) = match verify_stage_admission(stage, &ev) {
        Ok(v) => v,
        Err(e) => return emit_tool_error("stage-verify", &e, args.common.as_json),
    };
    let cert = match maybe_certify(args.common.certify, args.common.emit_proof.as_deref(), CertObligation::Stage(stage_kreq)) {
        Ok(c) => c,
        Err(e) => return emit_tool_error("stage-verify", &e, args.common.as_json),
    };
    let admitted = kernel_verdict.admitted && cert.as_ref().is_none_or(|c| c.certified);
    let exit_code = if admitted { EXIT_PASS } else { EXIT_STATIC };
    let dur_ms = t0.elapsed().as_millis();
    let evidence_json = json!({
        "observed": {
            "provenance": "observed", "tree_bound_ok": ev.tree_bound_ok,
            "receipt_chain_ok": ev.receipt_chain_ok, "required_commands": required_cmds,
            "toolchain_matched": ev.toolchain_matched, "toolchain_pin_files": spec.workflow.toolchain_pin_files,
            "discovered_tests": ev.discovered_tests, "executed_tests": ev.executed_tests,
            "test_parser": test_parser_used, "sawyer_staged_exact": ev.sawyer_staged_exact,
            "sawyer_excluded_clean": ev.sawyer_excluded_clean, "gpg_sign_required": ev.gpg_sign_required,
            "gpg_sig_valid": ev.gpg_sig_valid, "remote_head_matches": ev.remote_head_matches,
        },
        "attested": {
            "review_passed": review_att.to_json(),
            "ci_passed": ci_att.to_json(),
            "release_authorized": release_att.to_json(),
        },
    });
    let mut meta = Map::new();
    meta.insert("stage".into(), json!(stage.as_str()));
    meta.insert("admitted".into(), json!(admitted));
    meta.insert("evidence".into(), evidence_json.clone());
    let mut report = json!({
        "command": "stage-verify", "project": spec.project.name, "repo": repo_root.to_string_lossy(),
        "stage": stage.as_str(), "status": if admitted { "PASS" } else { "FAIL" },
        "exit_code": exit_code, "duration_ms": dur_ms as u64, "admitted": admitted,
        "contract_enabled": spec.workflow.contract_enabled("stage"), "evidence": evidence_json,
        "findings": findings,
    });
    attach_attestation(&mut meta, &mut report, cert.as_ref());
    let (receipt_sha, receipt_error) = record_workflow_receipt(
        &repo_root, &spec, "stage-verify", &args.common.surface, args.common.no_receipt,
        exit_code, dur_ms, &findings, &checked_files, meta,
    );
    report["receipt_sha256"] = json!(receipt_sha);
    report["receipt_error"] = json!(receipt_error);
    let mut lines = vec![format!(
        "birkin stage verify ({}): stage={} status={} tests={}/{} findings={} ({dur_ms}ms)",
        spec.project.name, stage.as_str(), if admitted { "PASS" } else { "FAIL" },
        ev.executed_tests, ev.discovered_tests, findings.len()
    )];
    lines.extend(format_findings(&findings));
    emit_output(&report, args.common.as_json, &lines.join("\n"));
    exit_code
}
