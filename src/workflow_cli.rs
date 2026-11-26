//! Workflow-contract CLI subcommands: plan, unit, stage, sawyer, and review-closure.

use crate::authority_contract::verify_dispatch;
use crate::config_utils::load_policy;
use crate::constants::{EXIT_PASS, EXIT_STATIC, EXIT_TOOL_ERROR};
use crate::ledger::append_receipt;
use crate::plan_contract::{can_dispatch_mutating, load_plan_document, validate_plan_document};
use crate::project_init::detect_project_spec;
use crate::project_models::{
    find_repo_root, find_spec_file, load_project_spec, ProjectFinding, ProjectSpec,
};
use crate::review_closure::verify_review_closure;
use crate::scope_contract::{collect_git_changed_paths, verify_task_scope, PathAuthority};
use crate::workflow_models::{
    ActiveUnitRecord, AgentRole, ApprovalTier, DispatchManifest, ReviewStateDocument,
};
use crate::workflow_stage_cli::{handle_sawyer_verify, handle_stage_verify, StageVerifyArgs};
use clap::{Args, Subcommand};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Args, Debug, Clone)]
pub struct WorkflowRepoArgs {
    /// Repository directory (defaults to current working directory)
    #[arg(long, default_value = ".")]
    pub repo: PathBuf,
    /// Explicit .birkin/config.yaml path
    #[arg(long)]
    pub spec: Option<PathBuf>,
    /// Execution surface recorded in receipts
    #[arg(long, default_value = "cli")]
    pub surface: String,
    /// Emit machine-readable JSON output
    #[arg(long = "json")]
    pub as_json: bool,
    /// Skip appending a receipt to the ledger
    #[arg(long)]
    pub no_receipt: bool,
}

#[derive(Subcommand, Debug)]
pub enum WorkflowCommand {
    /// Verify execution plans against the workflow plan contract
    Plan {
        #[command(subcommand)]
        action: PlanAction,
    },
    /// Admit a delegated unit or verify its file-scope containment
    Unit {
        #[command(subcommand)]
        action: UnitAction,
    },
    /// Verify lifecycle stage admission from observed and attested evidence
    Stage {
        #[command(subcommand)]
        action: StageAction,
    },
    /// Verify Git staging, commit, signature, and remote head via Sawyer context pack
    Sawyer {
        #[command(subcommand)]
        action: SawyerAction,
    },
    /// Verify canonical review-item closure before resolving threads or requesting re-review
    #[command(name = "review-closure")]
    ReviewClosure {
        #[command(subcommand)]
        action: ReviewClosureAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum PlanAction {
    /// Validate a plan.json document
    Verify {
        /// Path to plan.json
        plan: PathBuf,
        #[command(flatten)]
        common: WorkflowRepoArgs,
    },
}

#[derive(Args, Debug, Clone)]
pub struct UnitAdmitArgs {
    #[arg(long)]
    pub plan: PathBuf,
    #[arg(long)]
    pub task: String,
    #[arg(long)]
    pub role: String,
    #[arg(long)]
    pub tier: String,
    #[arg(long)]
    pub explicit_f: bool,
    #[arg(long)]
    pub model: Option<String>,
    #[arg(long)]
    pub runtime: Option<String>,
    #[arg(long)]
    pub implementer_model: Option<String>,
    #[arg(long)]
    pub implementer_runtime: Option<String>,
    #[arg(long = "forbidden-model")]
    pub forbidden_models: Vec<String>,
    #[arg(long)]
    pub policy: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    pub retries: u32,
    #[arg(long)]
    pub refusal: bool,
    #[arg(long)]
    pub prev_tier: Option<String>,
    #[command(flatten)]
    pub common: WorkflowRepoArgs,
}

#[derive(Args, Debug, Clone)]
pub struct UnitVerifyScopeArgs {
    #[arg(long)]
    pub plan: PathBuf,
    #[arg(long)]
    pub task: String,
    #[arg(long)]
    pub repo: Option<PathBuf>,
    #[arg(long)]
    pub spec: Option<PathBuf>,
    #[arg(long)]
    pub staged: bool,
    #[arg(long)]
    pub active_units: Option<PathBuf>,
    #[arg(long, default_value = "source")]
    pub authority: String,
    #[arg(long = "path")]
    pub paths: Vec<String>,
    #[arg(long, default_value = "cli")]
    pub surface: String,
    #[arg(long = "json")]
    pub as_json: bool,
    #[arg(long)]
    pub no_receipt: bool,
}

#[derive(Subcommand, Debug)]
pub enum UnitAction {
    /// Check both plan dispatchability and role/tier authority before delegating a unit
    Admit(Box<UnitAdmitArgs>),
    /// Verify changed or staged files stay inside task allowed_paths and disjoint from active units
    #[command(name = "verify-scope")]
    VerifyScope(Box<UnitVerifyScopeArgs>),
}

#[derive(Subcommand, Debug)]
pub enum StageAction {
    /// Verify admission for a lifecycle stage
    Verify(Box<StageVerifyArgs>),
}

#[derive(Subcommand, Debug)]
pub enum SawyerAction {
    /// Verify Sawyer Git context pack for preflight, staged, or post-push phase
    Verify {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long, default_value = "preflight")]
        phase: String,
        #[command(flatten)]
        common: WorkflowRepoArgs,
    },
}

#[derive(Subcommand, Debug)]
pub enum ReviewClosureAction {
    /// Validate canonical review-item closure state JSON
    Verify {
        /// Path to review-state.json
        state: PathBuf,
        #[command(flatten)]
        common: WorkflowRepoArgs,
    },
}

pub(crate) fn load_workflow_repo(
    path: &Path,
    explicit_spec: Option<&Path>,
) -> Result<(PathBuf, ProjectSpec, Option<PathBuf>), String> {
    if !path.exists() {
        return Err(format!("Repository path not found: {}", path.display()));
    }
    let repo_root = find_repo_root(path);
    if explicit_spec.is_some() || find_spec_file(&repo_root).is_some() {
        let (spec, spec_path) = load_project_spec(&repo_root, explicit_spec)?;
        return Ok((repo_root, spec, spec_path));
    }
    Ok((repo_root.clone(), detect_project_spec(&repo_root), None))
}

pub(crate) fn emit_output(data: &Value, as_json: bool, human: &str) {
    if as_json {
        println!("{}", serde_json::to_string_pretty(data).unwrap_or_else(|_| "{}".into()));
    } else {
        println!("{human}");
    }
}

pub(crate) fn emit_tool_error(command: &str, err: &str, as_json: bool) -> i32 {
    if as_json {
        let body = json!({"command": command, "status": "ERROR", "exit_code": EXIT_TOOL_ERROR, "error": err});
        println!("{}", serde_json::to_string_pretty(&body).unwrap_or_else(|_| "{}".into()));
    } else {
        eprintln!("ERROR: {err}");
    }
    EXIT_TOOL_ERROR
}

pub(crate) fn workflow_finding(
    rule: &str,
    file: Option<String>,
    message: String,
    remediation: &str,
) -> ProjectFinding {
    ProjectFinding {
        rule: rule.into(),
        category: "workflow".into(),
        severity: "error".into(),
        file,
        line: None,
        message,
        remediation: remediation.into(),
        details: BTreeMap::new(),
    }
}

pub(crate) fn format_findings(findings: &[ProjectFinding]) -> Vec<String> {
    let mut lines = Vec::new();
    for f in findings {
        let loc = f.file.as_deref().unwrap_or("<workflow>");
        lines.push(format!("  - [{}] {} ({loc}): {}", f.severity.to_uppercase(), f.rule, f.message));
        lines.push(format!("    remediation: {}", f.remediation));
    }
    lines
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn record_workflow_receipt(
    repo_root: &Path,
    spec: &ProjectSpec,
    command: &str,
    surface: &str,
    no_receipt: bool,
    exit_code: i32,
    dur_ms: u128,
    findings: &[ProjectFinding],
    files: &[String],
    meta: Map<String, Value>,
) -> (Option<String>, Option<String>) {
    if !spec.telemetry.enabled || no_receipt {
        return (None, None);
    }
    let fvals: Vec<Value> = findings.iter().filter_map(|f| serde_json::to_value(f).ok()).collect();
    let outcome = if exit_code == EXIT_PASS { "PASS" } else { "FAIL" };
    match append_receipt(repo_root, spec, command, surface, outcome, exit_code, dur_ms, &fvals, files, meta) {
        Ok(entry) => (entry.get("receipt_sha256").and_then(Value::as_str).map(str::to_owned), None),
        Err(err) => {
            eprintln!("[birkin] warning: failed recording receipt ({command}): {err}");
            (None, Some(err))
        }
    }
}

pub fn dispatch_workflow(cmd: WorkflowCommand) -> i32 {
    match cmd {
        WorkflowCommand::Plan { action: PlanAction::Verify { plan, common } } => {
            handle_plan_verify(&plan, &common)
        }
        WorkflowCommand::Unit { action: UnitAction::Admit(args) } => handle_unit_admit(*args),
        WorkflowCommand::Unit { action: UnitAction::VerifyScope(args) } => {
            handle_unit_verify_scope(*args)
        }
        WorkflowCommand::Stage { action: StageAction::Verify(args) } => handle_stage_verify(*args),
        WorkflowCommand::Sawyer { action: SawyerAction::Verify { pack, phase, common } } => {
            handle_sawyer_verify(&pack, &phase, &common)
        }
        WorkflowCommand::ReviewClosure { action: ReviewClosureAction::Verify { state, common } } => {
            handle_review_closure_verify(&state, &common)
        }
    }
}

fn handle_plan_verify(plan: &Path, common: &WorkflowRepoArgs) -> i32 {
    let t0 = Instant::now();
    let (repo_root, spec, _) = match load_workflow_repo(&common.repo, common.spec.as_deref()) {
        Ok(v) => v,
        Err(e) => return emit_tool_error("plan-verify", &e, common.as_json),
    };
    let doc = match load_plan_document(plan) {
        Ok(d) => d,
        Err(e) => return emit_tool_error("plan-verify", &e, common.as_json),
    };
    let outcome = validate_plan_document(&doc);
    let exit_code = if outcome.valid { EXIT_PASS } else { EXIT_STATIC };
    let dur_ms = t0.elapsed().as_millis();
    let plan_str = plan.to_string_lossy().into_owned();
    let mut meta = Map::new();
    meta.insert("plan".into(), json!(plan_str));
    meta.insert("intent".into(), json!(doc.intent));
    meta.insert("ready_tasks".into(), json!(outcome.ready_tasks));
    meta.insert("blocked_tasks".into(), json!(outcome.blocked_tasks));
    meta.insert("done_tasks".into(), json!(outcome.done_tasks));
    let (receipt_sha, receipt_error) = record_workflow_receipt(
        &repo_root, &spec, "plan-verify", &common.surface, common.no_receipt,
        exit_code, dur_ms, &outcome.findings, std::slice::from_ref(&plan_str), meta,
    );
    let report = json!({
        "command": "plan-verify", "project": spec.project.name, "repo": repo_root.to_string_lossy(),
        "plan": plan_str, "intent": doc.intent, "status": if outcome.valid { "PASS" } else { "FAIL" },
        "exit_code": exit_code, "duration_ms": dur_ms as u64, "valid": outcome.valid,
        "errors": outcome.errors, "ready_tasks": outcome.ready_tasks,
        "blocked_tasks": outcome.blocked_tasks, "done_tasks": outcome.done_tasks,
        "findings": outcome.findings, "contract_enabled": spec.workflow.contract_enabled("plan"),
        "receipt_sha256": receipt_sha, "receipt_error": receipt_error,
    });
    let mut lines = vec![format!(
        "birkin plan verify ({}): status={} intent={} ready={} blocked={} done={} errors={} ({dur_ms}ms)",
        spec.project.name, if outcome.valid { "PASS" } else { "FAIL" }, doc.intent,
        outcome.ready_tasks.len(), outcome.blocked_tasks.len(), outcome.done_tasks.len(), outcome.errors.len()
    )];
    lines.extend(format_findings(&outcome.findings));
    emit_output(&report, common.as_json, &lines.join("\n"));
    exit_code
}

fn handle_unit_admit(args: UnitAdmitArgs) -> i32 {
    let t0 = Instant::now();
    let role = match AgentRole::parse_str(&args.role) {
        Ok(r) => r,
        Err(e) => return emit_tool_error("unit-admit", &e, args.common.as_json),
    };
    let tier = match ApprovalTier::parse_str(&args.tier) {
        Ok(t) => t,
        Err(e) => return emit_tool_error("unit-admit", &e, args.common.as_json),
    };
    let prev_tier = match args.prev_tier.as_deref() {
        Some(raw) => match ApprovalTier::parse_str(raw) {
            Ok(t) => t,
            Err(e) => return emit_tool_error("unit-admit", &e, args.common.as_json),
        },
        None => ApprovalTier::R,
    };
    let (repo_root, spec, _) = match load_workflow_repo(&args.common.repo, args.common.spec.as_deref()) {
        Ok(v) => v,
        Err(e) => return emit_tool_error("unit-admit", &e, args.common.as_json),
    };
    let doc = match load_plan_document(&args.plan) {
        Ok(d) => d,
        Err(e) => return emit_tool_error("unit-admit", &e, args.common.as_json),
    };
    let policy_denylist = match args.policy.as_deref() {
        Some(p) => match load_policy(p) {
            Ok(pol) => pol.fallback_providers.forbidden_patterns,
            Err(e) => return emit_tool_error("unit-admit", &e, args.common.as_json),
        },
        None => Vec::new(),
    };
    let manifest = DispatchManifest {
        role, requested_tier: tier, explicit_f_auth: args.explicit_f, is_refusal_retry: args.refusal,
        prev_tier, retries_after_first: args.retries, model: args.model, runtime: args.runtime,
        implementer_model: args.implementer_model, implementer_runtime: args.implementer_runtime,
        forbidden_model_patterns: args.forbidden_models,
    };
    let plan_res = can_dispatch_mutating(&doc, &args.task);
    let auth_res = verify_dispatch(&manifest, &policy_denylist);
    let (plan_admitted, authority_admitted) = (plan_res.is_ok(), auth_res.is_ok());
    let admitted = plan_admitted && authority_admitted;
    let plan_str = args.plan.to_string_lossy().into_owned();
    let mut errors = Vec::new();
    let mut findings = Vec::new();
    if let Err(reasons) = plan_res {
        for r in reasons {
            findings.push(workflow_finding("UNIT_PLAN_DISPATCH_DENIED", Some(plan_str.clone()), r.clone(), "Resolve plan blockers, prerequisites, or plan-only intent before dispatch."));
            errors.push(r);
        }
    }
    if let Err(reason) = auth_res {
        findings.push(workflow_finding("UNIT_AUTHORITY_DENIED", Some(plan_str.clone()), reason.clone(), "Adjust role, tier, retry count, model policy, or reviewer independence."));
        errors.push(reason);
    }
    let exit_code = if admitted { EXIT_PASS } else { EXIT_STATIC };
    let dur_ms = t0.elapsed().as_millis();
    let mut meta = Map::new();
    meta.insert("plan".into(), json!(plan_str));
    meta.insert("task".into(), json!(args.task));
    meta.insert("role".into(), json!(role.as_str()));
    meta.insert("tier".into(), json!(tier.as_str()));
    meta.insert("admitted".into(), json!(admitted));
    meta.insert("plan_admitted".into(), json!(plan_admitted));
    meta.insert("authority_admitted".into(), json!(authority_admitted));
    let (receipt_sha, receipt_error) = record_workflow_receipt(
        &repo_root, &spec, "unit-admit", &args.common.surface, args.common.no_receipt,
        exit_code, dur_ms, &findings, std::slice::from_ref(&plan_str), meta,
    );
    let report = json!({
        "command": "unit-admit", "project": spec.project.name, "repo": repo_root.to_string_lossy(),
        "plan": plan_str, "task": args.task, "role": role.as_str(), "tier": tier.as_str(),
        "status": if admitted { "PASS" } else { "FAIL" }, "exit_code": exit_code,
        "duration_ms": dur_ms as u64, "admitted": admitted, "plan_admitted": plan_admitted,
        "authority_admitted": authority_admitted, "errors": errors, "findings": findings,
        "contract_enabled": spec.workflow.contract_enabled("authority"),
        "receipt_sha256": receipt_sha, "receipt_error": receipt_error,
    });
    let mut lines = vec![format!(
        "birkin unit admit ({}): task={} role={} tier={} status={} errors={} ({dur_ms}ms)",
        spec.project.name, args.task, role.as_str(), tier.as_str(),
        if admitted { "PASS" } else { "FAIL" }, errors.len()
    )];
    lines.extend(format_findings(&findings));
    emit_output(&report, args.common.as_json, &lines.join("\n"));
    exit_code
}

fn handle_unit_verify_scope(args: UnitVerifyScopeArgs) -> i32 {
    let t0 = Instant::now();
    let (auth, auth_label) = match args.authority.trim() {
        "source" | "source_edit" => (PathAuthority::SourceEdit, "source"),
        "verification-output" | "verification_output" => (PathAuthority::VerificationOutput, "verification-output"),
        other => return emit_tool_error("unit-verify-scope", &format!("Invalid --authority '{other}' (expected source or verification-output)"), args.as_json),
    };
    let doc = match load_plan_document(&args.plan) {
        Ok(d) => d,
        Err(e) => return emit_tool_error("unit-verify-scope", &e, args.as_json),
    };
    let active_units: Vec<ActiveUnitRecord> = match args.active_units.as_deref() {
        Some(p) => {
            let raw = match fs::read_to_string(p) {
                Ok(s) => s,
                Err(e) => return emit_tool_error("unit-verify-scope", &format!("Failed reading active-units {}: {e}", p.display()), args.as_json),
            };
            match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(e) => return emit_tool_error("unit-verify-scope", &format!("Invalid active-units JSON in {}: {e}", p.display()), args.as_json),
            }
        }
        None => Vec::new(),
    };
    let task = doc.tasks.iter().find(|t| t.id == args.task);
    let fallback_repo = task.and_then(|t| t.checkout_root.as_ref()).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    let target_repo = args.repo.as_deref().unwrap_or(fallback_repo.as_path());
    let (repo_root, spec, _) = match load_workflow_repo(target_repo, args.spec.as_deref()) {
        Ok(v) => v,
        Err(e) => return emit_tool_error("unit-verify-scope", &e, args.as_json),
    };
    let Some(task) = task else {
        let dur_ms = t0.elapsed().as_millis();
        let findings = vec![workflow_finding("SCOPE_UNKNOWN_TASK", Some(args.plan.to_string_lossy().into_owned()), format!("Task '{}' not found in plan.", args.task), "Pass a valid task ID declared in plan.json.")];
        let mut meta = Map::new();
        meta.insert("task".into(), json!(args.task));
        meta.insert("admitted".into(), json!(false));
        let (receipt_sha, receipt_error) = record_workflow_receipt(
            &repo_root, &spec, "unit-verify-scope", &args.surface, args.no_receipt,
            EXIT_STATIC, dur_ms, &findings, &[], meta,
        );
        let report = json!({
            "command": "unit-verify-scope", "project": spec.project.name, "repo": repo_root.to_string_lossy(),
            "plan": args.plan.to_string_lossy(), "task": args.task, "authority": auth_label,
            "staged_only": args.staged, "status": "FAIL", "exit_code": EXIT_STATIC, "duration_ms": dur_ms as u64,
            "admitted": false, "checked_paths": [], "decisions": [], "overlapping_writes": [],
            "findings": findings, "contract_enabled": spec.workflow.contract_enabled("scope"),
            "receipt_sha256": receipt_sha, "receipt_error": receipt_error,
        });
        emit_output(&report, args.as_json, &format!("birkin unit verify-scope ({}): task={} status=FAIL (unknown task)", spec.project.name, args.task));
        return EXIT_STATIC;
    };
    let changed_paths = if !args.paths.is_empty() {
        args.paths.clone()
    } else {
        match collect_git_changed_paths(&repo_root, args.staged) {
            Ok(p) => p,
            Err(e) => return emit_tool_error("unit-verify-scope", &e, args.as_json),
        }
    };
    let mut outcome = verify_task_scope(&repo_root, task, &changed_paths, auth, &active_units);
    if let Some(ref declared_root) = task.checkout_root {
        let declared_canon = fs::canonicalize(declared_root).ok();
        let actual_canon = fs::canonicalize(&repo_root).ok();
        if declared_canon.is_none() || declared_canon != actual_canon {
            outcome.admitted = false;
            outcome.findings.push(workflow_finding(
                "SCOPE_CHECKOUT_ROOT_MISMATCH", Some(declared_root.clone()),
                format!("Task '{}' declares checkout_root '{declared_root}', which does not match '{}'.", args.task, repo_root.display()),
                "Run scope verification against the task's declared checkout_root.",
            ));
        }
    }
    let exit_code = if outcome.admitted { EXIT_PASS } else { EXIT_STATIC };
    let dur_ms = t0.elapsed().as_millis();
    let mut meta = Map::new();
    meta.insert("plan".into(), json!(args.plan.to_string_lossy()));
    meta.insert("task".into(), json!(args.task));
    meta.insert("authority".into(), json!(auth_label));
    meta.insert("staged_only".into(), json!(args.staged));
    meta.insert("admitted".into(), json!(outcome.admitted));
    let (receipt_sha, receipt_error) = record_workflow_receipt(
        &repo_root, &spec, "unit-verify-scope", &args.surface, args.no_receipt,
        exit_code, dur_ms, &outcome.findings, &changed_paths, meta,
    );
    let report = json!({
        "command": "unit-verify-scope", "project": spec.project.name, "repo": repo_root.to_string_lossy(),
        "plan": args.plan.to_string_lossy(), "task": args.task, "authority": auth_label,
        "staged_only": args.staged, "status": if outcome.admitted { "PASS" } else { "FAIL" },
        "exit_code": exit_code, "duration_ms": dur_ms as u64, "admitted": outcome.admitted,
        "checked_paths": changed_paths, "decisions": outcome.decisions,
        "overlapping_writes": outcome.overlapping_writes, "findings": outcome.findings,
        "contract_enabled": spec.workflow.contract_enabled("scope"),
        "receipt_sha256": receipt_sha, "receipt_error": receipt_error,
    });
    let mut lines = vec![format!(
        "birkin unit verify-scope ({}): task={} status={} checked={} findings={} ({dur_ms}ms)",
        spec.project.name, args.task, if outcome.admitted { "PASS" } else { "FAIL" },
        changed_paths.len(), outcome.findings.len()
    )];
    lines.extend(format_findings(&outcome.findings));
    emit_output(&report, args.as_json, &lines.join("\n"));
    exit_code
}

fn handle_review_closure_verify(state_path: &Path, common: &WorkflowRepoArgs) -> i32 {
    let t0 = Instant::now();
    let (repo_root, spec, _) = match load_workflow_repo(&common.repo, common.spec.as_deref()) {
        Ok(v) => v,
        Err(e) => return emit_tool_error("review-closure-verify", &e, common.as_json),
    };
    let raw = match fs::read_to_string(state_path) {
        Ok(s) => s,
        Err(e) => return emit_tool_error("review-closure-verify", &format!("Failed reading review state {}: {e}", state_path.display()), common.as_json),
    };
    let doc: ReviewStateDocument = match serde_json::from_str(&raw) {
        Ok(d) => d,
        Err(e) => return emit_tool_error("review-closure-verify", &format!("Invalid review state JSON in {}: {e}", state_path.display()), common.as_json),
    };
    let state_str = state_path.to_string_lossy().into_owned();
    let res = verify_review_closure(&doc);
    let closed = res.is_ok();
    let error = res.err();
    let mut findings = Vec::new();
    if let Some(ref msg) = error {
        findings.push(workflow_finding("REVIEW_CLOSURE_VIOLATION", Some(state_str.clone()), msg.clone(), "Classify, reply with URL where resolved, verify must_fix items, and clear clarifications."));
    }
    let exit_code = if closed { EXIT_PASS } else { EXIT_STATIC };
    let dur_ms = t0.elapsed().as_millis();
    let mut meta = Map::new();
    meta.insert("state_file".into(), json!(state_str));
    meta.insert("item_count".into(), json!(doc.canonical_review_items.len()));
    meta.insert("request_re_review".into(), json!(doc.request_re_review));
    meta.insert("closed".into(), json!(closed));
    let (receipt_sha, receipt_error) = record_workflow_receipt(
        &repo_root, &spec, "review-closure-verify", &common.surface, common.no_receipt,
        exit_code, dur_ms, &findings, std::slice::from_ref(&state_str), meta,
    );
    let report = json!({
        "command": "review-closure-verify", "project": spec.project.name, "repo": repo_root.to_string_lossy(),
        "state_file": state_str, "item_count": doc.canonical_review_items.len(),
        "request_re_review": doc.request_re_review, "status": if closed { "PASS" } else { "FAIL" },
        "exit_code": exit_code, "duration_ms": dur_ms as u64, "closed": closed, "error": error,
        "findings": findings, "contract_enabled": spec.workflow.contract_enabled("review_closure"),
        "receipt_sha256": receipt_sha, "receipt_error": receipt_error,
    });
    let mut lines = vec![format!(
        "birkin review-closure verify ({}): items={} re_review={} status={} ({dur_ms}ms)",
        spec.project.name, doc.canonical_review_items.len(), doc.request_re_review,
        if closed { "PASS" } else { "FAIL" }
    )];
    lines.extend(format_findings(&findings));
    emit_output(&report, common.as_json, &lines.join("\n"));
    exit_code
}
