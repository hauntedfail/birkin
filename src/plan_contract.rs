//! Execution-plan contract validator (`fly-face` / `xo`) backed by `BirkinSpec.PlanContract`.
//!
//! Rust validates JSON schema and lexical field syntax; all DAG acyclicity, topological
//! dependency ordering, transitive block propagation, `done` completion evidence, question
//! blocking, and `canDispatchMutating` verdicts are computed directly by the Lean 4 decision
//! kernel (`birkin-kernel`).

use crate::lean_kernel::{
    eval_plan, eval_plan_dispatch, KernelBlockingQuestion, KernelPlanDispatchRequest,
    KernelPlanRequest, KernelPlanTask,
};
use crate::project_models::ProjectFinding;
use crate::workflow_models::PlanDocument;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

const VALID_STATUSES: &[&str] = &["ready", "blocked", "in_progress", "done", "superseded"];

#[derive(Debug, Clone)]
pub struct PlanValidationOutcome {
    pub valid: bool,
    pub errors: Vec<String>,
    pub findings: Vec<ProjectFinding>,
    pub ready_tasks: Vec<String>,
    pub blocked_tasks: Vec<String>,
    pub done_tasks: Vec<String>,
    pub kernel_error: Option<String>,
}

pub fn is_valid_scoped_path(value: &str) -> bool {
    if value.trim().is_empty() || value.starts_with('/') || value.starts_with('~') {
        return false;
    }
    for ch in value.chars() {
        if ch.is_control() || matches!(ch, '\\' | ':' | '*' | '?' | '[' | ']' | '{' | '}') {
            return false;
        }
    }
    let canonical = value.strip_suffix('/').unwrap_or(value);
    !canonical.is_empty()
        && canonical
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn non_empty_strings(items: &[String], require_nonempty: bool) -> bool {
    (!require_nonempty || !items.is_empty()) && items.iter().all(|s| !s.trim().is_empty())
}

fn add_err(errors: &mut Vec<String>, findings: &mut Vec<ProjectFinding>, rule: &str, msg: String) {
    findings.push(ProjectFinding {
        rule: rule.to_string(),
        category: "workflow".into(),
        severity: "error".into(),
        file: None,
        line: None,
        message: msg.clone(),
        remediation: "Fix plan.json to satisfy the workflow plan contract before dispatch.".into(),
        details: BTreeMap::new(),
    });
    errors.push(msg);
}

pub fn load_plan_document(path: &Path) -> Result<PlanDocument, String> {
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("Failed reading plan {}: {e}", path.display()))?;
    let val: Value = serde_json::from_str(&raw)
        .map_err(|e| format!("Invalid JSON in {}: {e}", path.display()))?;
    if !val.is_object() {
        return Err("plan must be a JSON object".into());
    }
    serde_json::from_value(val).map_err(|e| format!("Plan schema error in {}: {e}", path.display()))
}

/// Extract normalized plan facts for Lean 4 kernel evaluation and Mode B certification.
pub fn build_plan_kernel_request(plan: &PlanDocument) -> KernelPlanRequest {
    let tasks = plan
        .tasks
        .iter()
        .map(|t| {
            let status = if VALID_STATUSES.contains(&t.status.as_str()) {
                t.status.clone()
            } else {
                "blocked".into()
            };
            KernelPlanTask {
                id: t.id.clone(),
                status,
                depends_on: t.depends_on.clone(),
                has_completion_evidence: !t.completion_evidence.is_empty()
                    && t.completion_evidence.iter().all(|s| !s.trim().is_empty()),
                allowed_paths_nonempty: !t.allowed_paths.is_empty(),
                verification_nonempty: !t.verification.is_empty(),
            }
        })
        .collect();
    let questions = plan
        .questions
        .iter()
        .map(|q| KernelBlockingQuestion {
            id: q.id.clone(),
            blocks: q.blocks.clone(),
        })
        .collect();
    KernelPlanRequest { tasks, questions }
}

/// Extract normalized dispatch facts for Lean 4 kernel evaluation and Mode B certification.
pub fn build_plan_dispatch_kernel_request(
    plan: &PlanDocument,
    task_id: &str,
) -> KernelPlanDispatchRequest {
    let base = build_plan_kernel_request(plan);
    let intent = if matches!(plan.intent.as_str(), "plan-only" | "implement") {
        plan.intent.clone()
    } else {
        "plan-only".into()
    };
    KernelPlanDispatchRequest {
        intent,
        task_id: task_id.into(),
        tasks: base.tasks,
        questions: base.questions,
    }
}

fn validate_plan_syntax(
    plan: &PlanDocument,
    errors: &mut Vec<String>,
    findings: &mut Vec<ProjectFinding>,
) {
    let id_re = Regex::new(r"^[a-z0-9][a-z0-9_-]*$").unwrap();

    if plan.version != 1 {
        add_err(errors, findings, "PLAN_VERSION", "version must be 1".into());
    }
    if !matches!(plan.intent.as_str(), "plan-only" | "implement") {
        add_err(
            errors,
            findings,
            "PLAN_INTENT",
            "intent must be plan-only or implement".into(),
        );
    }
    if plan.outcome.trim().is_empty() {
        add_err(
            errors,
            findings,
            "PLAN_OUTCOME",
            "outcome is required".into(),
        );
    }
    if !non_empty_strings(&plan.non_goals, false) {
        add_err(
            errors,
            findings,
            "PLAN_FIELD",
            "non_goals: invalid string list".into(),
        );
    }
    if !non_empty_strings(&plan.constraints, true) {
        add_err(
            errors,
            findings,
            "PLAN_FIELD",
            "constraints: invalid string list".into(),
        );
    }
    if !non_empty_strings(&plan.evidence, true) {
        add_err(
            errors,
            findings,
            "PLAN_FIELD",
            "evidence: invalid string list".into(),
        );
    }

    for task in &plan.tasks {
        let tid = task.id.as_str();
        if !id_re.is_match(tid) {
            add_err(
                errors,
                findings,
                "PLAN_TASK_ID",
                format!("task ID '{tid}' must be a nonempty lowercase identifier"),
            );
        }
        for (field, val) in [
            ("title", task.title.as_str()),
            ("context", task.context.as_str()),
            ("expected_behavior", task.expected_behavior.as_str()),
            ("owner", task.owner.as_str()),
        ] {
            if val.trim().is_empty() {
                add_err(
                    errors,
                    findings,
                    "PLAN_TASK_FIELD",
                    format!("{tid}: missing {field}"),
                );
            }
        }
        if !VALID_STATUSES.contains(&task.status.as_str()) {
            add_err(
                errors,
                findings,
                "PLAN_TASK_STATUS",
                format!("{tid}: invalid status '{}'", task.status),
            );
        }
        if !non_empty_strings(&task.acceptance, true) {
            add_err(
                errors,
                findings,
                "PLAN_TASK_FIELD",
                format!("{tid}: invalid acceptance"),
            );
        }
        if !non_empty_strings(&task.stop_conditions, true) {
            add_err(
                errors,
                findings,
                "PLAN_TASK_FIELD",
                format!("{tid}: invalid stop_conditions"),
            );
        }
        if !non_empty_strings(&task.completion_evidence, false) {
            add_err(
                errors,
                findings,
                "PLAN_TASK_FIELD",
                format!("{tid}: invalid completion_evidence"),
            );
        }
        if task.allowed_paths.iter().any(|p| !is_valid_scoped_path(p)) {
            add_err(
                errors,
                findings,
                "PLAN_SCOPE_PATH",
                format!("{tid}: invalid scoped allowed_paths"),
            );
        }
        if task
            .forbidden_paths
            .iter()
            .any(|p| !is_valid_scoped_path(p))
        {
            add_err(
                errors,
                findings,
                "PLAN_SCOPE_PATH",
                format!("{tid}: invalid scoped forbidden_paths"),
            );
        }
        if task
            .verification_output_paths
            .iter()
            .any(|p| !is_valid_scoped_path(p))
        {
            add_err(
                errors,
                findings,
                "PLAN_SCOPE_PATH",
                format!("{tid}: invalid scoped verification_output_paths"),
            );
        }
        if let Some(ref root) = task.checkout_root {
            if root.trim().is_empty() || !Path::new(root).is_absolute() {
                add_err(
                    errors,
                    findings,
                    "PLAN_CHECKOUT_ROOT",
                    format!("{tid}: checkout_root must be an absolute path"),
                );
            }
        }
        let mut dep_seen = HashSet::new();
        for dep in &task.depends_on {
            if dep.trim().is_empty() || !dep_seen.insert(dep.as_str()) {
                add_err(
                    errors,
                    findings,
                    "PLAN_DEPENDENCY",
                    format!("{tid}: invalid depends_on"),
                );
            }
        }
        if task
            .verification
            .iter()
            .any(|v| v.method.trim().is_empty() || v.expected.trim().is_empty())
        {
            add_err(
                errors,
                findings,
                "PLAN_VERIFICATION",
                format!("{tid}: verification must contain nonempty method and expected"),
            );
        }
    }

    let mut q_ids = HashSet::new();
    for q in &plan.questions {
        if q.id.trim().is_empty()
            || q.question.trim().is_empty()
            || !non_empty_strings(&q.blocks, false)
        {
            add_err(
                errors,
                findings,
                "PLAN_QUESTION",
                "invalid blocking question".into(),
            );
            continue;
        }
        if !q_ids.insert(q.id.as_str()) {
            add_err(
                errors,
                findings,
                "PLAN_QUESTION_DUP",
                format!("duplicate question ID '{}'", q.id),
            );
        }
    }
}

/// Validate a `PlanDocument`: syntax in Rust, all contract semantics in the Lean 4 kernel.
pub fn validate_plan_document(plan: &PlanDocument) -> PlanValidationOutcome {
    let mut errors = Vec::new();
    let mut findings = Vec::new();
    validate_plan_syntax(plan, &mut errors, &mut findings);

    let kreq = build_plan_kernel_request(plan);
    match eval_plan(&kreq) {
        Ok(kplan) => {
            if !kplan.verdict.admitted {
                for reason in kplan.verdict.reasons {
                    let (rule, msg) = if let Some(rest) = reason.strip_prefix('[') {
                        if let Some((code, body)) = rest.split_once("] ") {
                            (code, body.to_string())
                        } else {
                            ("PLAN_KERNEL_CONTRACT", reason)
                        }
                    } else {
                        ("PLAN_KERNEL_CONTRACT", reason)
                    };
                    add_err(&mut errors, &mut findings, rule, msg);
                }
            }
            PlanValidationOutcome {
                valid: kplan.verdict.admitted && errors.is_empty(),
                errors,
                findings,
                ready_tasks: kplan.ready_tasks,
                blocked_tasks: kplan.blocked_tasks,
                done_tasks: kplan.done_tasks,
                kernel_error: None,
            }
        }
        Err(err) => {
            add_err(&mut errors, &mut findings, "PLAN_KERNEL_ERROR", err.clone());
            PlanValidationOutcome {
                valid: false,
                errors,
                findings,
                ready_tasks: Vec::new(),
                blocked_tasks: Vec::new(),
                done_tasks: Vec::new(),
                kernel_error: Some(err),
            }
        }
    }
}

/// Evaluate mutating dispatchability via syntax checks + Lean 4 kernel (`canDispatchMutating`),
/// returning `Err` on kernel/tool failure and `Ok((kreq, admitted, reasons))` otherwise.
pub fn verify_plan_dispatch_checked(
    plan: &PlanDocument,
    task_id: &str,
) -> Result<(KernelPlanDispatchRequest, bool, Vec<String>), String> {
    let mut syntax_errors = Vec::new();
    let mut syntax_findings = Vec::new();
    validate_plan_syntax(plan, &mut syntax_errors, &mut syntax_findings);

    let kreq = build_plan_dispatch_kernel_request(plan, task_id);
    let verdict = eval_plan_dispatch(&kreq)?;
    let mut reasons = syntax_errors;
    if !verdict.admitted {
        reasons.extend(verdict.reasons);
    }
    let admitted = verdict.admitted && reasons.is_empty();
    Ok((kreq, admitted, reasons))
}

/// Fail-closed dispatch check backed by `BirkinSpec.canDispatchMutating`.
pub fn can_dispatch_mutating(plan: &PlanDocument, task_id: &str) -> Result<bool, Vec<String>> {
    match verify_plan_dispatch_checked(plan, task_id) {
        Ok((_, true, _)) => Ok(true),
        Ok((_, false, reasons)) => Err(reasons),
        Err(err) => Err(vec![err]),
    }
}

pub fn plan_outcome_to_json(outcome: &PlanValidationOutcome) -> Value {
    json!({
        "valid": outcome.valid,
        "errors": outcome.errors,
        "ready_tasks": outcome.ready_tasks,
        "blocked_tasks": outcome.blocked_tasks,
        "done_tasks": outcome.done_tasks,
        "findings": outcome.findings,
    })
}
