//! Execution-plan contract validator (`fly-face` / `xo`) aligned with `BirkinSpec.PlanContract`.
//!
//! Enforces strict v1 structural invariants, topological dependency order (acyclic DAG),
//! transitive block propagation across dependencies and blocking questions, `plan-only`
//! mutation prohibition, multi-checkout `checkout_root` hygiene, and `done` completion evidence.

use crate::project_models::ProjectFinding;
use crate::workflow_models::{PlanDocument, PlanTaskSpec};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
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

pub fn is_question_blocked(plan: &PlanDocument, task_id: &str) -> bool {
    plan.questions
        .iter()
        .any(|q| q.blocks.iter().any(|b| b == task_id))
}

pub fn has_blocked_prereq(by_id: &HashMap<&str, &PlanTaskSpec>, task: &PlanTaskSpec) -> bool {
    task.depends_on
        .iter()
        .any(|dep| match by_id.get(dep.as_str()) {
            Some(dt) => dt.status == "blocked",
            None => true,
        })
}

pub fn all_prereqs_done(by_id: &HashMap<&str, &PlanTaskSpec>, task: &PlanTaskSpec) -> bool {
    task.depends_on
        .iter()
        .all(|dep| match by_id.get(dep.as_str()) {
            Some(dt) => dt.status == "done",
            None => false,
        })
}

/// Validate a `PlanDocument` with strict fail-closed semantics matching `BirkinSpec.PlanContract`.
pub fn validate_plan_document(plan: &PlanDocument) -> PlanValidationOutcome {
    let mut errors = Vec::new();
    let mut findings = Vec::new();
    let id_re = Regex::new(r"^[a-z0-9][a-z0-9_-]*$").unwrap();

    if plan.version != 1 {
        add_err(
            &mut errors,
            &mut findings,
            "PLAN_VERSION",
            "version must be 1".into(),
        );
    }
    if !matches!(plan.intent.as_str(), "plan-only" | "implement") {
        add_err(
            &mut errors,
            &mut findings,
            "PLAN_INTENT",
            "intent must be plan-only or implement".into(),
        );
    }
    if plan.outcome.trim().is_empty() {
        add_err(
            &mut errors,
            &mut findings,
            "PLAN_OUTCOME",
            "outcome is required".into(),
        );
    }
    if !non_empty_strings(&plan.non_goals, false) {
        add_err(
            &mut errors,
            &mut findings,
            "PLAN_FIELD",
            "non_goals: invalid string list".into(),
        );
    }
    if !non_empty_strings(&plan.constraints, true) {
        add_err(
            &mut errors,
            &mut findings,
            "PLAN_FIELD",
            "constraints: invalid string list".into(),
        );
    }
    if !non_empty_strings(&plan.evidence, true) {
        add_err(
            &mut errors,
            &mut findings,
            "PLAN_FIELD",
            "evidence: invalid string list".into(),
        );
    }
    if plan.tasks.is_empty() {
        add_err(
            &mut errors,
            &mut findings,
            "PLAN_TASKS_EMPTY",
            "tasks must be a nonempty list of objects".into(),
        );
        return PlanValidationOutcome {
            valid: false,
            errors,
            findings,
            ready_tasks: Vec::new(),
            blocked_tasks: Vec::new(),
            done_tasks: Vec::new(),
        };
    }

    let mut by_id: HashMap<&str, &PlanTaskSpec> = HashMap::new();
    for task in &plan.tasks {
        if !id_re.is_match(&task.id) {
            add_err(
                &mut errors,
                &mut findings,
                "PLAN_TASK_ID",
                format!(
                    "task ID '{}' must be a nonempty lowercase identifier",
                    task.id
                ),
            );
        }
        if by_id.insert(task.id.as_str(), task).is_some() {
            add_err(
                &mut errors,
                &mut findings,
                "PLAN_DUPLICATE_ID",
                format!("duplicate task ID '{}'", task.id),
            );
        }
    }

    let mut seen: HashSet<&str> = HashSet::new();
    for task in &plan.tasks {
        let tid = task.id.as_str();
        for (field, val) in [
            ("title", task.title.as_str()),
            ("context", task.context.as_str()),
            ("expected_behavior", task.expected_behavior.as_str()),
            ("owner", task.owner.as_str()),
        ] {
            if val.trim().is_empty() {
                add_err(
                    &mut errors,
                    &mut findings,
                    "PLAN_TASK_FIELD",
                    format!("{tid}: missing {field}"),
                );
            }
        }
        if !VALID_STATUSES.contains(&task.status.as_str()) {
            add_err(
                &mut errors,
                &mut findings,
                "PLAN_TASK_STATUS",
                format!("{tid}: invalid status '{}'", task.status),
            );
        }
        if !non_empty_strings(&task.acceptance, true) {
            add_err(
                &mut errors,
                &mut findings,
                "PLAN_TASK_FIELD",
                format!("{tid}: invalid acceptance"),
            );
        }
        if !non_empty_strings(&task.stop_conditions, true) {
            add_err(
                &mut errors,
                &mut findings,
                "PLAN_TASK_FIELD",
                format!("{tid}: invalid stop_conditions"),
            );
        }
        if !non_empty_strings(&task.completion_evidence, false) {
            add_err(
                &mut errors,
                &mut findings,
                "PLAN_TASK_FIELD",
                format!("{tid}: invalid completion_evidence"),
            );
        }
        if task.allowed_paths.is_empty()
            || task.allowed_paths.iter().any(|p| !is_valid_scoped_path(p))
        {
            add_err(
                &mut errors,
                &mut findings,
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
                &mut errors,
                &mut findings,
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
                &mut errors,
                &mut findings,
                "PLAN_SCOPE_PATH",
                format!("{tid}: invalid scoped verification_output_paths"),
            );
        }
        if let Some(ref root) = task.checkout_root {
            if root.trim().is_empty() || !Path::new(root).is_absolute() {
                add_err(
                    &mut errors,
                    &mut findings,
                    "PLAN_CHECKOUT_ROOT",
                    format!("{tid}: checkout_root must be an absolute path"),
                );
            }
        }

        let mut dep_seen = HashSet::new();
        for dep in &task.depends_on {
            if dep.trim().is_empty() || !dep_seen.insert(dep.as_str()) {
                add_err(
                    &mut errors,
                    &mut findings,
                    "PLAN_DEPENDENCY",
                    format!("{tid}: invalid depends_on"),
                );
                continue;
            }
            if !seen.contains(dep.as_str()) {
                add_err(
                    &mut errors,
                    &mut findings,
                    "PLAN_DAG_ORDER",
                    format!("{tid}: dependency {dep} missing, cyclic, or not in dependency order"),
                );
            } else if matches!(task.status.as_str(), "in_progress" | "done") {
                if let Some(dt) = by_id.get(dep.as_str()) {
                    if dt.status != "done" {
                        add_err(
                            &mut errors,
                            &mut findings,
                            "PLAN_PREREQ_UNMET",
                            format!("{tid}: prerequisite {dep} not done"),
                        );
                    }
                }
            }
        }
        seen.insert(tid);

        if task.verification.is_empty()
            || task
                .verification
                .iter()
                .any(|v| v.method.trim().is_empty() || v.expected.trim().is_empty())
        {
            add_err(
                &mut errors,
                &mut findings,
                "PLAN_VERIFICATION",
                format!("{tid}: verification needs method and expected result"),
            );
        }
        if task.status == "done" && !non_empty_strings(&task.completion_evidence, true) {
            add_err(
                &mut errors,
                &mut findings,
                "PLAN_DONE_EVIDENCE",
                format!("{tid}: done requires completion evidence"),
            );
        }

        let blocked_by_q = is_question_blocked(plan, tid);
        let blocked_by_dep = has_blocked_prereq(&by_id, task);
        if (blocked_by_q || blocked_by_dep)
            && !matches!(task.status.as_str(), "blocked" | "superseded")
        {
            add_err(
                &mut errors,
                &mut findings,
                "PLAN_BLOCK_PROPAGATION",
                format!("{tid}: blocked prerequisite or question must propagate status='blocked'"),
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
                &mut errors,
                &mut findings,
                "PLAN_QUESTION",
                "invalid blocking question".into(),
            );
            continue;
        }
        if !q_ids.insert(q.id.as_str()) {
            add_err(
                &mut errors,
                &mut findings,
                "PLAN_QUESTION_DUP",
                format!("duplicate question ID '{}'", q.id),
            );
        }
        for tid in &q.blocks {
            match by_id.get(tid.as_str()) {
                Some(t) if t.status == "blocked" => {}
                _ => add_err(
                    &mut errors,
                    &mut findings,
                    "PLAN_QUESTION_TARGET",
                    format!("question {}: {} must exist and be blocked", q.id, tid),
                ),
            }
        }
    }

    let ready_tasks = plan
        .tasks
        .iter()
        .filter(|t| t.status == "ready")
        .map(|t| t.id.clone())
        .collect();
    let blocked_tasks = plan
        .tasks
        .iter()
        .filter(|t| t.status == "blocked")
        .map(|t| t.id.clone())
        .collect();
    let done_tasks = plan
        .tasks
        .iter()
        .filter(|t| t.status == "done")
        .map(|t| t.id.clone())
        .collect();

    PlanValidationOutcome {
        valid: errors.is_empty(),
        errors,
        findings,
        ready_tasks,
        blocked_tasks,
        done_tasks,
    }
}

/// Fail-closed dispatch check matching `BirkinSpec.canDispatchMutating`.
pub fn can_dispatch_mutating(plan: &PlanDocument, task_id: &str) -> Result<bool, Vec<String>> {
    let outcome = validate_plan_document(plan);
    let mut reasons = outcome.errors;
    if plan.intent != "implement" {
        reasons.push(format!(
            "plan intent is '{}'; mutating dispatch requires intent='implement'",
            plan.intent
        ));
    }
    let by_id: HashMap<&str, &PlanTaskSpec> =
        plan.tasks.iter().map(|t| (t.id.as_str(), t)).collect();
    match by_id.get(task_id) {
        None => reasons.push(format!("task '{task_id}' not found in plan")),
        Some(task) => {
            if task.status != "ready" {
                reasons.push(format!(
                    "task '{task_id}' status is '{}', expected 'ready'",
                    task.status
                ));
            }
            if is_question_blocked(plan, task_id) {
                reasons.push(format!("task '{task_id}' is blocked by an open question"));
            }
            if has_blocked_prereq(&by_id, task) {
                reasons.push(format!("task '{task_id}' has a blocked prerequisite"));
            }
            if !all_prereqs_done(&by_id, task) {
                reasons.push(format!("task '{task_id}' has incomplete prerequisites"));
            }
        }
    }
    if reasons.is_empty() {
        Ok(true)
    } else {
        Err(reasons)
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
