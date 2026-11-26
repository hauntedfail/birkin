//! Entropy and garbage-collection scanner for agent-maintained repositories.

use crate::guides::audit_guides;
use crate::project_models::{ProjectFinding, ProjectSpec};
use crate::sensors::run_project_sensors;
use crate::steer::analyze_telemetry;
use chrono::NaiveDate;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

fn bucket_for_finding(finding: &ProjectFinding) -> &'static str {
    if matches!(
        finding.rule.as_str(),
        "KNOWLEDGE_BROKEN_DOC_LINK"
            | "KNOWLEDGE_STALE_DOC_REVIEW"
            | "KNOWLEDGE_MISSING_REQUIRED_DOC"
    ) {
        return "doc_rot";
    }
    if matches!(
        finding.rule.as_str(),
        "ORIENTATION_UNTRACKED_SPEC_FILE"
            | "ORIENTATION_ENTRY_DOC_BLOATED"
            | "ORIENTATION_MISSING_ENTRY_DOC"
            | "ADMISSION_CI_LOCAL_DRIFT"
            | "ADMISSION_NO_LOCAL_VERIFY_DECLARED"
    ) {
        return "spec_drift";
    }
    if finding.category == "architecture" {
        return "architecture_debt";
    }
    if finding.category == "entropy" {
        return "dead_rules";
    }
    "hygiene"
}

pub fn run_gc_scan(repo_root: &Path, spec: &ProjectSpec, today: Option<NaiveDate>) -> Value {
    let guide_findings = audit_guides(repo_root, spec, today);
    let (sensor_findings, checked_files) = run_project_sensors(repo_root, spec, None);
    let telemetry = analyze_telemetry(repo_root, spec);
    let total_runs = telemetry["total_runs"].as_u64().unwrap_or(0);

    let mut dead_rule_findings = Vec::new();
    if let Some(stale_arr) = telemetry["stale_rule_candidates"].as_array() {
        for item in stale_arr {
            if let Some(rule_name) = item.as_str() {
                dead_rule_findings.push(ProjectFinding {
                    rule: "ENTROPY_STALE_RULE".into(),
                    category: "entropy".into(),
                    severity: "info".into(),
                    file: None,
                    line: None,
                    message: format!(
                        "Declared rule '{rule_name}' fired 0 times across {total_runs} runs."
                    ),
                    remediation: format!(
                        "Run `birkin eval-rules` to verify '{rule_name}' still detects bad examples, or remove it to keep rule overhead minimal."
                    ),
                    details: BTreeMap::new(),
                });
            }
        }
    }

    let mut all_findings = Vec::new();
    all_findings.extend(guide_findings);
    all_findings.extend(sensor_findings);
    all_findings.extend(dead_rule_findings);

    let mut buckets: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
    for key in [
        "doc_rot",
        "spec_drift",
        "architecture_debt",
        "dead_rules",
        "hygiene",
    ] {
        buckets.insert(key, Vec::new());
    }
    for f in &all_findings {
        let bucket = bucket_for_finding(f);
        if let Some(vec) = buckets.get_mut(bucket) {
            vec.push(serde_json::to_value(f).unwrap_or(Value::Null));
        }
    }

    let errors = all_findings.iter().filter(|f| f.severity == "error").count();
    let warnings = all_findings
        .iter()
        .filter(|f| f.severity == "warning")
        .count();
    let status = if all_findings.is_empty() {
        "CLEAN"
    } else if errors > 0 {
        "FAIL"
    } else {
        "WARN"
    };
    let resolved = fs::canonicalize(repo_root)
        .unwrap_or_else(|_| repo_root.to_path_buf())
        .to_string_lossy()
        .into_owned();

    json!({
        "project": spec.project.name,
        "repo": resolved,
        "status": status,
        "files_scanned": checked_files.len(),
        "total_items": all_findings.len(),
        "errors": errors,
        "warnings": warnings,
        "buckets": buckets,
        "findings": all_findings,
    })
}
