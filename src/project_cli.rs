//! Project-universal command handlers and human formatters.

use crate::constants::{EXIT_PASS, EXIT_STATIC, EXIT_TOOL_ERROR};
use crate::guides::{audit_guides, build_readiness_scorecard};
use crate::ledger::{append_receipt, read_receipts, resolve_ledger_path};
use crate::project_init::{detect_project_spec, render_agent_guide, render_spec_yaml};
use crate::project_models::{
    find_repo_root, find_spec_file, load_project_spec, ProjectFinding, ProjectSpec,
};
use crate::semantic::{evaluate_semantic_rules, run_semantic_review};
use crate::sensors::{evaluate_regex_rules, run_project_sensors};
use crate::steer::analyze_telemetry;
use crate::verify::run_verify_commands;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn load_or_detect(
    path: &Path,
    explicit_spec: Option<&Path>,
) -> Result<(PathBuf, ProjectSpec, Option<PathBuf>), String> {
    let repo_root = find_repo_root(path);
    if explicit_spec.is_some() || find_spec_file(&repo_root).is_some() {
        let (spec, spec_path) = load_project_spec(&repo_root, explicit_spec)?;
        return Ok((repo_root, spec, spec_path));
    }
    Ok((repo_root.clone(), detect_project_spec(&repo_root), None))
}

fn emit(data: &Value, as_json: bool, human: &str) {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(data).unwrap_or_else(|_| "{}".into())
        );
    } else {
        println!("{human}");
    }
}

fn format_findings(findings: &[ProjectFinding]) -> Vec<String> {
    let mut lines = Vec::new();
    for f in findings {
        let loc = match (&f.file, f.line) {
            (Some(file), Some(line)) => format!("{file}:{line}"),
            (Some(file), None) => file.clone(),
            _ => "<repo>".to_string(),
        };
        lines.push(format!(
            "  - [{}] {} ({loc}): {}",
            f.severity.to_uppercase(),
            f.rule,
            f.message
        ));
        lines.push(format!("    remediation: {}", f.remediation));
    }
    lines
}

pub fn handle_init(path: &Path, write: bool, force: bool, as_json: bool) -> i32 {
    let repo_root = find_repo_root(path);
    let spec = detect_project_spec(&repo_root);
    let rendered = render_spec_yaml(&spec);
    let target = repo_root.join(".birkin").join("config.yaml");

    if write {
        if target.exists() && !force {
            let err = format!(
                "Birkin spec already exists at {} (pass --force to overwrite)",
                target.display()
            );
            emit(&json!({"status": "ERROR", "error": err}), as_json, &format!("ERROR: {err}"));
            return EXIT_TOOL_ERROR;
        }
        if let Some(parent) = target.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                let err = format!("Failed creating {}: {e}", parent.display());
                emit(&json!({"status": "ERROR", "error": err}), as_json, &format!("ERROR: {err}"));
                return EXIT_TOOL_ERROR;
            }
        }
        if let Err(e) = fs::write(&target, &rendered) {
            let err = format!("Failed writing {}: {e}", target.display());
            emit(&json!({"status": "ERROR", "error": err}), as_json, &format!("ERROR: {err}"));
            return EXIT_TOOL_ERROR;
        }
        let cmds: Vec<&str> = spec.verify.commands.iter().map(|c| c.cmd.as_str()).collect();
        let out = json!({
            "status": "WRITTEN",
            "path": target.to_string_lossy(),
            "languages": spec.project.languages,
            "verify_commands": cmds,
        });
        emit(
            &out,
            as_json,
            &format!(
                "Wrote {} (languages={:?}, verify={})",
                target.display(),
                spec.project.languages,
                spec.verify.commands.len()
            ),
        );
        return EXIT_PASS;
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&spec).unwrap_or_else(|_| "{}".into())
        );
    } else {
        print!("{rendered}");
    }
    EXIT_PASS
}

pub fn handle_guide(path: &Path, explicit_spec: Option<&Path>, as_json: bool) -> i32 {
    let (repo_root, spec, _) = match load_or_detect(path, explicit_spec) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return EXIT_TOOL_ERROR;
        }
    };
    let telemetry = analyze_telemetry(&repo_root, &spec);
    let guide = render_agent_guide(&repo_root, &spec, Some(&telemetry));
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "project": spec.project.name,
                "repo": repo_root.to_string_lossy(),
                "guide": guide,
            }))
            .unwrap_or_default()
        );
    } else {
        print!("{guide}");
    }
    EXIT_PASS
}

pub fn handle_audit(path: &Path, explicit_spec: Option<&Path>, as_json: bool) -> i32 {
    let t0 = Instant::now();
    let (repo_root, spec, spec_path) = match load_or_detect(path, explicit_spec) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return EXIT_TOOL_ERROR;
        }
    };
    let guide_findings = audit_guides(&repo_root, &spec, None);
    let (sensor_findings, checked) = run_project_sensors(&repo_root, &spec, None);
    let ledger_entries = read_receipts(&resolve_ledger_path(&repo_root, &spec));
    let scorecard =
        build_readiness_scorecard(&repo_root, &spec, &guide_findings, &sensor_findings, &ledger_entries);

    let mut all_findings = Vec::new();
    all_findings.extend(guide_findings);
    all_findings.extend(sensor_findings);
    let has_errors = all_findings.iter().any(|f| f.severity == "error");
    let has_warnings = all_findings.iter().any(|f| f.severity == "warning");
    let exit_code = if has_errors { EXIT_STATIC } else { EXIT_PASS };
    let status = if has_errors {
        "FAIL"
    } else if has_warnings {
        "WARN"
    } else {
        "PASS"
    };
    let dur_ms = t0.elapsed().as_millis() as u64;

    let report = json!({
        "command": "audit",
        "project": spec.project.name,
        "repo": repo_root.to_string_lossy(),
        "spec_path": spec_path.as_ref().map(|p| p.to_string_lossy().into_owned()),
        "status": status,
        "exit_code": exit_code,
        "duration_ms": dur_ms,
        "files_checked": checked.len(),
        "scorecard": scorecard,
        "findings": all_findings,
    });

    let mut lines = vec![format!(
        "birkin audit ({}): status={status} files={} ({dur_ms}ms)",
        spec.project.name,
        checked.len()
    )];
    if let Some(sc) = scorecard.as_object() {
        for axis in [
            "orientation",
            "knowledge",
            "architecture",
            "admission",
            "sensors",
            "proofs",
            "observability",
        ] {
            if let Some(ax) = sc.get(axis) {
                lines.push(format!(
                    "  [{}] {}",
                    axis,
                    ax["status"].as_str().unwrap_or("?")
                ));
            }
        }
    }
    if !all_findings.is_empty() {
        lines.push(format!("  findings ({}):", all_findings.len()));
        lines.extend(format_findings(&all_findings));
    }
    emit(&report, as_json, &lines.join("\n"));
    exit_code
}

#[allow(clippy::too_many_arguments)]
pub fn handle_check(
    path: &Path,
    explicit_spec: Option<&Path>,
    files: Option<&[PathBuf]>,
    run_verify: bool,
    no_guides: bool,
    no_receipt: bool,
    surface: &str,
    as_json: bool,
) -> i32 {
    let t0 = Instant::now();
    let (repo_root, spec, spec_path) = match load_or_detect(path, explicit_spec) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return EXIT_TOOL_ERROR;
        }
    };

    let mut findings = Vec::new();
    let (sensor_findings, checked) = run_project_sensors(&repo_root, &spec, files);
    findings.extend(sensor_findings);

    if files.is_none() && !no_guides {
        findings.extend(audit_guides(&repo_root, &spec, None));
    }

    let mut verify_results = Vec::new();
    if run_verify {
        let (v_findings, vr) = run_verify_commands(&repo_root, &spec);
        findings.extend(v_findings);
        verify_results = vr;
    }

    let dur_ms = t0.elapsed().as_millis();
    let has_errors = findings.iter().any(|f| f.severity == "error");
    let exit_code = if has_errors { EXIT_STATIC } else { EXIT_PASS };

    let mut receipt: Option<Map<String, Value>> = None;
    let mut receipt_errors: Vec<String> = Vec::new();
    if spec.telemetry.enabled && !no_receipt {
        let cmd_label = if run_verify { "verify" } else { "check" };
        let fvals: Vec<Value> = findings
            .iter()
            .filter_map(|f| serde_json::to_value(f).ok())
            .collect();
        let mut meta = Map::new();
        let vnames: Vec<&str> = verify_results
            .iter()
            .filter_map(|r| r["name"].as_str())
            .collect();
        meta.insert("verify_commands".into(), json!(vnames));

        match append_receipt(
            &repo_root,
            &spec,
            cmd_label,
            surface,
            if has_errors { "FAIL" } else { "PASS" },
            exit_code,
            dur_ms,
            &fvals,
            &checked,
            meta,
        ) {
            Ok(rcpt) => receipt = Some(rcpt),
            Err(err) => {
                eprintln!("[birkin] warning: failed recording receipt ({cmd_label}): {err}");
                receipt_errors.push(err);
            }
        }

        if run_verify {
            let sensor_only: Vec<Value> = findings
                .iter()
                .filter(|f| f.category != "admission")
                .filter_map(|f| serde_json::to_value(f).ok())
                .collect();
            let sensor_errors = findings
                .iter()
                .any(|f| f.severity == "error" && f.category != "admission");
            if let Err(err) = append_receipt(
                &repo_root,
                &spec,
                "check",
                surface,
                if sensor_errors { "FAIL" } else { "PASS" },
                if sensor_errors { EXIT_STATIC } else { EXIT_PASS },
                dur_ms,
                &sensor_only,
                &checked,
                Map::new(),
            ) {
                eprintln!("[birkin] warning: failed recording receipt (check): {err}");
                receipt_errors.push(err);
            }
        }
    }

    let receipt_sha = receipt
        .as_ref()
        .and_then(|r| r.get("receipt_sha256"))
        .and_then(Value::as_str);
    let receipt_error = if receipt_errors.is_empty() {
        None
    } else {
        Some(receipt_errors.join("; "))
    };
    let report = json!({
        "command": "check",
        "project": spec.project.name,
        "repo": repo_root.to_string_lossy(),
        "spec_path": spec_path.as_ref().map(|p| p.to_string_lossy().into_owned()),
        "status": if has_errors { "FAIL" } else { "PASS" },
        "exit_code": exit_code,
        "duration_ms": dur_ms as u64,
        "files_checked": checked.len(),
        "verify_results": verify_results,
        "findings": findings,
        "receipt_sha256": receipt_sha,
        "receipt_error": receipt_error,
    });

    let mut lines = vec![format!(
        "birkin check ({}): status={} files={} findings={} ({dur_ms}ms)",
        spec.project.name,
        if has_errors { "FAIL" } else { "PASS" },
        checked.len(),
        findings.len()
    )];
    for vr in &verify_results {
        lines.push(format!(
            "  [verify:{}] {} ({}ms) `{}`",
            vr["name"].as_str().unwrap_or(""),
            vr["status"].as_str().unwrap_or(""),
            vr["duration_ms"].as_u64().unwrap_or(0),
            vr["cmd"].as_str().unwrap_or(""),
        ));
    }
    lines.extend(format_findings(&findings));
    if let Some(ref r) = receipt {
        let sha_short: String = r["receipt_sha256"]
            .as_str()
            .unwrap_or("")
            .chars()
            .take(16)
            .collect();
        let head_short: String = r["git_head"]
            .as_str()
            .unwrap_or("none")
            .chars()
            .take(10)
            .collect();
        lines.push(format!("  receipt: {sha_short} (head={head_short})"));
    }
    emit(&report, as_json, &lines.join("\n"));
    exit_code
}

#[allow(clippy::too_many_arguments)]
pub fn handle_review(
    path: &Path,
    explicit_spec: Option<&Path>,
    staged: bool,
    diff_ref: Option<&str>,
    files: Option<&[PathBuf]>,
    no_receipt: bool,
    as_json: bool,
) -> i32 {
    let t0 = Instant::now();
    let (repo_root, spec, _) = match load_or_detect(path, explicit_spec) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return EXIT_TOOL_ERROR;
        }
    };
    let (code, findings, meta) = run_semantic_review(&repo_root, &spec, staged, diff_ref, files);
    let dur_ms = t0.elapsed().as_millis();
    let evaluated = meta.get("evaluated").and_then(Value::as_u64).unwrap_or(0);

    let mut receipt_error: Option<String> = None;
    if spec.telemetry.enabled && !no_receipt && evaluated > 0 {
        let fvals: Vec<Value> = findings
            .iter()
            .filter_map(|f| serde_json::to_value(f).ok())
            .collect();
        let rfiles: Vec<String> = meta
            .get("files")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let mut rmeta = Map::new();
        if let Some(m) = meta.get("model") {
            rmeta.insert("model".into(), m.clone());
        }
        if let Err(err) = append_receipt(
            &repo_root,
            &spec,
            "review",
            "cli",
            if code == EXIT_PASS { "PASS" } else { "FAIL" },
            code,
            dur_ms,
            &fvals,
            &rfiles,
            rmeta,
        ) {
            eprintln!("[birkin] warning: failed recording receipt (review): {err}");
            receipt_error = Some(err);
        }
    }

    let report = json!({
        "command": "review",
        "project": spec.project.name,
        "status": if code == EXIT_PASS { "PASS" } else { "FAIL" },
        "exit_code": code,
        "duration_ms": dur_ms as u64,
        "meta": meta,
        "findings": findings,
        "receipt_error": receipt_error,
    });
    let mut lines = vec![format!(
        "birkin review ({}): status={} evaluated={} fix_now={} advisories={} ({dur_ms}ms)",
        spec.project.name,
        if code == EXIT_PASS { "PASS" } else { "FAIL" },
        evaluated,
        meta.get("fix_now").and_then(Value::as_u64).unwrap_or(0),
        meta.get("advisories").and_then(Value::as_u64).unwrap_or(0),
    )];
    lines.extend(format_findings(&findings));
    emit(&report, as_json, &lines.join("\n"));
    code
}

pub fn handle_eval_rules(
    path: &Path,
    explicit_spec: Option<&Path>,
    live: bool,
    as_json: bool,
) -> i32 {
    let (_, spec, _) = match load_or_detect(path, explicit_spec) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return EXIT_TOOL_ERROR;
        }
    };
    let regex_eval = evaluate_regex_rules(&spec);
    let sem_eval = evaluate_semantic_rules(&spec, live);
    let mut all_rules = Vec::new();
    if let Some(arr) = regex_eval["rules"].as_array() {
        all_rules.extend(arr.iter().cloned());
    }
    if let Some(arr) = sem_eval["rules"].as_array() {
        all_rules.extend(arr.iter().cloned());
    }
    let ok = regex_eval["status"] == "PASS" && sem_eval["status"] == "PASS";
    let exit_code = if ok { EXIT_PASS } else { EXIT_STATIC };
    let report = json!({
        "command": "eval-rules",
        "project": spec.project.name,
        "status": if ok { "PASS" } else { "FAIL" },
        "exit_code": exit_code,
        "total_rules": all_rules.len(),
        "rules": all_rules,
    });
    let mut lines = vec![format!(
        "birkin eval-rules ({}): status={} rules={}",
        spec.project.name,
        if ok { "PASS" } else { "FAIL" },
        all_rules.len()
    )];
    for r in &all_rules {
        let fp = r["false_positives"]
            .as_u64()
            .or_else(|| r["false_positives"].as_array().map(|a| a.len() as u64))
            .unwrap_or(0);
        let fn_ = r["false_negatives"]
            .as_u64()
            .or_else(|| r["false_negatives"].as_array().map(|a| a.len() as u64))
            .unwrap_or(0);
        lines.push(format!(
            "  - [{}] {}:{} (pass={} fail={} fp={fp} fn={fn_})",
            r["status"].as_str().unwrap_or(""),
            r["kind"].as_str().unwrap_or(""),
            r["id"].as_str().unwrap_or(""),
            r["examples_pass"].as_u64().unwrap_or(0),
            r["examples_fail"].as_u64().unwrap_or(0),
        ));
    }
    emit(&report, as_json, &lines.join("\n"));
    exit_code
}
