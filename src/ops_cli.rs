//! Operational command handlers (hooks, install-hooks, sync, receipt verify, steer, gc).

use crate::client_sync::{format_sync_human, parse_targets, run_client_sync, SyncMode};
use crate::constants::{default_hermes_home, home_dir, EXIT_PASS, EXIT_STATIC, EXIT_TOOL_ERROR};
use crate::gc::run_gc_scan;
use crate::hooks::{
    extract_claude_edited_paths, install_claude_hook, install_git_pre_commit_hook,
    install_hermes_plugin, read_claude_stdin_payload, run_post_edit_hook, run_pre_commit_hook,
};
use crate::ledger::{append_receipt, verify_receipts_for_current_state};
use crate::project_init::detect_project_spec;
use crate::project_models::{find_repo_root, find_spec_file, load_project_spec, ProjectSpec};
use crate::prove::run_prove;
use crate::steer::analyze_telemetry;
use clap::Args;
use serde_json::{json, Map, Value};
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

pub fn handle_hook_post_edit(
    files: &[PathBuf],
    claude_stdin: bool,
    semantic: bool,
    block_on_error: bool,
    require_spec: bool,
    surface: &str,
) -> i32 {
    if claude_stdin {
        let Ok(payload) = read_claude_stdin_payload() else {
            return EXIT_PASS;
        };
        let paths = extract_claude_edited_paths(&payload);
        if paths.is_empty() {
            return EXIT_PASS;
        }
        let Ok((code, findings, feedback)) =
            run_post_edit_hook(&paths, "claude-hook", semantic, false)
        else {
            return EXIT_PASS;
        };
        if !findings.is_empty() && !feedback.is_empty() {
            println!(
                "{}",
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PostToolUse",
                        "additionalContext": feedback,
                    }
                })
            );
        }
        return if block_on_error { code } else { EXIT_PASS };
    }

    match run_post_edit_hook(files, surface, semantic, require_spec) {
        Ok((code, _, feedback)) => {
            if !feedback.is_empty() {
                if code != EXIT_PASS {
                    eprintln!("{feedback}");
                } else {
                    println!("{feedback}");
                }
            }
            if block_on_error { code } else { EXIT_PASS }
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            EXIT_TOOL_ERROR
        }
    }
}

pub fn handle_hook_pre_commit(path: &Path) -> i32 {
    let repo_root = find_repo_root(path);
    match run_pre_commit_hook(&repo_root) {
        Ok((code, _, feedback)) => {
            if !feedback.is_empty() {
                if code != EXIT_PASS {
                    eprintln!("{feedback}");
                } else {
                    println!("{feedback}");
                }
            }
            code
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            EXIT_TOOL_ERROR
        }
    }
}

pub fn handle_hook_pre_complete(path: &Path, require: &str, require_clean: bool) -> i32 {
    let (repo_root, spec, _) = match load_or_detect(path, None) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return EXIT_TOOL_ERROR;
        }
    };
    let reqs: Vec<String> = require
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let res = verify_receipts_for_current_state(&repo_root, &spec, &reqs, require_clean);
    if res["status"] == "PASS" {
        return EXIT_PASS;
    }
    eprintln!(
        "[birkin] Missing passing receipts for exact current revision: missing={}",
        res["missing"]
    );
    EXIT_STATIC
}

pub fn handle_install_hooks(
    path: &Path,
    target: &str,
    global_install: bool,
    hermes_home: Option<&Path>,
    as_json: bool,
) -> i32 {
    let repo_root = find_repo_root(path);
    let hhome = hermes_home
        .map(Path::to_path_buf)
        .unwrap_or_else(default_hermes_home);
    let mut results = Vec::new();

    if target == "git" || target == "all" {
        match install_git_pre_commit_hook(&repo_root) {
            Ok(v) => results.push(v),
            Err(e) => {
                eprintln!("ERROR: {e}");
                return EXIT_TOOL_ERROR;
            }
        }
    }
    if target == "claude" || target == "all" {
        let settings_path = if global_install {
            home_dir().join(".claude").join("settings.json")
        } else {
            repo_root.join(".claude").join("settings.local.json")
        };
        match install_claude_hook(&settings_path) {
            Ok(v) => results.push(v),
            Err(e) => {
                eprintln!("ERROR: {e}");
                return EXIT_TOOL_ERROR;
            }
        }
    }
    if target == "hermes" || target == "all" {
        match install_hermes_plugin(&hhome.join("plugins"), None) {
            Ok(v) => results.push(v),
            Err(e) => {
                eprintln!("ERROR: {e}");
                return EXIT_TOOL_ERROR;
            }
        }
    }

    let report = json!({"status": "OK", "installed": results});
    let mut lines = vec!["birkin install-hooks:".to_string()];
    for item in &results {
        lines.push(format!(
            "  - [{}] {} -> {}",
            item["target"].as_str().unwrap_or(""),
            item["status"].as_str().unwrap_or(""),
            item["path"].as_str().unwrap_or(""),
        ));
    }
    emit(&report, as_json, &lines.join("\n"));
    EXIT_PASS
}

pub fn handle_receipt_verify(
    path: &Path,
    explicit_spec: Option<&Path>,
    require: &str,
    require_clean: bool,
    as_json: bool,
) -> i32 {
    let (repo_root, spec, _) = match load_or_detect(path, explicit_spec) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return EXIT_TOOL_ERROR;
        }
    };
    let reqs: Vec<String> = require
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let res = verify_receipts_for_current_state(&repo_root, &spec, &reqs, require_clean);
    let ok = res["status"] == "PASS";
    let head_short: String = res["git_head"]
        .as_str()
        .unwrap_or("none")
        .chars()
        .take(10)
        .collect();
    let mut lines = vec![format!(
        "birkin receipt verify ({}): status={} chain_ok={} head={head_short} dirty={}",
        spec.project.name,
        res["status"].as_str().unwrap_or("FAIL"),
        res["chain_ok"].as_bool().unwrap_or(false),
        res["git_dirty"].as_bool().unwrap_or(false),
    )];
    if let Some(matched) = res["matched"].as_object() {
        for (cmd, info) in matched {
            let sha_short: String = info["receipt_sha256"]
                .as_str()
                .unwrap_or("")
                .chars()
                .take(12)
                .collect();
            lines.push(format!(
                "  [PASS] {cmd}: receipt={sha_short} surface={} at={}",
                info["surface"].as_str().unwrap_or(""),
                info["recorded_at"].as_str().unwrap_or(""),
            ));
        }
    }
    if let Some(missing) = res["missing"].as_array() {
        for m in missing {
            if let Some(ms) = m.as_str() {
                lines.push(format!("  [MISSING] {ms}"));
            }
        }
    }
    emit(&res, as_json, &lines.join("\n"));
    if ok { EXIT_PASS } else { EXIT_STATIC }
}

pub fn handle_steer(path: &Path, explicit_spec: Option<&Path>, as_json: bool) -> i32 {
    let (repo_root, spec, _) = match load_or_detect(path, explicit_spec) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return EXIT_TOOL_ERROR;
        }
    };
    let report = analyze_telemetry(&repo_root, &spec);
    let mut lines = vec![format!(
        "birkin steer ({}): runs={} pass_rate={} chain_ok={}",
        spec.project.name, report["total_runs"], report["pass_rate"], report["chain_ok"]
    )];
    if let Some(hotspots) = report["hotspots"].as_array() {
        if !hotspots.is_empty() {
            lines.push("  top hotspots:".into());
            for h in hotspots.iter().take(5) {
                lines.push(format!(
                    "    - {}: {} hits",
                    h["rule"].as_str().unwrap_or(""),
                    h["hits"].as_u64().unwrap_or(0)
                ));
            }
        }
    }
    if let Some(recs) = report["recommendations"].as_array() {
        if !recs.is_empty() {
            lines.push("  recommendations:".into());
            for r in recs {
                if let Some(rs) = r.as_str() {
                    lines.push(format!("    - {rs}"));
                }
            }
        }
    }
    emit(&report, as_json, &lines.join("\n"));
    EXIT_PASS
}

pub fn handle_gc(path: &Path, explicit_spec: Option<&Path>, as_json: bool) -> i32 {
    let (repo_root, spec, _) = match load_or_detect(path, explicit_spec) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return EXIT_TOOL_ERROR;
        }
    };
    let report = run_gc_scan(&repo_root, &spec, None);
    let errors = report["errors"].as_u64().unwrap_or(0);
    let line = format!(
        "birkin gc ({}): status={} files={} items={} (errors={errors}, warnings={})",
        spec.project.name,
        report["status"].as_str().unwrap_or(""),
        report["files_scanned"].as_u64().unwrap_or(0),
        report["total_items"].as_u64().unwrap_or(0),
        report["warnings"].as_u64().unwrap_or(0),
    );
    emit(&report, as_json, &line);
    if errors > 0 { EXIT_STATIC } else { EXIT_PASS }
}

#[allow(clippy::too_many_arguments)]
pub fn handle_prove(
    path: &Path,
    explicit_spec: Option<&Path>,
    emit_path: Option<&Path>,
    no_receipt: bool,
    skip_lean_projects: bool,
    surface: &str,
    as_json: bool,
) -> i32 {
    let (repo_root, spec, spec_path) = match load_or_detect(path, explicit_spec) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return EXIT_TOOL_ERROR;
        }
    };

    let outcome = run_prove(&repo_root, &spec, emit_path, skip_lean_projects);
    let passed = outcome.exit_code == EXIT_PASS;

    let mut receipt: Option<Map<String, Value>> = None;
    if spec.telemetry.enabled && !no_receipt {
        let fvals: Vec<Value> = outcome
            .findings
            .iter()
            .filter_map(|f| serde_json::to_value(f).ok())
            .collect();
        let mut meta = Map::new();
        meta.insert("theorems_proved".into(), json!(outcome.theorems_proved.len()));
        meta.insert("architecture_dag_proved".into(), json!(outcome.architecture_dag_proved));
        meta.insert("layer_edges_proved".into(), json!(outcome.layer_edges_proved));
        meta.insert("forbidden_imports_proved".into(), json!(outcome.forbidden_imports_proved));
        meta.insert("state_machines".into(), json!(outcome.state_machine_ids));
        meta.insert("policies".into(), json!(outcome.policy_ids));
        meta.insert("custom_projects".into(), json!(outcome.custom_projects));
        if let Ok(rcpt) = append_receipt(
            &repo_root,
            &spec,
            "prove",
            surface,
            if passed { "PASS" } else { "FAIL" },
            outcome.exit_code,
            outcome.duration_ms,
            &fvals,
            &outcome.files_checked,
            meta,
        ) {
            receipt = Some(rcpt);
        }
    }

    let report = json!({
        "command": "prove",
        "project": spec.project.name,
        "repo": repo_root.to_string_lossy(),
        "spec_path": spec_path.as_ref().map(|p| p.to_string_lossy().into_owned()),
        "status": if passed { "PASS" } else { "FAIL" },
        "exit_code": outcome.exit_code,
        "duration_ms": outcome.duration_ms as u64,
        "emitted_path": outcome.emitted_path,
        "architecture_dag_proved": outcome.architecture_dag_proved,
        "total_import_edges": outcome.total_import_edges,
        "layer_edges_proved": outcome.layer_edges_proved,
        "forbidden_imports_proved": outcome.forbidden_imports_proved,
        "state_machines": outcome.state_machine_ids,
        "policies": outcome.policy_ids,
        "custom_projects": outcome.custom_projects,
        "theorems_proved": outcome.theorems_proved,
        "axioms_audited": outcome.axioms_audited,
        "tcb": "Lean 4 kernel verifies DAG acyclicity, extracted import-graph compliance, state-machine/policy theorems, and custom proofs; Rust import extraction and git tree snapshotting form the host TCB.",
        "findings": outcome.findings,
        "receipt": receipt,
    });

    let mut lines = vec![format!(
        "birkin prove ({}): status={} theorems={} findings={} ({}ms)",
        spec.project.name,
        if passed { "PASS" } else { "FAIL" },
        outcome.theorems_proved.len(),
        outcome.findings.len(),
        outcome.duration_ms as u64,
    )];
    let proved_tag = if passed { "PROVED" } else { "FAILED" };
    if outcome.architecture_dag_proved {
        lines.push(format!(
            "  [{proved_tag}] architecture DAG acyclic; {} unique layer pair(s) from {} extracted import edge(s)",
            outcome.layer_edges_proved, outcome.total_import_edges
        ));
    }
    if outcome.forbidden_imports_proved > 0 || !spec.architecture.forbidden_imports.is_empty() {
        lines.push(format!(
            "  [{proved_tag}] forbidden imports: {} scoped import fact(s) verified",
            outcome.forbidden_imports_proved
        ));
    }
    if !outcome.state_machine_ids.is_empty() {
        lines.push(format!(
            "  [{proved_tag}] state machines: {}",
            outcome.state_machine_ids.join(", ")
        ));
    }
    if !outcome.policy_ids.is_empty() {
        lines.push(format!(
            "  [{proved_tag}] policies: {}",
            outcome.policy_ids.join(", ")
        ));
    }
    for cp in &outcome.custom_projects {
        lines.push(format!(
            "  [{}] lean project '{}' ({}, audited={})",
            cp["status"].as_str().unwrap_or("?"),
            cp["name"].as_str().unwrap_or(""),
            cp["dir"].as_str().unwrap_or(""),
            cp["theorems_audited"].as_u64().unwrap_or(0),
        ));
    }
    if let Some(ref ep) = outcome.emitted_path {
        lines.push(format!("  emitted: {ep}"));
    }
    for f in &outcome.findings {
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
    emit(&report, as_json, &lines.join("\n"));
    outcome.exit_code
}

#[derive(Args, Debug, Clone)]
pub struct SyncArgs {
    /// Read-only drift audit (writes nothing; exits 4 on drift)
    #[arg(long)]
    pub check: bool,
    /// Deterministically write managed adapters (refuses unmanaged files and symlinks)
    #[arg(long)]
    pub apply: bool,
    /// Required target root directory (never defaults to live $HOME)
    #[arg(long = "target-root")]
    pub target_root: Option<PathBuf>,
    /// Repeatable target filter: git, claude, hermes, skills, all (default: all)
    #[arg(long = "target")]
    pub targets: Vec<String>,
    /// Emit machine-readable JSON output
    #[arg(long = "json")]
    pub as_json: bool,
    /// Skip appending a receipt to the ledger
    #[arg(long)]
    pub no_receipt: bool,
    /// Optional repository directory for recording a sync receipt
    #[arg(long)]
    pub repo: Option<PathBuf>,
    /// Optional explicit .birkin/config.yaml path for recording a sync receipt
    #[arg(long)]
    pub spec: Option<PathBuf>,
    /// Execution surface recorded in receipts
    #[arg(long, default_value = "cli")]
    pub surface: String,
}

fn emit_sync_tool_error(err: &str, as_json: bool) -> i32 {
    if as_json {
        let body = json!({
            "command": "sync",
            "status": "ERROR",
            "exit_code": EXIT_TOOL_ERROR,
            "error": err,
        });
        println!("{}", serde_json::to_string_pretty(&body).unwrap_or_else(|_| "{}".into()));
    } else {
        eprintln!("ERROR: {err}");
    }
    EXIT_TOOL_ERROR
}

pub fn handle_sync(args: &SyncArgs) -> i32 {
    let t0 = Instant::now();
    let mode = match (args.check, args.apply) {
        (true, false) => SyncMode::Check,
        (false, true) => SyncMode::Apply,
        _ => {
            return emit_sync_tool_error(
                "Specify exactly one of --check or --apply.",
                args.as_json,
            );
        }
    };
    let Some(ref target_root) = args.target_root else {
        return emit_sync_tool_error(
            "--target-root <dir> is required; Birkin never defaults sync to live $HOME.",
            args.as_json,
        );
    };
    let targets = match parse_targets(&args.targets) {
        Ok(t) => t,
        Err(e) => return emit_sync_tool_error(&e, args.as_json),
    };
    let report = match run_client_sync(target_root, mode, &targets) {
        Ok(r) => r,
        Err(e) => return emit_sync_tool_error(&e, args.as_json),
    };

    let mut receipt_sha: Option<String> = None;
    let mut receipt_error: Option<String> = None;
    if !args.no_receipt && (args.repo.is_some() || args.spec.is_some()) {
        if let Some(ref r) = args.repo {
            if !r.is_dir() {
                return emit_sync_tool_error(
                    &format!("--repo {} is not an existing directory.", r.display()),
                    args.as_json,
                );
            }
        }
        let repo_hint = args.repo.as_deref().unwrap_or_else(|| Path::new("."));
        match load_or_detect(repo_hint, args.spec.as_deref()) {
            Ok((repo_root, spec, _)) if spec.telemetry.enabled => {
                let checked: Vec<String> = report.targets.iter().map(|t| t.relative_path.clone()).collect();
                let mut meta = Map::new();
                meta.insert("mode".into(), json!(report.mode));
                meta.insert("target_root".into(), json!(report.target_root));
                meta.insert("contract_version".into(), json!(report.contract_version));
                meta.insert("bundle_sha256".into(), json!(report.bundle_sha256));
                meta.insert("selected_targets".into(), json!(report.selected_targets));
                match append_receipt(
                    &repo_root,
                    &spec,
                    &format!("sync:{}", report.mode),
                    &args.surface,
                    &report.status,
                    report.exit_code,
                    t0.elapsed().as_millis(),
                    &[],
                    &checked,
                    meta,
                ) {
                    Ok(rcpt) => {
                        receipt_sha = rcpt.get("receipt_sha256").and_then(Value::as_str).map(str::to_string);
                    }
                    Err(e) => {
                        eprintln!(
                            "[birkin] warning: failed recording receipt (sync:{}): {e}",
                            report.mode
                        );
                        receipt_error = Some(e);
                    }
                }
            }
            Ok(_) => {}
            Err(e) => return emit_sync_tool_error(&e, args.as_json),
        }
    }

    let mut payload = serde_json::to_value(&report).unwrap_or_else(|_| json!({}));
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("receipt_sha256".into(), json!(receipt_sha));
        obj.insert("receipt_error".into(), json!(receipt_error));
    }
    emit(&payload, args.as_json, &format_sync_human(&report));
    report.exit_code
}
