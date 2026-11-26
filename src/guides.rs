//! Feedforward guide auditing, doc-link verification, CI parity, and 6-axis readiness scorecard.

use crate::project_models::{find_spec_file, ProjectFinding, ProjectSpec};
use chrono::{NaiveDate, Utc};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

const URL_PREFIXES: &[&str] = &[
    "http://", "https://", "mailto:", "tel:", "data:", "file://", "#",
];

fn rel_posix(path: &Path, root: &Path) -> String {
    let r = path.strip_prefix(root).unwrap_or(path);
    r.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn git_tracked_files(repo_root: &Path) -> Option<HashSet<String>> {
    let out = Command::new("git")
        .args(["-C", &repo_root.to_string_lossy(), "ls-files"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let set = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    Some(set)
}

fn strip_fenced_code(md_text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut in_fence = false;
    for (idx, line) in md_text.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence {
            out.push((idx + 1, line.to_string()));
        }
    }
    out
}

fn collect_doc_files(repo_root: &Path, spec: &ProjectSpec) -> Vec<PathBuf> {
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut files = Vec::new();
    let mut names: Vec<String> = spec.orientation.entry_docs.clone();
    names.push("CLAUDE.md".into());
    names.push("README.md".into());
    names.extend(spec.orientation.required_docs.iter().cloned());

    for name in names {
        let p = repo_root.join(&name);
        if p.is_file()
            && p.extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("md"))
                .unwrap_or(false)
        {
            let canon = fs::canonicalize(&p).unwrap_or_else(|_| p.clone());
            if seen.insert(canon) {
                files.push(p);
            }
        }
    }

    let docs_dir = repo_root.join("docs");
    if docs_dir.is_dir() {
        let mut doc_paths: Vec<PathBuf> = WalkDir::new(&docs_dir)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_type().is_file()
                    && e.path()
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(|s| s.eq_ignore_ascii_case("md"))
                        .unwrap_or(false)
            })
            .map(|e| e.into_path())
            .collect();
        doc_paths.sort();
        for p in doc_paths {
            let canon = fs::canonicalize(&p).unwrap_or_else(|_| p.clone());
            if seen.insert(canon) {
                files.push(p);
            }
        }
    }
    files
}

fn is_release_only_workflow(val: &serde_yaml::Value) -> bool {
    let key = |s: &str| serde_yaml::Value::String(s.into());
    let Some(on_map) = val
        .as_mapping()
        .and_then(|m| m.get(key("on")))
        .and_then(serde_yaml::Value::as_mapping)
    else {
        return false;
    };
    if on_map.contains_key(key("pull_request")) {
        return false;
    }
    if let Some(push) = on_map.get(key("push")).and_then(serde_yaml::Value::as_mapping) {
        return push.contains_key(key("tags")) && !push.contains_key(key("branches"));
    }
    on_map.contains_key(key("release"))
}

/// Extract `(workflow_rel_path, command_line)` pairs from `.github/workflows/*.yml|yaml`.
pub fn extract_ci_run_commands(repo_root: &Path) -> Vec<(String, String)> {
    let wf_dir = repo_root.join(".github").join("workflows");
    if !wf_dir.is_dir() {
        return Vec::new();
    }
    let mut wf_files: Vec<PathBuf> = fs::read_dir(&wf_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("yml") | Some("yaml")
                )
        })
        .collect();
    wf_files.sort();

    let mut commands = Vec::new();
    for wf in wf_files {
        let rel = rel_posix(&wf, repo_root);
        let Ok(text) = fs::read_to_string(&wf) else { continue; };
        let Ok(val) = serde_yaml::from_str::<serde_yaml::Value>(&text) else { continue; };
        if is_release_only_workflow(&val) {
            continue;
        }
        let Some(jobs) = val
            .as_mapping()
            .and_then(|m| m.get(serde_yaml::Value::String("jobs".into())))
            .and_then(serde_yaml::Value::as_mapping)
        else {
            continue;
        };
        for job in jobs.values() {
            let Some(steps) = job
                .as_mapping()
                .and_then(|m| m.get(serde_yaml::Value::String("steps".into())))
                .and_then(serde_yaml::Value::as_sequence)
            else {
                continue;
            };
            for step in steps {
                if let Some(run_val) = step
                    .as_mapping()
                    .and_then(|m| m.get(serde_yaml::Value::String("run".into())))
                    .and_then(serde_yaml::Value::as_str)
                {
                    for line in run_val.lines() {
                        let cleaned = line.trim();
                        if !cleaned.is_empty() && !cleaned.starts_with('#') {
                            commands.push((rel.clone(), cleaned.to_string()));
                        }
                    }
                }
            }
        }
    }
    commands
}

fn is_verify_like_ci_cmd(cmd: &str) -> bool {
    let low = cmd.to_lowercase();
    const SKIPS: &[&str] = &[
        "pip install", "npm ci", "npm install", "pnpm install", "yarn install", "bun install",
        "cargo fetch", "go mod download", "apt-get", "brew install", "uv sync",
        "elan default", "elan toolchain",
    ];
    if SKIPS.iter().any(|s| low.contains(s)) {
        return false;
    }
    const TOKENS: &[&str] = &[
        "pytest", "ruff", "mypy", "pyright", "go test", "go vet", "golangci-lint",
        "cargo test", "cargo clippy", "cargo check", "lake build", "lake exe",
        "npm test", "npm run lint", "npm run test", "npm run typecheck",
        "pnpm test", "pnpm run", "bun test", "bun run ", "vitest", "jest", "eslint", "tsc",
    ];
    if TOKENS.iter().any(|t| low.contains(t)) {
        return true;
    }
    low.starts_with("birkin ") || low.contains("&& birkin ") || low.contains("; birkin ")
}

pub fn audit_guides(
    repo_root: &Path,
    spec: &ProjectSpec,
    today: Option<NaiveDate>,
) -> Vec<ProjectFinding> {
    let cur_date = today.unwrap_or_else(|| Utc::now().date_naive());
    let mut findings = Vec::new();

    // 1. Entry docs presence & line budgets
    let mut found_entry = false;
    for rel_name in &spec.orientation.entry_docs {
        let doc_path = repo_root.join(rel_name);
        if !doc_path.is_file() {
            findings.push(ProjectFinding {
                rule: "ORIENTATION_MISSING_ENTRY_DOC".into(),
                category: "orientation".into(),
                severity: "warning".into(),
                file: Some(rel_name.clone()),
                line: None,
                message: format!("Declared entry map '{rel_name}' does not exist."),
                remediation: format!(
                    "Create a concise map-style '{rel_name}' (<= {} lines) or run `birkin guide`.",
                    spec.orientation.max_entry_doc_lines
                ),
                details: BTreeMap::new(),
            });
            continue;
        }
        found_entry = true;
        if let Ok(text) = fs::read_to_string(&doc_path) {
            let line_count = text.lines().count();
            if line_count > spec.orientation.max_entry_doc_lines {
                findings.push(ProjectFinding {
                    rule: "ORIENTATION_ENTRY_DOC_BLOATED".into(),
                    category: "orientation".into(),
                    severity: "warning".into(),
                    file: Some(rel_name.clone()),
                    line: Some(line_count),
                    message: format!(
                        "Entry doc '{rel_name}' has {line_count} lines (budget: {}).",
                        spec.orientation.max_entry_doc_lines
                    ),
                    remediation: format!(
                        "Keep '{rel_name}' as a concise table of contents and move deep details into docs/."
                    ),
                    details: BTreeMap::new(),
                });
            }
        }
    }

    // 1b. Committed spec file check
    let spec_file = find_spec_file(repo_root);
    if spec.orientation.require_committed_spec {
        if let Some(ref sf) = spec_file {
            if let Some(tracked) = git_tracked_files(repo_root) {
                let s_rel = rel_posix(sf, repo_root);
                if !tracked.contains(&s_rel) {
                    findings.push(ProjectFinding {
                        rule: "ORIENTATION_UNTRACKED_SPEC_FILE".into(),
                        category: "orientation".into(),
                        severity: "warning".into(),
                        file: Some(s_rel.clone()),
                        line: None,
                        message: format!(
                            "Birkin spec '{s_rel}' exists on disk but is untracked in git."
                        ),
                        remediation: format!(
                            "Commit '{s_rel}' so repository invariants are versioned and CI-enforced."
                        ),
                        details: BTreeMap::new(),
                    });
                }
            }
        }
    }

    // 2. Required docs
    for req_rel in &spec.orientation.required_docs {
        if !repo_root.join(req_rel).exists() {
            findings.push(ProjectFinding {
                rule: "KNOWLEDGE_MISSING_REQUIRED_DOC".into(),
                category: "knowledge".into(),
                severity: "error".into(),
                file: Some(req_rel.clone()),
                line: None,
                message: format!("Required knowledge document '{req_rel}' is missing."),
                remediation: format!(
                    "Create '{req_rel}' or remove it from orientation.required_docs."
                ),
                details: BTreeMap::new(),
            });
        }
    }

    // 3. Markdown link integrity & Last reviewed staleness
    if spec.orientation.verify_markdown_links {
        let md_link_re =
            Regex::new(r#"!?\[[^\]]*\]\(([^)\s]+)(?:\s+["'][^"']*["'])?\)"#).unwrap();
        let last_rev_re = Regex::new(r"(?i)last\s+reviewed\s*:\s*(\d{4}-\d{2}-\d{2})").unwrap();

        for doc in collect_doc_files(repo_root, spec) {
            let rel_doc = rel_posix(&doc, repo_root);
            let Ok(text) = fs::read_to_string(&doc) else {
                continue;
            };
            let doc_parent = doc.parent().unwrap_or(repo_root);
            for (line_no, line) in strip_fenced_code(&text) {
                for caps in md_link_re.captures_iter(&line) {
                    let raw_target = caps[1].trim();
                    if raw_target.is_empty()
                        || URL_PREFIXES.iter().any(|p| raw_target.starts_with(p))
                    {
                        continue;
                    }
                    let path_part = raw_target
                        .split('#')
                        .next()
                        .unwrap_or("")
                        .split('?')
                        .next()
                        .unwrap_or("");
                    if path_part.is_empty() {
                        continue;
                    }
                    let target = doc_parent.join(path_part);
                    if !target.exists() {
                        findings.push(ProjectFinding {
                            rule: "KNOWLEDGE_BROKEN_DOC_LINK".into(),
                            category: "knowledge".into(),
                            severity: "error".into(),
                            file: Some(rel_doc.clone()),
                            line: Some(line_no),
                            message: format!(
                                "Broken local link '{raw_target}' in {rel_doc}:{line_no}."
                            ),
                            remediation: format!(
                                "Fix or remove the link to '{raw_target}' in {rel_doc}:{line_no}."
                            ),
                            details: BTreeMap::new(),
                        });
                    }
                }
                if let Some(caps) = last_rev_re.captures(&line) {
                    if let Ok(reviewed_on) = NaiveDate::parse_from_str(&caps[1], "%Y-%m-%d") {
                        let age = (cur_date - reviewed_on).num_days();
                        if age > spec.orientation.max_review_age_days as i64 {
                            findings.push(ProjectFinding {
                                rule: "KNOWLEDGE_STALE_DOC_REVIEW".into(),
                                category: "knowledge".into(),
                                severity: "warning".into(),
                                file: Some(rel_doc.clone()),
                                line: Some(line_no),
                                message: format!(
                                    "Document '{rel_doc}' was last reviewed {age} days ago ({} > {}d).",
                                    reviewed_on, spec.orientation.max_review_age_days
                                ),
                                remediation: format!(
                                    "Review '{rel_doc}' against current code and update 'Last reviewed:'."
                                ),
                                details: BTreeMap::new(),
                            });
                        }
                    }
                }
            }
        }
    }

    // 4. Local verify vs CI parity
    if spec.verify.check_ci_parity {
        let ci_cmds = extract_ci_run_commands(repo_root);
        let verify_like: Vec<(String, String)> = ci_cmds
            .into_iter()
            .filter(|(_, c)| is_verify_like_ci_cmd(c))
            .collect();
        let declared_cmds: Vec<String> = spec
            .verify
            .commands
            .iter()
            .map(|c| c.cmd.trim().to_string())
            .collect();
        if !verify_like.is_empty() && declared_cmds.is_empty() {
            let mut details = BTreeMap::new();
            let cmds_only: Vec<&str> = verify_like.iter().map(|(_, c)| c.as_str()).collect();
            details.insert("ci_commands".into(), json!(cmds_only));
            findings.push(ProjectFinding {
                rule: "ADMISSION_NO_LOCAL_VERIFY_DECLARED".into(),
                category: "admission".into(),
                severity: "warning".into(),
                file: Some(verify_like[0].0.clone()),
                line: None,
                message: format!(
                    "CI defines {} verification command(s) but .birkin/config.yaml declares no verify.commands.",
                    verify_like.len()
                ),
                remediation:
                    "Declare canonical verify.commands in .birkin/config.yaml mirroring CI.".into(),
                details,
            });
        } else if !verify_like.is_empty() {
            let joined_local = declared_cmds.join("\n").to_lowercase();
            for (wf, ci_cmd) in verify_like {
                let tokens: Vec<&str> = ci_cmd.split_whitespace().collect();
                let sig = if tokens.len() >= 2 {
                    format!("{} {}", tokens[0], tokens[1]).to_lowercase()
                } else {
                    ci_cmd.to_lowercase()
                };
                if !joined_local.contains(&ci_cmd.to_lowercase()) && !joined_local.contains(&sig) {
                    findings.push(ProjectFinding {
                        rule: "ADMISSION_CI_LOCAL_DRIFT".into(),
                        category: "admission".into(),
                        severity: "warning".into(),
                        file: Some(wf.clone()),
                        line: None,
                        message: format!(
                            "CI command `{ci_cmd}` in {wf} is not covered by verify.commands."
                        ),
                        remediation: format!(
                            "Add `{ci_cmd}` (or an equivalent command) to verify.commands in .birkin/config.yaml so local and CI admission paths stay identical."
                        ),
                        details: BTreeMap::new(),
                    });
                }
            }
        }
    }

    // 5. Opt-in workflow contract input checks
    if !spec.workflow.enabled_contracts.is_empty() {
        for pin in &spec.workflow.toolchain_pin_files {
            if !repo_root.join(pin).is_file() {
                findings.push(ProjectFinding { rule: "WORKFLOW_MISSING_TOOLCHAIN_PIN".into(), category: "workflow".into(), severity: "warning".into(), file: Some(pin.clone()), line: None, message: format!("Configured toolchain pin file '{pin}' does not exist."), remediation: "Create the toolchain pin file or update workflow.toolchain_pin_files.".into(), details: BTreeMap::new() });
            }
        }
        if spec.workflow.contract_enabled("stage") && spec.workflow.test_runners.is_empty() {
            findings.push(ProjectFinding { rule: "WORKFLOW_NO_TEST_RUNNERS".into(), category: "workflow".into(), severity: "warning".into(), file: None, line: None, message: "Workflow contract 'stage' is enabled but workflow.test_runners is empty.".into(), remediation: "Declare at least one parser under workflow.test_runners in .birkin/config.yaml.".into(), details: BTreeMap::new() });
        }
        if let Some(ref wl) = spec.workflow.exclude_whitelist_path {
            if !repo_root.join(wl).is_file() {
                findings.push(ProjectFinding { rule: "WORKFLOW_MISSING_EXCLUDE_WHITELIST".into(), category: "workflow".into(), severity: "warning".into(), file: Some(wl.clone()), line: None, message: format!("Configured Sawyer exclude whitelist '{wl}' does not exist."), remediation: "Create the whitelist file or update workflow.exclude_whitelist_path.".into(), details: BTreeMap::new() });
            }
        }
    }

    let _ = found_entry;
    findings
}

pub fn build_readiness_scorecard(
    repo_root: &Path,
    spec: &ProjectSpec,
    guide_findings: &[ProjectFinding],
    sensor_findings: &[ProjectFinding],
    ledger_entries: &[Map<String, Value>],
) -> Value {
    let spec_file = find_spec_file(repo_root);
    let all_findings: Vec<&ProjectFinding> =
        guide_findings.iter().chain(sensor_findings.iter()).collect();

    let by_cat = |cat: &str| -> Vec<&ProjectFinding> {
        all_findings
            .iter()
            .copied()
            .filter(|f| f.category == cat)
            .collect()
    };

    let orient_f = by_cat("orientation");
    let know_f = by_cat("knowledge");
    let arch_f = by_cat("architecture");
    let adm_f = by_cat("admission");
    let inv_f = by_cat("invariant");

    let has_entry_doc = spec
        .orientation
        .entry_docs
        .iter()
        .any(|d| repo_root.join(d).is_file());
    let has_layers =
        !spec.architecture.layers.is_empty() || !spec.architecture.forbidden_imports.is_empty();
    let has_verify = !spec.verify.commands.is_empty();
    let pre_commit = repo_root.join(".git").join("hooks").join("pre-commit");
    let has_hooks = pre_commit.is_file()
        && fs::read_to_string(&pre_commit)
            .map(|t| t.contains("birkin"))
            .unwrap_or(false);

    let grade = |has_cap: bool, list: &[&ProjectFinding]| -> &'static str {
        if list.iter().any(|f| f.severity == "error") {
            "FAIL"
        } else if !has_cap || list.iter().any(|f| f.severity == "warning") {
            "WARN"
        } else {
            "PASS"
        }
    };

    let entry_present: Vec<&String> = spec
        .orientation
        .entry_docs
        .iter()
        .filter(|d| repo_root.join(d).is_file())
        .collect();
    let verify_names: Vec<&str> = spec.verify.commands.iter().map(|c| c.name.as_str()).collect();

    let has_proof_obligations = (spec.proofs.prove_architecture && has_layers)
        || !spec.proofs.state_machines.is_empty()
        || !spec.proofs.policies.is_empty()
        || !spec.proofs.lean_projects.is_empty();
    let prove_receipts = ledger_entries
        .iter()
        .filter(|e| {
            e.get("command").and_then(Value::as_str) == Some("prove")
                && e.get("outcome").and_then(Value::as_str) == Some("PASS")
        })
        .count();

    json!({
        "orientation": {
            "status": grade(has_entry_doc && spec_file.is_some(), &orient_f),
            "spec_path": spec_file.as_ref().map(|p| rel_posix(p, repo_root)),
            "entry_docs_present": entry_present,
            "findings": orient_f.len(),
        },
        "knowledge": {
            "status": grade(true, &know_f),
            "findings": know_f.len(),
        },
        "architecture": {
            "status": grade(has_layers, &arch_f),
            "layers_declared": spec.architecture.layers.len(),
            "forbidden_import_rules": spec.architecture.forbidden_imports.len(),
            "findings": arch_f.len(),
        },
        "admission": {
            "status": grade(has_verify, &adm_f),
            "verify_commands": verify_names,
            "findings": adm_f.len(),
        },
        "sensors": {
            "status": grade(true, &inv_f),
            "custom_regex_rules": spec.invariants.custom_regex_rules.len(),
            "semantic_rules": spec.semantic.rules.len(),
            "semantic_enabled": spec.semantic.enabled,
            "findings": inv_f.len(),
        },
        "proofs": {
            "status": if has_proof_obligations { "PASS" } else { "WARN" },
            "prove_architecture": spec.proofs.prove_architecture && has_layers,
            "state_machines": spec.proofs.state_machines.len(),
            "policies": spec.proofs.policies.len(),
            "lean_projects": spec.proofs.lean_projects.len(),
            "passing_prove_receipts": prove_receipts,
        },
        "observability": {
            "status": if !ledger_entries.is_empty() || has_hooks { "PASS" } else { "WARN" },
            "git_pre_commit_wired": has_hooks,
            "receipt_count": ledger_entries.len(),
        },
        "workflow": {
            "status": if spec.workflow.enabled_contracts.is_empty() { "OPT_IN" } else { grade(true, &by_cat("workflow")) },
            "enabled_contracts": spec.workflow.enabled_contracts,
            "inputs_configured": {
                "toolchain_pin_files": spec.workflow.toolchain_pin_files,
                "missing_toolchain_pin_files": spec.workflow.toolchain_pin_files.iter().filter(|p| !repo_root.join(p).is_file()).collect::<Vec<_>>(),
                "test_runners": spec.workflow.test_runners.iter().map(|r| &r.name).collect::<Vec<_>>(),
                "exclude_whitelist_path": spec.workflow.exclude_whitelist_path,
                "exclude_whitelist_exists": spec.workflow.exclude_whitelist_path.as_ref().map(|p| repo_root.join(p).is_file()),
                "require_plan_receipt": spec.workflow.require_plan_receipt,
            },
            "findings": by_cat("workflow").len(),
        },
    })
}
