//! Deterministic computational sensors for multi-language repositories.
//!
//! Enforces architecture layer DAG acyclicity & boundaries, forbidden imports, file line budgets,
//! secret leaks, debug leftovers, English-prose invariants, custom regex rules, and verify gates.

use crate::glob::{fnmatch, matches_any};
use crate::imports_parser::{detect_go_module, extract_imports_for_file};
use crate::project_models::{LayerSpec, ProjectFinding, ProjectSpec};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use walkdir::WalkDir;

const CODE_EXTENSIONS: &[&str] = &[
    ".py", ".go", ".rs", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
];
const TEXT_EXTENSIONS: &[&str] = &[
    ".py", ".go", ".rs", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".lean", ".md", ".yaml",
    ".yml", ".toml", ".json", ".sh", ".bash", ".zsh", ".txt",
];

fn rel_posix(path: &Path, root: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    Some(
        rel.components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/"),
    )
}

fn layer_for_path<'a>(rel: &str, layers: &'a [LayerSpec]) -> Option<&'a LayerSpec> {
    layers.iter().find(|l| matches_any(rel, &l.paths))
}

/// Check whether the declared layer dependency graph is a DAG (no directed cycles).
pub fn find_layer_dag_cycles(layers: &[LayerSpec]) -> Vec<String> {
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for layer in layers {
        adj.insert(
            layer.name.as_str(),
            layer.allowed_dependencies.iter().map(String::as_str).collect(),
        );
    }
    // 0 = unvisited, 1 = visiting, 2 = visited
    let mut state: HashMap<&str, u8> = HashMap::new();
    let mut cyclic_nodes: Vec<String> = Vec::new();

    fn dfs<'a>(
        node: &'a str,
        adj: &HashMap<&'a str, Vec<&'a str>>,
        state: &mut HashMap<&'a str, u8>,
        cyclic: &mut Vec<String>,
    ) -> bool {
        state.insert(node, 1);
        let mut found = false;
        if let Some(neighbors) = adj.get(node) {
            for &next in neighbors {
                match state.get(next).copied().unwrap_or(0) {
                    1 => {
                        cyclic.push(format!("{node} -> {next}"));
                        found = true;
                    }
                    0 if dfs(next, adj, state, cyclic) => {
                        found = true;
                    }
                    _ => {}
                }
            }
        }
        state.insert(node, 2);
        found
    }

    for layer in layers {
        let name = layer.name.as_str();
        if state.get(name).copied().unwrap_or(0) == 0 {
            dfs(name, &adj, &mut state, &mut cyclic_nodes);
        }
    }
    cyclic_nodes
}

pub fn collect_target_files(
    repo_root: &Path,
    spec: &ProjectSpec,
    files: Option<&[PathBuf]>,
) -> Vec<PathBuf> {
    let resolved_root = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let excludes = &spec.project.exclude_globs;

    if let Some(explicit) = files {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for f in explicit {
            let candidate = if f.is_absolute() {
                f.clone()
            } else {
                resolved_root.join(f)
            };
            let canon = match fs::canonicalize(&candidate) {
                Ok(c) if c.is_file() => c,
                _ => continue,
            };
            let Some(rel) = rel_posix(&canon, &resolved_root) else {
                continue;
            };
            if matches_any(&rel, excludes) {
                continue;
            }
            if seen.insert(canon.clone()) {
                out.push(canon);
            }
        }
        out.sort();
        return out;
    }

    let mut out = Vec::new();
    let walker = WalkDir::new(&resolved_root)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            let Some(rel) = rel_posix(entry.path(), &resolved_root) else {
                return false;
            };
            if entry.file_type().is_dir() {
                let probe = format!("{rel}/x");
                return !matches_any(&rel, excludes) && !matches_any(&probe, excludes);
            }
            !matches_any(&rel, excludes)
        });

    for entry in walker.filter_map(Result::ok) {
        if entry.file_type().is_file() {
            out.push(entry.into_path());
        }
    }
    out
}

fn is_comment_line(ext: &str, line: &str) -> bool {
    let stripped = line.trim_start();
    if matches!(ext, ".py" | ".sh" | ".bash" | ".zsh" | ".yaml" | ".yml" | ".toml") {
        return stripped.starts_with('#');
    }
    if matches!(
        ext,
        ".go" | ".rs" | ".ts" | ".tsx" | ".js" | ".jsx" | ".mjs" | ".cjs"
    ) {
        return stripped.starts_with("//") || stripped.starts_with("/*") || stripped.starts_with('*');
    }
    if ext == ".lean" {
        return stripped.starts_with("--") || stripped.starts_with("/-");
    }
    false
}

fn has_cjk(s: &str) -> bool {
    s.chars().any(|c| {
        matches!(
            c as u32,
            0x3040..=0x309F | 0x30A0..=0x30FF | 0x4E00..=0x9FFF
        )
    })
}

pub fn run_project_sensors(
    repo_root: &Path,
    spec: &ProjectSpec,
    files: Option<&[PathBuf]>,
) -> (Vec<ProjectFinding>, Vec<String>) {
    let resolved_root = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let targets = collect_target_files(&resolved_root, spec, files);
    let mut findings = Vec::new();
    let mut checked_rel = Vec::new();
    let go_mod = detect_go_module(&resolved_root);

    // 0. Formally required DAG acyclicity check on declared layers
    for cycle_edge in find_layer_dag_cycles(&spec.architecture.layers) {
        findings.push(ProjectFinding {
            rule: "ARCH_LAYER_DAG_CYCLE".into(),
            category: "architecture".into(),
            severity: "error".into(),
            file: None,
            line: None,
            message: format!("Declared architecture.layers graph contains a cycle at edge {cycle_edge}."),
            remediation: "Remove cyclic allowed_dependencies entries so layers form a strict DAG.".into(),
            details: BTreeMap::new(),
        });
    }

    let secret_patterns: Vec<(&str, Regex)> = vec![
        (
            "PRIVATE_KEY_HEADER",
            Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----").unwrap(),
        ),
        ("AWS_ACCESS_KEY", Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap()),
        (
            "GITHUB_PAT",
            Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b").unwrap(),
        ),
        (
            "ANTHROPIC_KEY",
            Regex::new(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b").unwrap(),
        ),
        (
            "OPENAI_KEY",
            Regex::new(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b").unwrap(),
        ),
        (
            "SLACK_TOKEN",
            Regex::new(r"\bxox[baprs]-[0-9]{10,}-[A-Za-z0-9\-]{10,}\b").unwrap(),
        ),
    ];

    let py_debug_re = Regex::new(r"\b(?:breakpoint\(\)|pdb\.set_trace\(\))").unwrap();
    let js_debug_re = Regex::new(r"^\s*debugger\s*;?\s*$").unwrap();
    let rs_debug_re = Regex::new(r"\bdbg!\s*\(").unwrap();

    let compiled_custom: Vec<_> = spec
        .invariants
        .custom_regex_rules
        .iter()
        .filter_map(|r| Regex::new(&r.pattern).ok().map(|re| (r, re)))
        .collect();

    for path in targets {
        let Some(rel) = rel_posix(&path, &resolved_root) else {
            continue;
        };
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| format!(".{}", s.to_lowercase()))
            .unwrap_or_default();
        checked_rel.push(rel.clone());

        if !ext.is_empty() && !TEXT_EXTENSIONS.contains(&ext.as_str()) {
            continue;
        }
        let Ok(raw_bytes) = fs::read(&path) else {
            continue;
        };
        let probe_len = raw_bytes.len().min(4096);
        if raw_bytes[..probe_len].contains(&0u8) {
            continue;
        }
        let text = String::from_utf8_lossy(&raw_bytes);
        let lines: Vec<&str> = text.lines().collect();

        // 1. File line budget (code files only)
        if CODE_EXTENSIONS.contains(&ext.as_str())
            && lines.len() > spec.architecture.max_file_lines
            && !matches_any(&rel, &spec.architecture.file_line_exemptions)
        {
            findings.push(ProjectFinding {
                rule: "ARCH_FILE_TOO_LARGE".into(),
                category: "architecture".into(),
                severity: "warning".into(),
                file: Some(rel.clone()),
                line: Some(lines.len()),
                message: format!(
                    "{rel} has {} lines (budget: {}).",
                    lines.len(),
                    spec.architecture.max_file_lines
                ),
                remediation: format!(
                    "Split {rel} along cohesive responsibility boundaries or add a justified exemption in architecture.file_line_exemptions."
                ),
                details: BTreeMap::new(),
            });
        }

        // 2. Architecture layer DAG & forbidden imports
        if CODE_EXTENSIONS.contains(&ext.as_str())
            && (!spec.architecture.layers.is_empty()
                || !spec.architecture.forbidden_imports.is_empty())
        {
            let edges = extract_imports_for_file(&path, &resolved_root, go_mod.as_deref());
            let src_layer = layer_for_path(&rel, &spec.architecture.layers);

            for edge in edges {
                if let (Some(sl), Some(ref resolved_dst)) = (src_layer, &edge.resolved_path) {
                    if let Some(dl) = layer_for_path(resolved_dst, &spec.architecture.layers) {
                        if dl.name != sl.name
                            && !sl.allowed_dependencies.iter().any(|a| a == &dl.name)
                        {
                            let allowed = if sl.allowed_dependencies.is_empty() {
                                "none".to_string()
                            } else {
                                sl.allowed_dependencies.join(", ")
                            };
                            let rem = if sl.remediation.is_empty() {
                                format!(
                                    "Layer '{}' may only depend on: {allowed}. Move shared types to a lower layer.",
                                    sl.name
                                )
                            } else {
                                sl.remediation.clone()
                            };
                            let mut details = BTreeMap::new();
                            details.insert("source_layer".into(), json!(sl.name));
                            details.insert("target_layer".into(), json!(dl.name));
                            details.insert("target_file".into(), json!(resolved_dst));
                            details.insert("import".into(), json!(edge.raw));
                            findings.push(ProjectFinding {
                                rule: "ARCH_LAYER_VIOLATION".into(),
                                category: "architecture".into(),
                                severity: "error".into(),
                                file: Some(rel.clone()),
                                line: Some(edge.line),
                                message: format!(
                                    "Layer '{}' ({rel}) imports layer '{}' ({resolved_dst}) via `{}`.",
                                    sl.name, dl.name, edge.raw
                                ),
                                remediation: rem,
                                details,
                            });
                        }
                    }
                }

                for frule in &spec.architecture.forbidden_imports {
                    if !matches_any(&rel, &frule.from_globs) {
                        continue;
                    }
                    let target_matched = frule.forbid_patterns.iter().any(|pat| {
                        fnmatch(&edge.raw, pat)
                            || edge
                                .resolved_path
                                .as_deref()
                                .map(|rp| fnmatch(rp, pat))
                                .unwrap_or(false)
                    });
                    if target_matched {
                        let mut details = BTreeMap::new();
                        details.insert("rule_id".into(), json!(frule.id));
                        details.insert("import".into(), json!(edge.raw));
                        findings.push(ProjectFinding {
                            rule: format!("ARCH_FORBIDDEN_IMPORT:{}", frule.id),
                            category: "architecture".into(),
                            severity: "error".into(),
                            file: Some(rel.clone()),
                            line: Some(edge.line),
                            message: format!("{} (found import `{}`)", frule.message, edge.raw),
                            remediation: frule.remediation.clone(),
                            details,
                        });
                    }
                }
            }
        }

        // 3. Hardcoded secret scan
        if spec.invariants.forbid_secrets
            && !matches_any(&rel, &spec.invariants.secret_exempt_globs)
        {
            for (idx, line) in lines.iter().enumerate() {
                for (label, pat) in &secret_patterns {
                    if pat.is_match(line) {
                        let mut details = BTreeMap::new();
                        details.insert("secret_type".into(), json!(label));
                        findings.push(ProjectFinding {
                            rule: format!("INVARIANT_SECRET_LEAK:{label}"),
                            category: "invariant".into(),
                            severity: "error".into(),
                            file: Some(rel.clone()),
                            line: Some(idx + 1),
                            message: format!(
                                "Potential hardcoded secret ({label}) detected in {rel}:{}.",
                                idx + 1
                            ),
                            remediation: "Remove the secret immediately, rotate credentials if committed, and read from environment variables instead.".into(),
                            details,
                        });
                    }
                }
            }
        }

        // 4. Debug leftovers
        if spec.invariants.forbid_debug_leftovers {
            for (idx, line) in lines.iter().enumerate() {
                let hit = if ext == ".py" && py_debug_re.is_match(line) {
                    Some("PYTHON_BREAKPOINT")
                } else if matches!(
                    ext.as_str(),
                    ".js" | ".jsx" | ".ts" | ".tsx" | ".mjs" | ".cjs"
                ) && js_debug_re.is_match(line)
                {
                    Some("JS_DEBUGGER")
                } else if ext == ".rs" && rs_debug_re.is_match(line) {
                    Some("RUST_DBG_MACRO")
                } else {
                    None
                };
                if let Some(label) = hit {
                    findings.push(ProjectFinding {
                        rule: format!("INVARIANT_DEBUG_LEFTOVER:{label}"),
                        category: "invariant".into(),
                        severity: "error".into(),
                        file: Some(rel.clone()),
                        line: Some(idx + 1),
                        message: format!("Debug leftover ({label}) in {rel}:{}.", idx + 1),
                        remediation: "Remove debug breakpoints before committing.".into(),
                        details: BTreeMap::new(),
                    });
                }
            }
        }

        // 5. English-prose invariant
        if spec.invariants.english_prose_only
            && !matches_any(&rel, &spec.invariants.prose_exempt_globs)
        {
            let is_md = ext == ".md";
            for (idx, line) in lines.iter().enumerate() {
                if (is_md || is_comment_line(&ext, line)) && has_cjk(line) {
                    findings.push(ProjectFinding {
                        rule: "INVARIANT_NON_ENGLISH_PROSE".into(),
                        category: "invariant".into(),
                        severity: "error".into(),
                        file: Some(rel.clone()),
                        line: Some(idx + 1),
                        message: format!("Non-English prose detected in {rel}:{}.", idx + 1),
                        remediation: "Keep repository documentation and inline comments in English (or exempt intentional multilingual test fixtures in invariants.prose_exempt_globs).".into(),
                        details: BTreeMap::new(),
                    });
                    break;
                }
            }
        }

        // 6. Custom regex rules
        for (rule, pat) in &compiled_custom {
            if !matches_any(&rel, &rule.globs) || matches_any(&rel, &rule.exclude_globs) {
                continue;
            }
            for (idx, line) in lines.iter().enumerate() {
                if pat.is_match(line) {
                    let mut details = BTreeMap::new();
                    details.insert("rule_id".into(), json!(rule.id));
                    findings.push(ProjectFinding {
                        rule: format!("CUSTOM_REGEX:{}", rule.id),
                        category: "invariant".into(),
                        severity: rule.severity.clone(),
                        file: Some(rel.clone()),
                        line: Some(idx + 1),
                        message: rule.message.clone(),
                        remediation: rule.remediation.clone(),
                        details,
                    });
                }
            }
        }
    }

    (findings, checked_rel)
}

fn tail_chars(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        s.to_string()
    } else {
        s.chars().skip(count - max_chars).collect()
    }
}

pub fn run_verify_commands(
    repo_root: &Path,
    spec: &ProjectSpec,
) -> (Vec<ProjectFinding>, Vec<Value>) {
    let mut findings = Vec::new();
    let mut results = Vec::new();

    for vc in &spec.verify.commands {
        let t0 = Instant::now();
        let output = Command::new("sh")
            .args(["-c", &vc.cmd])
            .current_dir(repo_root)
            .output();
        let dur_ms = t0.elapsed().as_millis() as u64;

        match output {
            Ok(out) => {
                let code = out.status.code().unwrap_or(1);
                let ok = out.status.success();
                let combined = format!(
                    "{}\n{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                let tail = tail_chars(combined.trim(), 1500);
                results.push(json!({
                    "name": vc.name, "cmd": vc.cmd, "kind": vc.kind,
                    "exit_code": code, "duration_ms": dur_ms,
                    "status": if ok { "PASS" } else { "FAIL" }, "output_tail": tail,
                }));
                if !ok {
                    let mut details = BTreeMap::new();
                    details.insert("exit_code".into(), json!(code));
                    details.insert("output_tail".into(), json!(tail_chars(&tail, 600)));
                    findings.push(ProjectFinding {
                        rule: format!("ADMISSION_VERIFY_FAILED:{}", vc.name),
                        category: "admission".into(),
                        severity: "error".into(),
                        file: None,
                        line: None,
                        message: format!(
                            "Canonical verify command '{}' (`{}`) failed with exit {code}.",
                            vc.name, vc.cmd
                        ),
                        remediation: format!(
                            "Run `{}` locally, fix the reported failures, and re-run `birkin check --run-verify`.",
                            vc.cmd
                        ),
                        details,
                    });
                }
            }
            Err(err) => {
                results.push(json!({
                    "name": vc.name, "cmd": vc.cmd, "kind": vc.kind,
                    "exit_code": 127, "duration_ms": dur_ms,
                    "status": "ERROR", "output_tail": err.to_string(),
                }));
                findings.push(ProjectFinding {
                    rule: format!("ADMISSION_VERIFY_FAILED:{}", vc.name),
                    category: "admission".into(),
                    severity: "error".into(),
                    file: None,
                    line: None,
                    message: format!("Failed spawning verify command '{}': {err}", vc.name),
                    remediation: format!("Ensure `{}` is executable in PATH.", vc.cmd),
                    details: BTreeMap::new(),
                });
            }
        }
    }

    (findings, results)
}

pub fn evaluate_regex_rules(spec: &ProjectSpec) -> Value {
    let mut report = Vec::new();
    let mut all_ok = true;
    for rule in &spec.invariants.custom_regex_rules {
        let (fps, fns, compile_err) = match Regex::new(&rule.pattern) {
            Ok(pat) => (
                rule.examples_pass.iter().filter(|ex| pat.is_match(ex)).cloned().collect::<Vec<_>>(),
                rule.examples_fail.iter().filter(|ex| !pat.is_match(ex)).cloned().collect::<Vec<_>>(),
                None,
            ),
            Err(err) => (Vec::new(), Vec::new(), Some(err.to_string())),
        };
        let missing_fixtures = rule.examples_pass.is_empty() || rule.examples_fail.is_empty();
        let passed = compile_err.is_none() && fps.is_empty() && fns.is_empty() && !missing_fixtures;
        if !passed {
            all_ok = false;
        }
        report.push(json!({
            "id": rule.id, "kind": "regex",
            "status": if passed { "PASS" } else { "FAIL" },
            "examples_pass": rule.examples_pass.len(),
            "examples_fail": rule.examples_fail.len(),
            "false_positives": fps, "false_negatives": fns,
            "missing_fixtures": missing_fixtures, "compile_error": compile_err,
        }));
    }
    json!({"status": if all_ok { "PASS" } else { "FAIL" }, "rules": report})
}
