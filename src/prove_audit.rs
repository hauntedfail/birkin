//! Lean 4 process runner, `#print axioms` kernel auditor, and custom Lean project verifier.

use crate::constants::{EXIT_PASS, EXIT_STATIC, EXIT_TOOL_ERROR};
use crate::project_models::{ProjectFinding, ProjectSpec};
use crate::proof_models::LeanProjectSpec;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

pub const STANDARD_AXIOMS: &[&str] = &["propext", "Classical.choice", "Quot.sound"];

pub enum ProcResult {
    Finished {
        code: i32,
        ok: bool,
        stdout: String,
        stderr: String,
    },
    TimedOut {
        stdout: String,
        stderr: String,
    },
    NotFound(String),
    SpawnError(String),
}

pub fn tail_chars(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        s.to_string()
    } else {
        s.chars().skip(count - max_chars).collect()
    }
}

pub fn summarize_lean_errors(stdout: &str, stderr: &str, max_chars: usize) -> String {
    let combined = format!("{stdout}\n{stderr}");
    let err_lines: Vec<&str> = combined
        .lines()
        .filter(|l| l.contains("error:") || l.contains("failed"))
        .take(6)
        .collect();
    if !err_lines.is_empty() {
        tail_chars(&err_lines.join(" | "), max_chars)
    } else {
        tail_chars(combined.trim(), max_chars)
    }
}

pub fn run_lean_process(
    program: &str,
    args: &[&str],
    cwd: &Path,
    stdin_payload: Option<&str>,
    timeout_secs: u64,
) -> ProcResult {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin_payload.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    #[cfg(unix)]
    cmd.process_group(0);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return ProcResult::NotFound(format!("Required executable '{program}' not found in PATH"));
        }
        Err(err) => return ProcResult::SpawnError(err.to_string()),
    };

    if let Some(input) = stdin_payload {
        if let Some(mut sin) = child.stdin.take() {
            let _ = sin.write_all(input.as_bytes());
        }
    }

    let out_h = child.stdout.take().map(|mut p| {
        thread::spawn(move || {
            let mut b = Vec::new();
            let _ = p.read_to_end(&mut b);
            b
        })
    });
    let err_h = child.stderr.take().map(|mut p| {
        thread::spawn(move || {
            let mut b = Vec::new();
            let _ = p.read_to_end(&mut b);
            b
        })
    });

    let limit = Duration::from_secs(timeout_secs.max(1));
    let started = Instant::now();
    let mut timed_out = false;
    let mut code = 1;
    let mut ok = false;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                code = status.code().unwrap_or(1);
                ok = status.success();
                break;
            }
            Ok(None) => {
                if started.elapsed() >= limit {
                    timed_out = true;
                    #[cfg(unix)]
                    unsafe {
                        libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                thread::sleep(Duration::from_millis(15));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }
    }

    let stdout = String::from_utf8_lossy(&out_h.and_then(|h| h.join().ok()).unwrap_or_default())
        .into_owned();
    let stderr = String::from_utf8_lossy(&err_h.and_then(|h| h.join().ok()).unwrap_or_default())
        .into_owned();

    if timed_out {
        ProcResult::TimedOut { stdout, stderr }
    } else {
        ProcResult::Finished {
            code,
            ok,
            stdout,
            stderr,
        }
    }
}

/// Parse Lean 4 `#print axioms` output (including multi-line wrapped axiom lists)
/// into a theorem -> axiom list map.
pub fn parse_print_axioms(stdout: &str) -> BTreeMap<String, Vec<String>> {
    let re_none = Regex::new(r"(?m)^'([^']+)' does not depend on any axioms\s*$").unwrap();
    let re_some =
        Regex::new(r"(?ms)^'([^']+)' depends on axioms:\s*\[([^\]]*)\]").unwrap();
    let mut map = BTreeMap::new();
    for caps in re_none.captures_iter(stdout) {
        map.insert(caps[1].to_string(), Vec::new());
    }
    for caps in re_some.captures_iter(stdout) {
        let axioms: Vec<String> = caps[2]
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        map.insert(caps[1].to_string(), axioms);
    }
    map
}

pub fn audit_axioms(
    expected: &[String],
    observed: &BTreeMap<String, Vec<String>>,
    require_standard_only: bool,
    findings: &mut Vec<ProjectFinding>,
) {
    for thm in expected {
        let Some(axioms) = observed.get(thm) else {
            findings.push(ProjectFinding {
                rule: "PROOF_THEOREM_UNAUDITED".into(),
                category: "proof".into(),
                severity: "error".into(),
                file: None,
                line: None,
                message: format!("Expected theorem '{thm}' missing from Lean #print axioms output."),
                remediation: "Ensure the theorem compiles and matches the declared fully-qualified name.".into(),
                details: BTreeMap::new(),
            });
            continue;
        };
        if !require_standard_only {
            continue;
        }
        let forbidden: Vec<&str> = axioms
            .iter()
            .map(String::as_str)
            .filter(|ax| !STANDARD_AXIOMS.contains(ax))
            .collect();
        if !forbidden.is_empty() {
            findings.push(ProjectFinding {
                rule: "PROOF_FORBIDDEN_AXIOM".into(),
                category: "proof".into(),
                severity: "error".into(),
                file: None,
                line: None,
                message: format!(
                    "Theorem '{thm}' depends on non-standard axiom(s): [{}].",
                    forbidden.join(", ")
                ),
                remediation: "Remove `sorry`, `native_decide`, or custom `axiom` declarations so proofs rely only on Lean's standard kernel axioms.".into(),
                details: BTreeMap::new(),
            });
        }
    }
}

fn rel_posix(path: &Path, root: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    Some(
        rel.components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/"),
    )
}

pub fn strip_lean_comments(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut depth = 0usize;
    let mut in_str = false;

    while i < n {
        let ch = chars[i];
        if depth > 0 {
            if ch == '/' && i + 1 < n && chars[i + 1] == '-' {
                depth += 1;
                i += 2;
            } else if ch == '-' && i + 1 < n && chars[i + 1] == '/' {
                depth -= 1;
                i += 2;
            } else {
                if ch == '\n' {
                    out.push('\n');
                }
                i += 1;
            }
            continue;
        }
        if in_str {
            if ch == '\\' && i + 1 < n {
                i += 2;
                continue;
            }
            if ch == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if ch == '"' {
            in_str = true;
            out.push(' ');
            i += 1;
            continue;
        }
        if ch == '/' && i + 1 < n && chars[i + 1] == '-' {
            depth = 1;
            i += 2;
            continue;
        }
        if ch == '-' && i + 1 < n && chars[i + 1] == '-' {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        out.push(ch);
        i += 1;
    }
    out
}

pub fn scan_lean_project_shortcuts(
    repo_root: &Path,
    project_dir: &Path,
    require_zero_sorry: bool,
    require_standard_axioms_only: bool,
) -> Vec<ProjectFinding> {
    let mut findings = Vec::new();
    let sorry_re = Regex::new(r"\b(?:sorry|admit)\b").unwrap();
    let axiom_re = Regex::new(r"^\s*(?:(?:private|protected|local)\s+)*axiom\b").unwrap();

    for entry in WalkDir::new(project_dir)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| e.file_name().to_str() != Some(".lake"))
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.path().extension().and_then(|s| s.to_str()) != Some("lean") {
            continue;
        }
        let Ok(raw) = fs::read_to_string(entry.path()) else {
            continue;
        };
        let cleaned = strip_lean_comments(&raw);
        let rel = rel_posix(entry.path(), repo_root)
            .unwrap_or_else(|| entry.path().to_string_lossy().into_owned());
        for (idx, line) in cleaned.lines().enumerate() {
            if require_zero_sorry && sorry_re.is_match(line) {
                findings.push(ProjectFinding {
                    rule: "PROOF_LEAN_SORRY".into(),
                    category: "proof".into(),
                    severity: "error".into(),
                    file: Some(rel.clone()),
                    line: Some(idx + 1),
                    message: format!("Unproved `sorry`/`admit` found in {rel}:{}.", idx + 1),
                    remediation: "Complete the formal proof without `sorry` or `admit`.".into(),
                    details: BTreeMap::new(),
                });
            }
            if require_standard_axioms_only && axiom_re.is_match(line) {
                findings.push(ProjectFinding {
                    rule: "PROOF_CUSTOM_AXIOM_DECL".into(),
                    category: "proof".into(),
                    severity: "error".into(),
                    file: Some(rel.clone()),
                    line: Some(idx + 1),
                    message: format!("Custom `axiom` declaration found in {rel}:{}.", idx + 1),
                    remediation: "Prove the statement as a theorem instead of postulating a custom `axiom`.".into(),
                    details: BTreeMap::new(),
                });
            }
        }
    }
    findings
}

pub fn verify_lean_project(
    repo_root: &Path,
    lp: &LeanProjectSpec,
    spec: &ProjectSpec,
    axioms_out: &mut BTreeMap<String, Vec<String>>,
    theorems_out: &mut Vec<String>,
) -> (i32, Vec<ProjectFinding>, Value) {
    let dir = repo_root.join(&lp.dir);
    let mut findings = Vec::new();
    if !dir.is_dir()
        || (!dir.join("lakefile.toml").is_file() && !dir.join("lakefile.lean").is_file())
    {
        findings.push(ProjectFinding {
            rule: "PROOF_LEAN_PROJECT_MISSING".into(),
            category: "proof".into(),
            severity: "error".into(),
            file: Some(lp.dir.clone()),
            line: None,
            message: format!(
                "Lean project '{}' directory '{}' lacks lakefile.toml or lakefile.lean.",
                lp.name, lp.dir
            ),
            remediation: "Fix proofs.lean_projects[].dir or initialize the Lake project.".into(),
            details: BTreeMap::new(),
        });
        return (
            EXIT_STATIC,
            findings,
            json!({"name": lp.name, "dir": lp.dir, "status": "FAIL"}),
        );
    }

    findings.extend(scan_lean_project_shortcuts(
        repo_root,
        &dir,
        spec.proofs.require_zero_sorry,
        spec.proofs.require_standard_axioms_only,
    ));

    let t0 = Instant::now();
    let mut code = EXIT_PASS;
    match run_lean_process("lake", &["build"], &dir, None, spec.proofs.timeout_seconds) {
        ProcResult::Finished { ok: true, .. } => {}
        ProcResult::Finished {
            code: ec,
            stdout,
            stderr,
            ..
        } => {
            code = EXIT_STATIC;
            findings.push(ProjectFinding {
                rule: format!("PROOF_LEAN_BUILD_FAIL:{}", lp.name),
                category: "proof".into(),
                severity: "error".into(),
                file: Some(lp.dir.clone()),
                line: None,
                message: format!(
                    "`lake build` failed for '{}' (exit {ec}): {}",
                    lp.name,
                    tail_chars(format!("{stdout}\n{stderr}").trim(), 400)
                ),
                remediation: format!("Fix Lean proof errors in '{}'.", lp.dir),
                details: BTreeMap::new(),
            });
        }
        ProcResult::TimedOut { .. } => {
            code = EXIT_STATIC;
            findings.push(ProjectFinding {
                rule: format!("PROOF_LEAN_TIMEOUT:{}", lp.name),
                category: "proof".into(),
                severity: "error".into(),
                file: Some(lp.dir.clone()),
                line: None,
                message: format!(
                    "`lake build` timed out after {}s for '{}'.",
                    spec.proofs.timeout_seconds, lp.name
                ),
                remediation: "Simplify slow proof steps or raise proofs.timeout_seconds.".into(),
                details: BTreeMap::new(),
            });
        }
        ProcResult::NotFound(msg) | ProcResult::SpawnError(msg) => {
            code = EXIT_TOOL_ERROR;
            findings.push(ProjectFinding {
                rule: "PROOF_LEAN_TOOLCHAIN_MISSING".into(),
                category: "proof".into(),
                severity: "error".into(),
                file: None,
                line: None,
                message: msg,
                remediation: "Install Lean 4 (`elan` / `lake`) and ensure `lake` is on PATH.".into(),
                details: BTreeMap::new(),
            });
        }
    }

    if code == EXIT_PASS && !lp.theorems.is_empty() {
        let mut script = String::new();
        for m in &lp.modules {
            script.push_str(&format!("import {m}\n"));
        }
        for thm in &lp.theorems {
            script.push_str(&format!("#print axioms {thm}\n"));
        }
        match run_lean_process(
            "lake",
            &["env", "lean", "--stdin"],
            &dir,
            Some(&script),
            spec.proofs.timeout_seconds,
        ) {
            ProcResult::Finished {
                ok: true, stdout, ..
            } => {
                let parsed = parse_print_axioms(&stdout);
                audit_axioms(
                    &lp.theorems,
                    &parsed,
                    spec.proofs.require_standard_axioms_only,
                    &mut findings,
                );
                axioms_out.extend(parsed);
                theorems_out.extend(lp.theorems.iter().cloned());
            }
            ProcResult::Finished { stdout, stderr, .. } => {
                code = EXIT_STATIC;
                findings.push(ProjectFinding {
                    rule: format!("PROOF_AXIOM_AUDIT_FAIL:{}", lp.name),
                    category: "proof".into(),
                    severity: "error".into(),
                    file: Some(lp.dir.clone()),
                    line: None,
                    message: format!(
                        "Axiom audit failed for '{}': {}",
                        lp.name,
                        tail_chars(format!("{stdout}\n{stderr}").trim(), 400)
                    ),
                    remediation: "Verify proofs.lean_projects[].modules and theorem names.".into(),
                    details: BTreeMap::new(),
                });
            }
            ProcResult::TimedOut { .. } => {
                code = EXIT_STATIC;
                findings.push(ProjectFinding {
                    rule: format!("PROOF_AXIOM_AUDIT_TIMEOUT:{}", lp.name),
                    category: "proof".into(),
                    severity: "error".into(),
                    file: Some(lp.dir.clone()),
                    line: None,
                    message: format!("Axiom audit timed out for '{}'.", lp.name),
                    remediation: "Raise proofs.timeout_seconds.".into(),
                    details: BTreeMap::new(),
                });
            }
            ProcResult::NotFound(msg) | ProcResult::SpawnError(msg) => {
                code = EXIT_TOOL_ERROR;
                findings.push(ProjectFinding {
                    rule: "PROOF_LEAN_TOOLCHAIN_MISSING".into(),
                    category: "proof".into(),
                    severity: "error".into(),
                    file: None,
                    line: None,
                    message: msg,
                    remediation: "Install Lean 4 (`elan` / `lake`).".into(),
                    details: BTreeMap::new(),
                });
            }
        }
    }

    if findings.iter().any(|f| f.severity == "error") && code == EXIT_PASS {
        code = EXIT_STATIC;
    }
    let meta = json!({
        "name": lp.name,
        "dir": lp.dir,
        "status": if code == EXIT_PASS { "PASS" } else { "FAIL" },
        "theorems_audited": lp.theorems.len(),
        "duration_ms": t0.elapsed().as_millis() as u64,
    });
    (code, findings, meta)
}
