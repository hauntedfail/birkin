//! File-scope containment, symlink escape detection, and concurrent write-disjointness engine.
//!
//! Rust performs OS realpath/symlink containment, rule matching, and Git diff collection;
//! all path-admission and concurrent write-disjointness verdicts are computed directly by
//! the Lean 4 decision kernel (`BirkinSpec.ScopeContract`).

use crate::lean_kernel::{eval_scope, KernelPathDecision, KernelScopeRequest};
use crate::project_models::ProjectFinding;
use crate::workflow_models::{ActiveUnitRecord, PlanTaskSpec};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathAuthority {
    SourceEdit,
    VerificationOutput,
}

impl PathAuthority {
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::SourceEdit => "source",
            Self::VerificationOutput => "verification_output",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathDecision {
    pub path: String,
    pub inside_root: bool,
    pub matched_allowed: bool,
    pub matched_forbidden: bool,
    pub matched_verify_output: bool,
    pub admitted: bool,
}

#[derive(Debug, Clone)]
pub struct ScopeOutcome {
    pub admitted: bool,
    pub decisions: Vec<PathDecision>,
    pub overlapping_writes: Vec<String>,
    pub findings: Vec<ProjectFinding>,
    pub kernel_error: Option<String>,
}

/// Match a repo-relative POSIX spelling against an exact file or directory rule.
pub fn scoped_entry_matches(rel_posix: &str, scoped: &str) -> bool {
    let rel = rel_posix.trim_start_matches("./");
    let rule = scoped.trim_start_matches("./");
    if let Some(dir) = rule.strip_suffix('/') {
        rel == dir || rel.starts_with(rule)
    } else {
        rel == rule
    }
}

struct ScopePath {
    lexical: String,
    canonical: String,
}

fn relative_spelling(path: &Path) -> Option<String> {
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => names.push(name.to_str()?),
            Component::CurDir => (),
            _ => return None,
        }
    }
    Some(names.join("/"))
}

fn checkout_directory(root: &Path) -> Option<PathBuf> {
    let canonical = fs::canonicalize(root).ok()?;
    canonical.to_str()?;
    fs::metadata(&canonical).ok()?.is_dir().then_some(canonical)
}

fn resolve_scope_path(root: &Path, canonical_root: &Path, raw: &str) -> Option<ScopePath> {
    let path = Path::new(raw);
    let relative = if path.is_absolute() {
        path.strip_prefix(canonical_root)
            .ok()
            .or_else(|| path.strip_prefix(std::path::absolute(root).ok()?).ok())?
    } else {
        path
    };
    let lexical = relative_spelling(relative)?;
    let mut resolved = canonical_root.to_path_buf();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            continue;
        };
        // A drive-like segment in the middle of a Windows path must never reset the base.
        if !matches!(
            Path::new(name).components().next(),
            Some(Component::Normal(_))
        ) {
            return None;
        }
        resolved.push(name);
        match fs::symlink_metadata(&resolved) {
            Ok(_) => {
                resolved = fs::canonicalize(&resolved).ok()?;
                resolved.strip_prefix(canonical_root).ok()?;
                resolved.to_str()?;
                let requires_dir = components.peek().is_some()
                    || raw.ends_with(std::path::is_separator)
                    || raw
                        .strip_suffix('.')
                        .is_some_and(|p| p.ends_with(std::path::is_separator));
                if requires_dir && !fs::metadata(&resolved).ok()?.is_dir() {
                    return None;
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => (),
            Err(_) => return None,
        }
    }
    let canonical = relative_spelling(resolved.strip_prefix(canonical_root).ok()?)?;
    Some(ScopePath { lexical, canonical })
}

/// Return the canonical checkout-relative spelling, including a verified new-file suffix.
pub fn resolve_under_root(root: &Path, rel_or_abs: &str) -> (bool, String) {
    let path = checkout_directory(root).and_then(|dir| resolve_scope_path(root, &dir, rel_or_abs));
    match path {
        Some(path) => (true, path.canonical),
        None => (false, rel_or_abs.to_owned()),
    }
}

impl ScopePath {
    fn matches(&self, task: &PlanTaskSpec) -> (bool, bool, bool) {
        let matches = |name: &str, rules: &[String]| {
            rules.iter().any(|rule| scoped_entry_matches(name, rule))
        };
        let names = [self.lexical.as_str(), self.canonical.as_str()];
        let allowed = names.map(|name| matches(name, &task.allowed_paths));
        let output = names.map(|name| matches(name, &task.verification_output_paths));
        let forbidden = names
            .iter()
            .any(|name| matches(name, &task.forbidden_paths));
        let verified_output =
            (output[0] || output[1]) && (allowed[0] || output[0]) && (allowed[1] || output[1]);
        (allowed[0] && allowed[1], forbidden, verified_output)
    }
}

/// Evaluate task scope via the Lean 4 decision kernel, returning `Err` on kernel failure
/// and also returning the exact `KernelScopeRequest` for Mode B certification.
pub fn verify_task_scope_checked(
    checkout_root: &Path,
    task: &PlanTaskSpec,
    changed_paths: &[String],
    auth: PathAuthority,
    other_active_units: &[ActiveUnitRecord],
) -> Result<(ScopeOutcome, KernelScopeRequest), String> {
    let mut findings = Vec::new();
    let mut normalized_writes = BTreeSet::new();
    let canonical_root = checkout_directory(checkout_root);

    let mut raw_entries: Vec<(String, String, KernelPathDecision)> =
        Vec::with_capacity(changed_paths.len());
    for raw in changed_paths {
        let path = canonical_root
            .as_deref()
            .and_then(|root| resolve_scope_path(checkout_root, root, raw));
        let inside_root = path.is_some();
        let (matched_allowed, matched_forbidden, matched_verify_output) =
            path.as_ref().map(|p| p.matches(task)).unwrap_or_default();
        let rel_posix = path
            .as_ref()
            .map_or_else(|| raw.clone(), |p| p.canonical.clone());
        if let Some(p) = path {
            normalized_writes.extend([p.lexical, p.canonical]);
        }
        raw_entries.push((
            raw.clone(),
            rel_posix,
            KernelPathDecision {
                inside_root,
                matched_allowed,
                matched_forbidden,
                matched_verify_output,
            },
        ));
    }

    let mut other_writes = BTreeSet::new();
    for unit in other_active_units
        .iter()
        .filter(|unit| unit.task_id != task.id)
    {
        let unit_dir = Path::new(&unit.checkout_root);
        let Some(unit_root) = checkout_directory(unit_dir) else {
            findings.push(unresolved_writer(unit, &unit.checkout_root));
            continue;
        };
        if canonical_root.as_ref() != Some(&unit_root) {
            continue;
        }
        for write in &unit.write_paths {
            match resolve_scope_path(unit_dir, &unit_root, write) {
                Some(path) => other_writes.extend([path.lexical, path.canonical]),
                None => findings.push(unresolved_writer(unit, write)),
            }
        }
    }

    let kernel_req = KernelScopeRequest {
        authority: auth.as_wire().into(),
        decisions: raw_entries.iter().map(|(_, _, d)| d.clone()).collect(),
        my_writes: normalized_writes.into_iter().collect(),
        other_active_writes: other_writes.into_iter().collect(),
    };

    let kscope = eval_scope(&kernel_req)?;
    if kscope.path_admitted.len() != raw_entries.len() {
        return Err(format!(
            "Lean kernel returned {} path decisions for {} paths",
            kscope.path_admitted.len(),
            raw_entries.len()
        ));
    }

    let mut decisions = Vec::with_capacity(raw_entries.len());
    for ((raw, rel_posix, kd), &admitted) in raw_entries.iter().zip(kscope.path_admitted.iter()) {
        if !admitted {
            let rule = if !kd.inside_root {
                "SCOPE_ROOT_ESCAPE"
            } else if kd.matched_forbidden {
                "SCOPE_FORBIDDEN_PATH"
            } else if kd.matched_verify_output && auth == PathAuthority::SourceEdit {
                "SCOPE_VERIFY_OUTPUT_SOURCE_EDIT"
            } else {
                "SCOPE_OUT_OF_BOUNDS"
            };
            findings.push(ProjectFinding {
                rule: rule.into(),
                category: "workflow".into(),
                severity: "error".into(),
                file: Some(raw.clone()),
                line: None,
                message: format!(
                    "Path '{raw}' (resolved '{rel_posix}') is not admitted for task '{}'.",
                    task.id
                ),
                remediation: "Keep edits inside allowed_paths, never touch forbidden_paths, and do not escape checkout_root.".into(),
                details: BTreeMap::new(),
            });
        }
        decisions.push(PathDecision {
            path: raw.clone(),
            inside_root: kd.inside_root,
            matched_allowed: kd.matched_allowed,
            matched_forbidden: kd.matched_forbidden,
            matched_verify_output: kd.matched_verify_output,
            admitted,
        });
    }

    for w in &kscope.overlapping_writes {
        findings.push(ProjectFinding {
            rule: "SCOPE_CONCURRENT_WRITE_OVERLAP".into(),
            category: "workflow".into(),
            severity: "error".into(),
            file: Some(w.clone()),
            line: None,
            message: format!(
                "Path '{w}' overlaps with another active mutating unit on the same checkout."
            ),
            remediation: "Serialize overlapping units or isolate them in separate worktrees."
                .into(),
            details: BTreeMap::new(),
        });
    }

    let admitted = kscope.verdict.admitted && findings.is_empty() && canonical_root.is_some();
    Ok((
        ScopeOutcome {
            admitted,
            decisions,
            overlapping_writes: kscope.overlapping_writes,
            findings,
            kernel_error: None,
        },
        kernel_req,
    ))
}

/// Evaluate a list of changed/target paths plus optional concurrent active-unit write sets,
/// failing closed if the Lean 4 decision kernel is unavailable.
pub fn verify_task_scope(
    checkout_root: &Path,
    task: &PlanTaskSpec,
    changed_paths: &[String],
    auth: PathAuthority,
    other_active_units: &[ActiveUnitRecord],
) -> ScopeOutcome {
    match verify_task_scope_checked(checkout_root, task, changed_paths, auth, other_active_units) {
        Ok((outcome, _)) => outcome,
        Err(err) => ScopeOutcome {
            admitted: false,
            decisions: Vec::new(),
            overlapping_writes: Vec::new(),
            findings: vec![ProjectFinding {
                rule: "SCOPE_KERNEL_ERROR".into(),
                category: "workflow".into(),
                severity: "error".into(),
                file: None,
                line: None,
                message: err.clone(),
                remediation: "Build or install birkin-kernel (`cd lean && lake build`).".into(),
                details: BTreeMap::new(),
            }],
            kernel_error: Some(err),
        },
    }
}

fn unresolved_writer(unit: &ActiveUnitRecord, path: &str) -> ProjectFinding {
    ProjectFinding {
        rule: "SCOPE_UNRESOLVED_WRITER".into(),
        category: "workflow".into(),
        severity: "error".into(),
        file: Some(path.into()),
        line: None,
        message: format!("Cannot verify write scope for active task '{}'.", unit.task_id),
        remediation: "Provide a resolvable checkout and checkout-relative write set.".into(),
        details: BTreeMap::new(),
    }
}

fn git_path(bytes: &[u8]) -> Result<String, String> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| "Git reported a path that cannot be represented as UTF-8".into())
}

/// Collect changed (or staged) repo-relative paths via Git for live scope inspection.
pub fn collect_git_changed_paths(
    repo_root: &Path,
    staged_only: bool,
) -> Result<Vec<String>, String> {
    let mut paths = BTreeSet::new();
    if staged_only {
        let out = Command::new("git")
            .current_dir(repo_root)
            .args(["diff", "--cached", "--name-only", "--no-renames", "-z"])
            .output()
            .map_err(|e| format!("Failed invoking git diff --cached: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        for chunk in out.stdout.split(|&b| b == 0) {
            if !chunk.is_empty() {
                paths.insert(git_path(chunk)?);
            }
        }
    } else {
        let out = Command::new("git")
            .current_dir(repo_root)
            .args(["status", "--porcelain=v1", "-z", "--no-renames", "-uall"])
            .output()
            .map_err(|e| format!("Failed invoking git status: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        for rec in out.stdout.split(|&b| b == 0) {
            if rec.len() > 3 {
                paths.insert(git_path(&rec[3..])?);
            }
        }
    }
    Ok(paths.into_iter().collect())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn scope_spelling_requires_lossless_native_components() {
        let valid = Path::new("src/name-\u{fffd}");
        let invalid = Path::new(OsStr::from_bytes(b"src/name-\xff"));
        assert_eq!(relative_spelling(valid).as_deref(), valid.to_str());
        assert_eq!(relative_spelling(invalid), None);
    }
}
