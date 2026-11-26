//! File-scope containment, symlink escape detection, and concurrent write-disjointness engine
//! aligned with `BirkinSpec.ScopeContract`.

use crate::project_models::ProjectFinding;
use crate::workflow_models::{ActiveUnitRecord, PlanTaskSpec};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathAuthority {
    SourceEdit,
    VerificationOutput,
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
}

/// Core boolean decision mirroring `BirkinSpec.pathAdmitted`.
pub fn path_admitted_bool(
    auth: PathAuthority,
    inside_root: bool,
    matched_allowed: bool,
    matched_forbidden: bool,
    matched_verify_output: bool,
) -> bool {
    if !inside_root || matched_forbidden {
        return false;
    }
    match auth {
        PathAuthority::SourceEdit => matched_allowed,
        PathAuthority::VerificationOutput => matched_allowed || matched_verify_output,
    }
}

fn normalize_posix(raw: &str) -> String {
    raw.replace('\\', "/").trim_start_matches("./").to_string()
}

/// Match a normalized repo-relative path against a scoped `fly-face` entry (exact file or `dir/`).
pub fn scoped_entry_matches(rel_posix: &str, scoped: &str) -> bool {
    let rel = normalize_posix(rel_posix);
    let rule = normalize_posix(scoped);
    if let Some(dir_prefix) = rule.strip_suffix('/') {
        rel == dir_prefix || rel.starts_with(&format!("{dir_prefix}/"))
    } else {
        rel == rule
    }
}

/// Two declared write paths conflict when equal or when one is a directory prefix of the other.
pub fn write_paths_overlap(a: &str, b: &str) -> bool {
    let (a, b) = (a.trim_end_matches('/'), b.trim_end_matches('/'));
    a == b || a.starts_with(&format!("{b}/")) || b.starts_with(&format!("{a}/"))
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Resolve an existing or not-yet-created path under `root`, following symlinks on its nearest
/// existing ancestor so symlink escapes outside `root` are caught fail-closed.
pub fn resolve_under_root(root: &Path, rel_or_abs: &str) -> (bool, String) {
    let Ok(canon_root) = fs::canonicalize(root) else {
        return (false, normalize_posix(rel_or_abs));
    };
    // Join segment by segment: a canonical Windows root is a verbatim path, where `/` is not a
    // separator. A relative `..` is rejected outright because lexical and symlink-aware
    // resolution can disagree about where it lands.
    let candidate = if Path::new(rel_or_abs).is_absolute() {
        PathBuf::from(rel_or_abs)
    } else {
        let mut joined = canon_root.clone();
        for seg in rel_or_abs.split(['/', '\\']) {
            match seg {
                "" | "." => {}
                ".." => return (false, normalize_posix(rel_or_abs)),
                s => joined.push(s),
            }
        }
        joined
    };

    let resolved = if candidate.exists() || candidate.symlink_metadata().is_ok() {
        match fs::canonicalize(&candidate) {
            Ok(c) => c,
            Err(_) => {
                // Broken symlink: check link target directly; treat unresolved target as outside root.
                if let Ok(target) = fs::read_link(&candidate) {
                    let full = if target.is_absolute() {
                        target
                    } else {
                        candidate.parent().unwrap_or(&canon_root).join(target)
                    };
                    normalize_lexical(&full)
                } else {
                    return (false, normalize_posix(rel_or_abs));
                }
            }
        }
    } else {
        // Walk up until an existing ancestor is found, canonicalize it, then append remaining tail.
        let mut cur = candidate.as_path();
        let mut tail = Vec::new();
        loop {
            if cur.exists() {
                let Ok(base) = fs::canonicalize(cur) else {
                    return (false, normalize_posix(rel_or_abs));
                };
                let mut rebuilt = base;
                for seg in tail.into_iter().rev() {
                    rebuilt.push(seg);
                }
                break normalize_lexical(&rebuilt);
            }
            match (cur.parent(), cur.file_name()) {
                (Some(parent), Some(name)) => {
                    tail.push(name.to_os_string());
                    cur = parent;
                }
                _ => break normalize_lexical(&candidate),
            }
        }
    };

    match resolved.strip_prefix(&canon_root) {
        Ok(rel) => {
            let posix = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            (true, posix)
        }
        Err(_) => (false, normalize_posix(rel_or_abs)),
    }
}

/// Evaluate a list of changed/target paths plus optional concurrent active-unit write sets.
pub fn verify_task_scope(
    checkout_root: &Path,
    task: &PlanTaskSpec,
    changed_paths: &[String],
    auth: PathAuthority,
    other_active_units: &[ActiveUnitRecord],
) -> ScopeOutcome {
    let mut decisions = Vec::new();
    let mut findings = Vec::new();
    let mut normalized_writes = Vec::new();

    for raw in changed_paths {
        let (inside_root, rel_posix) = resolve_under_root(checkout_root, raw);
        let matched_allowed = inside_root
            && task
                .allowed_paths
                .iter()
                .any(|p| scoped_entry_matches(&rel_posix, p));
        let matched_forbidden = inside_root
            && task
                .forbidden_paths
                .iter()
                .any(|p| scoped_entry_matches(&rel_posix, p));
        let matched_verify_output = inside_root
            && task
                .verification_output_paths
                .iter()
                .any(|p| scoped_entry_matches(&rel_posix, p));
        let admitted = path_admitted_bool(
            auth,
            inside_root,
            matched_allowed,
            matched_forbidden,
            matched_verify_output,
        );
        if inside_root {
            normalized_writes.push(rel_posix.clone());
        }
        if !admitted {
            let rule = if !inside_root {
                "SCOPE_ROOT_ESCAPE"
            } else if matched_forbidden {
                "SCOPE_FORBIDDEN_PATH"
            } else if matched_verify_output && auth == PathAuthority::SourceEdit {
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
                message: format!("Path '{raw}' (resolved '{rel_posix}') is not admitted for task '{}'.", task.id),
                remediation: "Keep edits inside allowed_paths, never touch forbidden_paths, and do not escape checkout_root.".into(),
                details: BTreeMap::new(),
            });
        }
        decisions.push(PathDecision {
            path: raw.clone(),
            inside_root,
            matched_allowed,
            matched_forbidden,
            matched_verify_output,
            admitted,
        });
    }

    let canon_root_str = fs::canonicalize(checkout_root)
        .unwrap_or_else(|_| checkout_root.to_path_buf())
        .to_string_lossy()
        .into_owned();

    let mut other_writes: BTreeSet<String> = BTreeSet::new();
    for unit in other_active_units {
        if unit.task_id == task.id {
            continue;
        }
        let unit_root = fs::canonicalize(&unit.checkout_root)
            .unwrap_or_else(|_| PathBuf::from(&unit.checkout_root))
            .to_string_lossy()
            .into_owned();
        if unit_root != canon_root_str {
            continue;
        }
        for wp in &unit.write_paths {
            let (in_r, norm) = resolve_under_root(checkout_root, wp);
            if in_r {
                other_writes.insert(norm);
            } else {
                other_writes.insert(normalize_posix(wp));
            }
        }
    }

    let mut overlapping_writes = Vec::new();
    for w in &normalized_writes {
        if other_writes.iter().any(|o| write_paths_overlap(w, o)) {
            overlapping_writes.push(w.clone());
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
    }

    let admitted = decisions.iter().all(|d| d.admitted) && overlapping_writes.is_empty();
    ScopeOutcome {
        admitted,
        decisions,
        overlapping_writes,
        findings,
    }
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
            .args(["diff", "--cached", "--name-only", "-z"])
            .output()
            .map_err(|e| format!("Failed invoking git diff --cached: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        for chunk in out.stdout.split(|&b| b == 0) {
            if !chunk.is_empty() {
                paths.insert(String::from_utf8_lossy(chunk).into_owned());
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
                paths.insert(String::from_utf8_lossy(&rec[3..]).into_owned());
            }
        }
    }
    Ok(paths.into_iter().collect())
}
