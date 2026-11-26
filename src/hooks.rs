//! Real-time agent hook adapters and idempotent operational installers.
//!
//! Integrates Birkin into:
//!   1. Claude Code PostToolUse hooks (JSON stdin -> hookSpecificOutput.additionalContext)
//!   2. Hermes Agent native plugin (~/.hermes/plugins/birkin/, invoking native birkin binary)
//!   3. Git pre-commit hooks (.git/hooks/pre-commit)

use crate::constants::{EXIT_PASS, EXIT_STATIC};
use crate::guides::audit_guides;
use crate::ledger::append_receipt;
use crate::project_models::{find_repo_root, find_spec_file, load_project_spec, ProjectFinding};
use crate::semantic::run_semantic_review;
use crate::sensors::run_project_sensors;
use serde_json::{json, Map, Value};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const GIT_HOOK_MARKER: &str = "# birkin-managed-pre-commit";
const CLAUDE_HOOK_CMD: &str = "birkin hook post-edit --claude-stdin";

pub fn format_llm_feedback(findings: &[ProjectFinding], max_items: usize) -> String {
    if findings.is_empty() {
        return String::new();
    }
    let mut lines = vec![format!(
        "[birkin] {} invariant finding(s) — fix before continuing:",
        findings.len()
    )];
    for item in findings.iter().take(max_items) {
        let loc = match (&item.file, item.line) {
            (Some(f), Some(l)) => format!("{f}:{l}"),
            (Some(f), None) => f.clone(),
            _ => "<repo>".to_string(),
        };
        lines.push(format!(
            "- [{}][{}] {loc}: {}",
            item.severity.to_uppercase(),
            item.rule,
            item.message
        ));
        lines.push(format!("  Fix: {}", item.remediation));
    }
    if findings.len() > max_items {
        lines.push(format!(
            "... and {} more finding(s); run `birkin check` for full output.",
            findings.len() - max_items
        ));
    }
    lines.join("\n")
}

pub fn extract_claude_edited_paths(payload: &Value) -> Vec<PathBuf> {
    let Some(obj) = payload.as_object() else {
        return Vec::new();
    };
    let tool_name = obj.get("tool_name").and_then(Value::as_str).unwrap_or("");
    if !matches!(
        tool_name,
        "Write" | "Edit" | "MultiEdit" | "write_file" | "patch"
    ) {
        return Vec::new();
    }
    let Some(tool_input) = obj.get("tool_input").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut paths = Vec::new();
    for key in ["file_path", "path"] {
        if let Some(s) = tool_input.get(key).and_then(Value::as_str) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                paths.push(PathBuf::from(trimmed));
            }
        }
    }
    if let Some(edits) = tool_input.get("edits").and_then(Value::as_array) {
        for ed in edits {
            if let Some(m) = ed.as_object() {
                let fp = m
                    .get("file_path")
                    .or_else(|| m.get("path"))
                    .and_then(Value::as_str);
                if let Some(s) = fp {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        paths.push(PathBuf::from(trimmed));
                    }
                }
            }
        }
    }
    paths
}

pub fn read_claude_stdin_payload() -> Result<Value, String> {
    let mut raw = String::new();
    io::stdin()
        .read_to_string(&mut raw)
        .map_err(|e| format!("Failed reading stdin: {e}"))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(json!({}));
    }
    let parsed: Value =
        serde_json::from_str(trimmed).map_err(|e| format!("Invalid stdin JSON: {e}"))?;
    if parsed.is_object() {
        Ok(parsed)
    } else {
        Ok(json!({}))
    }
}

pub fn run_post_edit_hook(
    file_paths: &[PathBuf],
    surface: &str,
    include_semantic: bool,
    require_spec: bool,
) -> Result<(i32, Vec<ProjectFinding>, String), String> {
    if file_paths.is_empty() {
        return Ok((EXIT_PASS, Vec::new(), String::new()));
    }
    let first = fs::canonicalize(&file_paths[0]).unwrap_or_else(|_| file_paths[0].clone());
    let repo_root = find_repo_root(&first);
    if find_spec_file(&repo_root).is_none() && !require_spec {
        return Ok((EXIT_PASS, Vec::new(), String::new()));
    }

    let t0 = Instant::now();
    let (spec, _) = load_project_spec(&repo_root, None)?;
    let (mut findings, checked_rel) = run_project_sensors(&repo_root, &spec, Some(file_paths));

    if include_semantic && spec.semantic.enabled && !spec.semantic.rules.is_empty() {
        let (_, sem_findings, _) =
            run_semantic_review(&repo_root, &spec, false, None, Some(file_paths));
        findings.extend(sem_findings);
    }

    let dur_ms = t0.elapsed().as_millis();
    let has_errors = findings.iter().any(|f| f.severity == "error");
    let exit_code = if has_errors { EXIT_STATIC } else { EXIT_PASS };

    if spec.telemetry.enabled {
        let fvals: Vec<Value> = findings
            .iter()
            .filter_map(|f| serde_json::to_value(f).ok())
            .collect();
        if let Err(err) = append_receipt(
            &repo_root,
            &spec,
            "hook:post-edit",
            surface,
            if has_errors { "FAIL" } else { "PASS" },
            exit_code,
            dur_ms,
            &fvals,
            &checked_rel,
            Map::new(),
        ) {
            eprintln!("[birkin] warning: failed recording receipt (hook:post-edit): {err}");
        }
    }

    let feedback = format_llm_feedback(&findings, 12);
    Ok((exit_code, findings, feedback))
}

pub fn run_pre_commit_hook(repo_root: &Path) -> Result<(i32, Vec<ProjectFinding>, String), String> {
    let resolved = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    if find_spec_file(&resolved).is_none() {
        return Ok((EXIT_PASS, Vec::new(), String::new()));
    }

    let t0 = Instant::now();
    let (spec, _) = load_project_spec(&resolved, None)?;
    let out = Command::new("git")
        .args([
            "-C",
            &resolved.to_string_lossy(),
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
        ])
        .output()
        .map_err(|e| format!("Failed invoking git diff --cached: {e}"))?;
    let staged_rels: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if staged_rels.is_empty() {
        return Ok((EXIT_PASS, Vec::new(), String::new()));
    }

    let staged_paths: Vec<PathBuf> = staged_rels.iter().map(|r| resolved.join(r)).collect();
    let (mut findings, checked_rel) = run_project_sensors(&resolved, &spec, Some(&staged_paths));

    if staged_rels
        .iter()
        .any(|r| r.ends_with(".md") || r.starts_with(".birkin/") || r == "birkin.yaml")
    {
        findings.extend(audit_guides(&resolved, &spec, None));
    }

    let dur_ms = t0.elapsed().as_millis();
    let has_errors = findings.iter().any(|f| f.severity == "error");
    let exit_code = if has_errors { EXIT_STATIC } else { EXIT_PASS };

    if spec.telemetry.enabled {
        let fvals: Vec<Value> = findings
            .iter()
            .filter_map(|f| serde_json::to_value(f).ok())
            .collect();
        if let Err(err) = append_receipt(
            &resolved,
            &spec,
            "hook:pre-commit",
            "git-hook",
            if has_errors { "FAIL" } else { "PASS" },
            exit_code,
            dur_ms,
            &fvals,
            &checked_rel,
            Map::new(),
        ) {
            eprintln!("[birkin] warning: failed recording receipt (hook:pre-commit): {err}");
        }
    }

    let feedback = format_llm_feedback(&findings, 12);
    Ok((exit_code, findings, feedback))
}

pub fn install_git_pre_commit_hook(repo_root: &Path) -> Result<Value, String> {
    let resolve = |args: &[&str]| -> Result<PathBuf, String> {
        let out = Command::new("git").current_dir(repo_root)
            .args(["rev-parse", "--path-format=absolute"]).args(args).output()
            .map_err(|e| format!("Failed resolving Git hook directory: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_owned());
        }
        let path = String::from_utf8(out.stdout).map_err(|e| e.to_string())?;
        Ok(PathBuf::from(path.trim_end_matches(['\r', '\n'])))
    };
    let hooks = resolve(&["--git-path", "hooks"])?;
    let standard = resolve(&["--git-common-dir"])?.join("hooks");
    let path = hooks.join("pre-commit");
    let invocation = r#"birkin hook pre-commit "$(git rev-parse --show-toplevel)" || exit $?"#;
    let manual = format!("Git uses {}. Integrate `{invocation}` into the active pre-commit hook.", path.display());
    let same_hooks_dir = hooks.components().eq(standard.components());
    if !same_hooks_dir || hooks.is_symlink() || path.is_symlink() {
        return Err(manual);
    }
    fs::create_dir_all(&hooks).map_err(|e| format!("{}: {e}", hooks.display()))?;
    let managed = format!("#!/bin/sh\nset -eu\n{GIT_HOOK_MARKER}\n{invocation}\n");
    let status = match fs::OpenOptions::new().create_new(true).write(true).open(&path) {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(managed.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
            "created"
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let text = fs::read_to_string(&path).map_err(|_| manual.clone())?;
            let legacy = format!("#!/bin/sh\nset -eu\n\n{GIT_HOOK_MARKER}\nif command -v birkin >/dev/null 2>&1; then\n  {invocation}\nfi\n");
            if text != managed && text != legacy { return Err(manual); }
            "already_installed"
        }
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path).map_err(|e| e.to_string())?.permissions();
        perms.set_mode(perms.mode() | 0o111);
        fs::set_permissions(&path, perms).map_err(|e| e.to_string())?;
    }
    Ok(json!({"target": "git", "path": path, "status": status}))
}

pub fn install_claude_hook(settings_path: &Path) -> Result<Value, String> {
    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed creating {}: {e}", parent.display()))?;
    }
    let mut raw = Map::new();
    let mut backup_path: Option<String> = None;

    if settings_path.is_file() {
        let txt = fs::read_to_string(settings_path)
            .map_err(|e| format!("Failed reading {}: {e}", settings_path.display()))?;
        let parsed: Value = serde_json::from_str(&txt)
            .map_err(|e| format!("Invalid JSON in {}: {e}", settings_path.display()))?;
        raw = parsed
            .as_object()
            .cloned()
            .ok_or_else(|| format!("{} must contain a JSON object", settings_path.display()))?;
        let backup = settings_path.with_extension("json.birkin.bak");
        let _ = fs::copy(settings_path, &backup);
        backup_path = Some(backup.to_string_lossy().into_owned());
    }

    let hooks_entry = raw
        .entry("hooks".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if !hooks_entry.is_object() {
        *hooks_entry = Value::Object(Map::new());
    }
    let hooks_map = hooks_entry.as_object_mut().unwrap();
    let post_entry = hooks_map
        .entry("PostToolUse".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    if !post_entry.is_array() {
        *post_entry = Value::Array(Vec::new());
    }
    let post_list = post_entry.as_array_mut().unwrap();

    for entry in post_list.iter() {
        if let Some(sub_hooks) = entry.get("hooks").and_then(Value::as_array) {
            for h in sub_hooks {
                if h.get("command")
                    .and_then(Value::as_str)
                    .map(|c| c.contains("birkin hook post-edit"))
                    .unwrap_or(false)
                {
                    return Ok(json!({
                        "target": "claude",
                        "path": settings_path.to_string_lossy(),
                        "status": "already_installed",
                        "backup": backup_path,
                    }));
                }
            }
        }
    }

    post_list.push(json!({
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [{
            "type": "command",
            "command": CLAUDE_HOOK_CMD,
            "timeout": 10,
        }]
    }));

    let tmp = settings_path.with_extension("json.tmp");
    let serialized = serde_json::to_string_pretty(&Value::Object(raw))
        .map_err(|e| format!("Failed serializing settings JSON: {e}"))?;
    fs::write(&tmp, format!("{serialized}\n"))
        .map_err(|e| format!("Failed writing temp settings {}: {e}", tmp.display()))?;
    fs::rename(&tmp, settings_path)
        .map_err(|e| format!("Failed replacing {}: {e}", settings_path.display()))?;

    Ok(json!({
        "target": "claude",
        "path": settings_path.to_string_lossy(),
        "status": "installed",
        "backup": backup_path,
    }))
}

fn hermes_plugin_yaml() -> &'static str {
    concat!(
        "name: birkin\nversion: \"",
        env!("CARGO_PKG_VERSION"),
        "\"\ndescription: \"Real-time Birkin native computational feedback on write_file and patch edits.\"\nauthor: hauntedfail\nkind: standalone\nprovides_hooks:\n  - transform_tool_result\n"
    )
}

fn hermes_plugin_init_py(birkin_bin: &Path) -> String {
    let bin_escaped = birkin_bin.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#""""Hermes Agent native plugin delegating edit feedback to the native Birkin Rust binary."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

_BIRKIN_BIN = "{bin_escaped}"
_EDIT_TOOLS = frozenset({{"write_file", "patch"}})


def _resolve_bin() -> str | None:
    if Path(_BIRKIN_BIN).is_file():
        return _BIRKIN_BIN
    return shutil.which("birkin")


def _extract_path(args: Any) -> Path | None:
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            return None
    if not isinstance(args, dict):
        return None
    raw = args.get("path") or args.get("file_path")
    if isinstance(raw, str) and raw.strip():
        return Path(raw.strip())
    return None


def transform_tool_result(tool_name: str = "", args: Any = None, **kwargs: Any) -> str | None:
    """Append concise Birkin remediation feedback after file edits inside configured repos."""
    if tool_name not in _EDIT_TOOLS:
        return None
    target = _extract_path(args)
    if target is None or not target.is_file():
        return None
    birkin_bin = _resolve_bin()
    if not birkin_bin:
        return None
    try:
        proc = subprocess.run(
            [birkin_bin, "hook", "post-edit", "--surface", "hermes-plugin", "--files", str(target)],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        feedback = (proc.stderr or proc.stdout or "").strip()
        if not feedback:
            return None
        raw_result = kwargs.get("result")
        if isinstance(raw_result, str):
            try:
                parsed = json.loads(raw_result)
                if isinstance(parsed, dict):
                    parsed["birkin_feedback"] = feedback
                    return json.dumps(parsed, ensure_ascii=False)
            except ValueError:
                return raw_result + "\n\n" + feedback
        return None
    except Exception:
        return None


def register(ctx: Any) -> None:
    ctx.register_hook("transform_tool_result", transform_tool_result)
"#
    )
}

pub fn install_hermes_plugin(plugins_dir: &Path, birkin_bin: Option<&Path>) -> Result<Value, String> {
    let resolved_bin = match birkin_bin {
        Some(p) => p.to_path_buf(),
        None => std::env::current_exe().unwrap_or_else(|_| PathBuf::from("birkin")),
    };
    let plugin_dir = plugins_dir.join("birkin");
    fs::create_dir_all(&plugin_dir)
        .map_err(|e| format!("Failed creating {}: {e}", plugin_dir.display()))?;
    fs::write(plugin_dir.join("plugin.yaml"), hermes_plugin_yaml())
        .map_err(|e| format!("Failed writing plugin.yaml: {e}"))?;
    fs::write(
        plugin_dir.join("__init__.py"),
        hermes_plugin_init_py(&resolved_bin),
    )
    .map_err(|e| format!("Failed writing __init__.py: {e}"))?;
    Ok(json!({
        "target": "hermes",
        "path": plugin_dir.to_string_lossy(),
        "birkin_bin": resolved_bin.to_string_lossy(),
        "status": "installed",
    }))
}
