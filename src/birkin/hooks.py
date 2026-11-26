"""Real-time agent hook adapters and idempotent operational installers.

Integrates Birkin directly into:
  1. Claude Code PostToolUse hooks (JSON stdin -> hookSpecificOutput.additionalContext)
  2. Hermes Agent native plugins (transform_tool_result on write_file / patch)
  3. Git pre-commit hooks (.git/hooks/pre-commit)
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from birkin.constants import EXIT_PASS, EXIT_STATIC
from birkin.guides import audit_guides
from birkin.ledger import append_receipt
from birkin.project_models import (
    ProjectFinding,
    find_harness_file,
    find_repo_root,
    load_project_harness,
)
from birkin.semantic import run_semantic_review
from birkin.sensors import run_project_sensors

_GIT_HOOK_MARKER = "# birkin-managed-pre-commit"
_CLAUDE_HOOK_CMD = "birkin hook post-edit --claude-stdin"


def format_llm_feedback(findings: list[ProjectFinding], *, max_items: int = 12) -> str:
    """Format findings as concise, actionable LLM self-correction instructions."""
    if not findings:
        return ""
    lines = [f"[birkin-harness] {len(findings)} invariant finding(s) — fix before continuing:"]
    for item in findings[:max_items]:
        loc = f"{item.file}:{item.line}" if (item.file and item.line) else (item.file or "<repo>")
        lines.append(f"- [{item.severity.upper()}][{item.rule}] {loc}: {item.message}")
        lines.append(f"  Fix: {item.remediation}")
    if len(findings) > max_items:
        lines.append(f"... and {len(findings) - max_items} more finding(s); run `birkin check` for full output.")
    return "\n".join(lines)


def extract_claude_edited_paths(payload: dict[str, Any]) -> list[Path]:
    """Extract edited file path(s) from a Claude Code PostToolUse hook JSON payload."""
    tool_name = str(payload.get("tool_name") or "")
    if tool_name not in ("Write", "Edit", "MultiEdit", "write_file", "patch"):
        return []
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return []
    paths: list[Path] = []
    for key in ("file_path", "path"):
        val = tool_input.get(key)
        if isinstance(val, str) and val.strip():
            paths.append(Path(val.strip()))
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        for ed in edits:
            if isinstance(ed, dict):
                fp = ed.get("file_path") or ed.get("path")
                if isinstance(fp, str) and fp.strip():
                    paths.append(Path(fp.strip()))
    return paths


def run_post_edit_hook(
    file_paths: list[Path],
    *,
    surface: str = "hook",
    include_semantic: bool = False,
    require_harness: bool = False,
) -> tuple[int, list[ProjectFinding], str]:
    """Run sub-second computational (and optional semantic) sensors on edited file(s)."""
    if not file_paths:
        return EXIT_PASS, [], ""

    first = file_paths[0].resolve()
    repo_root = find_repo_root(first)
    if find_harness_file(repo_root) is None and not require_harness:
        return EXIT_PASS, [], ""

    t0 = time.monotonic()
    spec, _ = load_project_harness(repo_root)
    findings, checked_rel = run_project_sensors(repo_root, spec, files=file_paths)

    if include_semantic and spec.semantic.enabled and spec.semantic.rules:
        _, sem_findings, _ = run_semantic_review(repo_root, spec, files=file_paths)
        findings.extend(sem_findings)

    dur_ms = int((time.monotonic() - t0) * 1000)
    has_errors = any(f.severity == "error" for f in findings)
    exit_code = EXIT_STATIC if has_errors else EXIT_PASS

    if spec.telemetry.enabled:
        append_receipt(
            repo_root,
            spec,
            command="hook:post-edit",
            surface=surface,
            outcome="FAIL" if has_errors else "PASS",
            exit_code=exit_code,
            duration_ms=dur_ms,
            findings=[f.model_dump() for f in findings],
            files=checked_rel,
        )

    return exit_code, findings, format_llm_feedback(findings)


def run_pre_commit_hook(repo_root: Path) -> tuple[int, list[ProjectFinding], str]:
    """Check staged files and modified docs/harness before git commit."""
    resolved = repo_root.resolve()
    if find_harness_file(resolved) is None:
        return EXIT_PASS, [], ""

    t0 = time.monotonic()
    spec, _ = load_project_harness(resolved)
    proc = subprocess.run(
        ["git", "-C", str(resolved), "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    staged_rels = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not staged_rels:
        return EXIT_PASS, [], ""

    staged_paths = [resolved / rel for rel in staged_rels]
    findings, checked_rel = run_project_sensors(resolved, spec, files=staged_paths)

    # Also audit guides whenever markdown or .birkin files are staged
    if any(r.endswith(".md") or r.startswith(".birkin/") or r == "birkin.yaml" for r in staged_rels):
        findings.extend(audit_guides(resolved, spec))

    dur_ms = int((time.monotonic() - t0) * 1000)
    has_errors = any(f.severity == "error" for f in findings)
    exit_code = EXIT_STATIC if has_errors else EXIT_PASS

    if spec.telemetry.enabled:
        append_receipt(
            resolved,
            spec,
            command="hook:pre-commit",
            surface="git-hook",
            outcome="FAIL" if has_errors else "PASS",
            exit_code=exit_code,
            duration_ms=dur_ms,
            findings=[f.model_dump() for f in findings],
            files=checked_rel,
        )

    return exit_code, findings, format_llm_feedback(findings)


def install_git_pre_commit_hook(repo_root: Path) -> dict[str, Any]:
    """Install an idempotent .git/hooks/pre-commit script invoking `birkin hook pre-commit`."""
    git_dir = repo_root / ".git"
    if not git_dir.is_dir():
        raise FileNotFoundError(f"Not a git repository (missing .git directory): {repo_root}")
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    snippet = (
        f"{_GIT_HOOK_MARKER}\n"
        'if command -v birkin >/dev/null 2>&1; then\n'
        '  birkin hook pre-commit "$(git rev-parse --show-toplevel)" || exit $?\n'
        "fi\n"
    )

    if hook_path.is_file():
        existing = hook_path.read_text(encoding="utf-8", errors="replace")
        if _GIT_HOOK_MARKER in existing:
            return {"target": "git", "path": str(hook_path), "status": "already_installed"}
        updated = existing.rstrip() + "\n\n" + snippet
        hook_path.write_text(updated, encoding="utf-8")
        action = "appended"
    else:
        hook_path.write_text("#!/bin/sh\nset -eu\n\n" + snippet, encoding="utf-8")
        action = "created"

    mode = hook_path.stat().st_mode
    hook_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return {"target": "git", "path": str(hook_path), "status": action}


def install_claude_hook(settings_path: Path) -> dict[str, Any]:
    """Idempotently register Birkin PostToolUse hook in a Claude Code settings JSON file."""
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path: str | None = None
    if settings_path.is_file():
        raw = json.loads(settings_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"Expected JSON object in {settings_path}")
        bak = settings_path.with_suffix(settings_path.suffix + ".birkin.bak")
        shutil.copy2(settings_path, bak)
        backup_path = str(bak)
    else:
        raw = {}

    hooks = raw.setdefault("hooks", {})
    post_list = hooks.setdefault("PostToolUse", [])
    if not isinstance(post_list, list):
        raise ValueError(f"hooks.PostToolUse must be a list in {settings_path}")

    for entry in post_list:
        if isinstance(entry, dict):
            for sub in entry.get("hooks", []):
                if isinstance(sub, dict) and _CLAUDE_HOOK_CMD in str(sub.get("command", "")):
                    return {
                        "target": "claude",
                        "path": str(settings_path),
                        "status": "already_installed",
                        "backup": backup_path,
                    }

    post_list.append(
        {
            "matcher": "Write|Edit|MultiEdit",
            "hooks": [
                {
                    "type": "command",
                    "command": _CLAUDE_HOOK_CMD,
                    "timeout": 10,
                }
            ],
        }
    )

    tmp = settings_path.with_suffix(settings_path.suffix + ".tmp")
    tmp.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, settings_path)
    return {
        "target": "claude",
        "path": str(settings_path),
        "status": "installed",
        "backup": backup_path,
    }


def _hermes_plugin_yaml() -> str:
    return (
        "name: birkin-harness\n"
        'version: "0.3.0"\n'
        'description: "Real-time Birkin computational harness feedback on write_file and patch edits."\n'
        "author: hauntedfail\n"
        "kind: standalone\n"
        "provides_hooks:\n"
        "  - transform_tool_result\n"
    )


def _hermes_plugin_init_py(birkin_src_dir: Path) -> str:
    src_str = str(birkin_src_dir.resolve())
    return f'''"""Hermes Agent native plugin for real-time Birkin harness feedback."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_BIRKIN_SRC = {src_str!r}
if _BIRKIN_SRC not in sys.path:
    sys.path.insert(0, _BIRKIN_SRC)

_EDIT_TOOLS = frozenset({{"write_file", "patch"}})


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
    """Append concise Birkin harness remediation feedback after file edits inside harnessed repos."""
    if tool_name not in _EDIT_TOOLS:
        return None
    target = _extract_path(args)
    if target is None or not target.is_file():
        return None
    try:
        from birkin.hooks import run_post_edit_hook

        _, findings, feedback = run_post_edit_hook([target], surface="hermes-plugin")
        if not findings or not feedback:
            return None
        raw_result = kwargs.get("result")
        if isinstance(raw_result, str):
            try:
                parsed = json.loads(raw_result)
                if isinstance(parsed, dict):
                    parsed["birkin_harness_feedback"] = feedback
                    return json.dumps(parsed, ensure_ascii=False)
            except ValueError:
                return raw_result + "\\n\\n" + feedback
        return None
    except Exception:
        # Never break core tool execution if harness evaluation fails unexpectedly.
        return None


def register(ctx: Any) -> None:
    ctx.register_hook("transform_tool_result", transform_tool_result)
'''


def install_hermes_plugin(plugins_dir: Path, *, birkin_src_dir: Path | None = None) -> dict[str, Any]:
    """Install the native Hermes plugin `birkin-harness` into plugins_dir."""
    src_dir = birkin_src_dir or Path(__file__).resolve().parents[1]
    plugin_dir = plugins_dir / "birkin-harness"
    plugin_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "plugin.yaml").write_text(_hermes_plugin_yaml(), encoding="utf-8")
    (plugin_dir / "__init__.py").write_text(_hermes_plugin_init_py(src_dir), encoding="utf-8")
    return {
        "target": "hermes",
        "path": str(plugin_dir),
        "birkin_src": str(src_dir.resolve()),
        "status": "installed",
    }


def read_claude_stdin_payload() -> dict[str, Any]:
    raw = sys.stdin.read().strip()
    if not raw:
        return {}
    parsed = json.loads(raw)
    return parsed if isinstance(parsed, dict) else {}
