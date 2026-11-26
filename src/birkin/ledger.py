"""Append-only, hash-chained receipt ledger bound to git revision and spec digest.

Implements experience/decision observability and portable disclosure:
receipts are stored outside the repository working tree by default (~/.birkin/ledger/) so
they never dirty git state and remain independently auditable.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from birkin.project_models import ProjectSpec

DEFAULT_LEDGER_DIR = Path(os.environ.get("BIRKIN_LEDGER_DIR", str(Path.home() / ".birkin" / "ledger")))


def repo_slug(repo_root: Path) -> str:
    resolved = str(repo_root.resolve())
    short_hash = hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:10]
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", repo_root.resolve().name).strip("-") or "repo"
    return f"{safe_name}-{short_hash}"


def resolve_ledger_path(repo_root: Path, spec: ProjectSpec) -> Path:
    if spec.telemetry.ledger_path:
        p = Path(spec.telemetry.ledger_path).expanduser()
        return p if p.is_absolute() else (repo_root / p)
    return DEFAULT_LEDGER_DIR / f"{repo_slug(repo_root)}.jsonl"


def canonical_spec_sha256(spec: ProjectSpec) -> str:
    payload = json.dumps(spec.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def git_revision_state(repo_root: Path, *, ignore_rel: str | None = None) -> dict[str, Any]:
    """Return exact git HEAD SHA, dirty flag, and working-tree digest (or non-git fallback)."""
    try:
        head_proc = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        head = head_proc.stdout.strip() if head_proc.returncode == 0 else None
        status_proc = subprocess.run(
            ["git", "-C", str(repo_root), "status", "--porcelain=v1", "-uall"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        status_lines = [
            line
            for line in (status_proc.stdout.splitlines() if status_proc.returncode == 0 else [])
            if not (ignore_rel and line[3:].strip() == ignore_rel)
        ]
        status_text = "\n".join(status_lines)
        diff_proc = subprocess.run(
            ["git", "-C", str(repo_root), "diff", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        diff_text = diff_proc.stdout if diff_proc.returncode == 0 else ""
        dirty = bool(status_text.strip())
        digest_input = f"{head or ''}\n---\n{status_text}\n---\n{diff_text}"
        tree_digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()
        return {
            "is_git": head is not None,
            "git_head": head,
            "git_dirty": dirty,
            "tree_digest": tree_digest,
        }
    except (OSError, subprocess.TimeoutExpired):
        return {
            "is_git": False,
            "git_head": None,
            "git_dirty": False,
            "tree_digest": None,
        }


def _relative_ignore(repo_root: Path, ledger_path: Path) -> str | None:
    try:
        return ledger_path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return None


def _receipt_hash(entry: dict[str, Any]) -> str:
    copy = {k: v for k, v in entry.items() if k != "receipt_sha256"}
    canonical = json.dumps(copy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def read_receipts(ledger_path: Path) -> list[dict[str, Any]]:
    if not ledger_path.is_file():
        return []
    entries: list[dict[str, Any]] = []
    for raw in ledger_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                entries.append(parsed)
        except json.JSONDecodeError:
            entries.append({"_corrupt": True, "raw": line})
    return entries


def verify_chain(entries: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    """Verify hash-chain integrity across all ledger entries."""
    errors: list[str] = []
    prev_hash = "GENESIS"
    for idx, entry in enumerate(entries):
        if entry.get("_corrupt"):
            errors.append(f"Line {idx + 1}: corrupt JSON entry")
            continue
        if entry.get("prev_receipt_sha256") != prev_hash:
            errors.append(
                f"Line {idx + 1}: prev_receipt_sha256 mismatch (expected {prev_hash[:12]}, "
                f"got {str(entry.get('prev_receipt_sha256'))[:12]})"
            )
        expected_hash = _receipt_hash(entry)
        actual_hash = entry.get("receipt_sha256")
        if actual_hash != expected_hash:
            errors.append(f"Line {idx + 1}: receipt_sha256 tampered or invalid")
        prev_hash = str(actual_hash or "")
    return len(errors) == 0, errors


def append_receipt(
    repo_root: Path,
    spec: ProjectSpec,
    *,
    command: str,
    surface: str,
    outcome: str,
    exit_code: int,
    duration_ms: int,
    findings: list[dict[str, Any]] | None = None,
    files: list[str] | None = None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append a hash-chained receipt entry to the repository's ledger."""
    ledger_path = resolve_ledger_path(repo_root, spec)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)

    existing = read_receipts(ledger_path)
    prev_hash = "GENESIS"
    if existing and not existing[-1].get("_corrupt"):
        prev_hash = str(existing[-1].get("receipt_sha256") or "GENESIS")

    rev = git_revision_state(repo_root, ignore_rel=_relative_ignore(repo_root, ledger_path))
    finding_items = findings or []
    rule_counts: dict[str, int] = {}
    affected_files: list[str] = []
    for item in finding_items:
        rule = str(item.get("rule", "UNKNOWN"))
        rule_counts[rule] = rule_counts.get(rule, 0) + 1
        f = item.get("file")
        if isinstance(f, str) and f not in affected_files:
            affected_files.append(f)

    entry: dict[str, Any] = {
        "schema_version": 1,
        "recorded_at": datetime.now(UTC).isoformat(),
        "repo": str(repo_root.resolve()),
        "project": spec.project.name,
        "command": command,
        "surface": surface,
        "outcome": outcome,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "git_head": rev["git_head"],
        "git_dirty": rev["git_dirty"],
        "tree_digest": rev["tree_digest"],
        "spec_sha256": canonical_spec_sha256(spec),
        "finding_count": len(finding_items),
        "error_count": sum(1 for item in finding_items if item.get("severity") == "error"),
        "rule_counts": rule_counts,
        "files_checked": files or [],
        "affected_files": affected_files,
        "meta": meta or {},
        "prev_receipt_sha256": prev_hash,
    }
    entry["receipt_sha256"] = _receipt_hash(entry)

    with ledger_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def verify_receipts_for_current_state(
    repo_root: Path,
    spec: ProjectSpec,
    *,
    required_commands: list[str],
    require_clean: bool = False,
) -> dict[str, Any]:
    """Prove that the exact current revision/tree + Birkin spec has passing receipts."""
    ledger_path = resolve_ledger_path(repo_root, spec)
    entries = read_receipts(ledger_path)
    chain_ok, chain_errors = verify_chain(entries)
    rev = git_revision_state(repo_root, ignore_rel=_relative_ignore(repo_root, ledger_path))
    spec_sha = canonical_spec_sha256(spec)

    missing: list[str] = []
    matched: dict[str, dict[str, Any]] = {}

    if require_clean and rev["git_dirty"]:
        return {
            "status": "FAIL",
            "reason": "Working tree is dirty while --require-clean is set",
            "chain_ok": chain_ok,
            "chain_errors": chain_errors,
            "git_head": rev["git_head"],
            "git_dirty": rev["git_dirty"],
            "tree_digest": rev["tree_digest"],
            "spec_sha256": spec_sha,
            "matched": {},
            "missing": required_commands,
        }

    for req in required_commands:
        found: dict[str, Any] | None = None
        for entry in reversed(entries):
            if entry.get("_corrupt"):
                continue
            if entry.get("command") != req:
                continue
            if entry.get("exit_code") != 0 or entry.get("outcome") != "PASS":
                continue
            if entry.get("spec_sha256") != spec_sha:
                continue
            if rev["tree_digest"] is not None and entry.get("tree_digest") != rev["tree_digest"]:
                continue
            if rev["git_head"] is not None and entry.get("git_head") != rev["git_head"]:
                continue
            found = {
                "recorded_at": entry.get("recorded_at"),
                "surface": entry.get("surface"),
                "receipt_sha256": entry.get("receipt_sha256"),
                "duration_ms": entry.get("duration_ms"),
            }
            break
        if found is None:
            missing.append(req)
        else:
            matched[req] = found

    ok = chain_ok and not missing and bool(required_commands)
    return {
        "status": "PASS" if ok else "FAIL",
        "chain_ok": chain_ok,
        "chain_errors": chain_errors,
        "ledger_path": str(ledger_path),
        "git_head": rev["git_head"],
        "git_dirty": rev["git_dirty"],
        "tree_digest": rev["tree_digest"],
        "spec_sha256": spec_sha,
        "matched": matched,
        "missing": missing,
    }
