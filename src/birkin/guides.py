"""Feedforward guide auditing, doc-link verification, CI parity, and 6-axis harness scorecard."""

from __future__ import annotations

import re
import subprocess
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml

from birkin.project_models import ProjectFinding, ProjectHarnessSpec, find_harness_file

_MD_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+[\"'][^\"']*[\"'])?\)")
_LAST_REVIEWED_RE = re.compile(r"(?i)last\s+reviewed\s*:\s*(\d{4}-\d{2}-\d{2})")
_URL_PREFIXES = ("http://", "https://", "mailto:", "tel:", "data:", "file://", "#")


def _git_tracked_files(repo_root: Path) -> set[str] | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode != 0:
            return None
        return {line.strip() for line in proc.stdout.splitlines() if line.strip()}
    except (OSError, subprocess.TimeoutExpired):
        return None


def _strip_fenced_code(md_text: str) -> list[tuple[int, str]]:
    """Yield (1-based line_no, line) outside fenced ``` code blocks."""
    out: list[tuple[int, str]] = []
    in_fence = False
    for idx, line in enumerate(md_text.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            out.append((idx, line))
    return out


def _collect_doc_files(repo_root: Path, spec: ProjectHarnessSpec) -> list[Path]:
    seen: set[Path] = set()
    files: list[Path] = []
    for name in (*spec.orientation.entry_docs, "CLAUDE.md", "README.md", *spec.orientation.required_docs):
        p = repo_root / name
        if p.is_file() and p.suffix.lower() == ".md" and p.resolve() not in seen:
            seen.add(p.resolve())
            files.append(p)
    docs_dir = repo_root / "docs"
    if docs_dir.is_dir():
        for p in sorted(docs_dir.rglob("*.md")):
            if p.is_file() and p.resolve() not in seen:
                seen.add(p.resolve())
                files.append(p)
    return files


def extract_ci_run_commands(repo_root: Path) -> list[tuple[str, str]]:
    """Extract (workflow_rel_path, command_line) pairs from .github/workflows/*.yml."""
    wf_dir = repo_root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    commands: list[tuple[str, str]] = []
    for wf in sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))):
        rel = wf.relative_to(repo_root).as_posix()
        try:
            data = yaml.safe_load(wf.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        jobs = data.get("jobs")
        if not isinstance(jobs, dict):
            continue
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                run_val = step.get("run")
                if isinstance(run_val, str):
                    for line in run_val.splitlines():
                        cleaned = line.strip()
                        if cleaned and not cleaned.startswith("#"):
                            commands.append((rel, cleaned))
    return commands


def _is_verify_like_ci_cmd(cmd: str) -> bool:
    """Return True if a CI run line looks like a lint/test/typecheck/build gate (not setup/install)."""
    low = cmd.lower()
    if any(
        skip in low
        for skip in (
            "pip install",
            "npm ci",
            "npm install",
            "pnpm install",
            "yarn install",
            "bun install",
            "cargo fetch",
            "go mod download",
            "apt-get",
            "brew install",
            "uv sync",
        )
    ):
        return False
    return any(
        tok in low
        for tok in (
            "pytest",
            "ruff",
            "mypy",
            "pyright",
            "go test",
            "go vet",
            "golangci-lint",
            "cargo test",
            "cargo clippy",
            "cargo fmt",
            "npm test",
            "npm run ",
            "pnpm test",
            "pnpm run ",
            "pnpm verify",
            "pnpm check",
            "vitest",
            "jest",
            "eslint",
            "tsc",
            "birkin ",
        )
    )


def audit_guides(
    repo_root: Path,
    spec: ProjectHarnessSpec,
    *,
    today: date | None = None,
) -> list[ProjectFinding]:
    """Audit feedforward orientation guides, doc links, review staleness, git tracking, and CI parity."""
    findings: list[ProjectFinding] = []
    tracked = _git_tracked_files(repo_root)
    cur_date = today or datetime.now(UTC).date()

    # 1. Entry docs presence, line budget, and git tracking
    found_entry = False
    for entry_rel in spec.orientation.entry_docs:
        entry_path = repo_root / entry_rel
        if not entry_path.is_file():
            findings.append(
                ProjectFinding(
                    rule="ORIENTATION_MISSING_ENTRY_DOC",
                    category="orientation",
                    severity="warning",
                    file=entry_rel,
                    message=f"Feedforward entry guide '{entry_rel}' does not exist.",
                    remediation=(
                        f"Add a concise map-style '{entry_rel}' (<={spec.orientation.max_entry_doc_lines} lines) "
                        "pointing to architecture, verification commands, and detailed docs."
                    ),
                )
            )
            continue
        found_entry = True
        lines = entry_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if len(lines) > spec.orientation.max_entry_doc_lines:
            findings.append(
                ProjectFinding(
                    rule="ORIENTATION_ENTRY_DOC_BLOATED",
                    category="orientation",
                    severity="warning",
                    file=entry_rel,
                    line=len(lines),
                    message=(
                        f"Entry guide '{entry_rel}' has {len(lines)} lines, exceeding "
                        f"max_entry_doc_lines={spec.orientation.max_entry_doc_lines}."
                    ),
                    remediation=(
                        f"Trim '{entry_rel}' into a short table of contents (<={spec.orientation.max_entry_doc_lines} lines) "
                        "and move deep reference detail into docs/."
                    ),
                )
            )
        if spec.orientation.require_committed_harness and tracked is not None and entry_rel not in tracked:
            findings.append(
                ProjectFinding(
                    rule="ORIENTATION_UNTRACKED_HARNESS_FILE",
                    category="orientation",
                    severity="warning",
                    file=entry_rel,
                    message=f"Harness entry guide '{entry_rel}' exists on disk but is untracked in git.",
                    remediation=f"Commit '{entry_rel}' so CI and all agents share the same feedforward guide.",
                )
            )

    # Check harness file git tracking
    harness_path = find_harness_file(repo_root)
    if spec.orientation.require_committed_harness and harness_path is not None and tracked is not None:
        h_rel = harness_path.relative_to(repo_root).as_posix()
        if h_rel not in tracked:
            findings.append(
                ProjectFinding(
                    rule="ORIENTATION_UNTRACKED_HARNESS_FILE",
                    category="orientation",
                    severity="warning",
                    file=h_rel,
                    message=f"Harness spec '{h_rel}' exists on disk but is untracked in git.",
                    remediation=f"Commit '{h_rel}' so harness invariants are versioned and CI-enforced.",
                )
            )

    # 2. Required docs
    for req_rel in spec.orientation.required_docs:
        if not (repo_root / req_rel).exists():
            findings.append(
                ProjectFinding(
                    rule="KNOWLEDGE_MISSING_REQUIRED_DOC",
                    category="knowledge",
                    severity="error",
                    file=req_rel,
                    message=f"Required knowledge document '{req_rel}' is missing.",
                    remediation=f"Create '{req_rel}' or remove it from orientation.required_docs.",
                )
            )

    # 3. Markdown link integrity & Last reviewed staleness
    if spec.orientation.verify_markdown_links:
        for doc in _collect_doc_files(repo_root, spec):
            rel_doc = doc.relative_to(repo_root).as_posix()
            text = doc.read_text(encoding="utf-8", errors="replace")
            for line_no, line in _strip_fenced_code(text):
                for m in _MD_LINK_RE.finditer(line):
                    raw_target = m.group(1).strip()
                    if not raw_target or raw_target.startswith(_URL_PREFIXES):
                        continue
                    path_part = raw_target.split("#", 1)[0].split("?", 1)[0]
                    if not path_part:
                        continue
                    resolved = (doc.parent / path_part).resolve()
                    if not resolved.exists():
                        findings.append(
                            ProjectFinding(
                                rule="KNOWLEDGE_BROKEN_DOC_LINK",
                                category="knowledge",
                                severity="error",
                                file=rel_doc,
                                line=line_no,
                                message=f"Broken local link '{raw_target}' in {rel_doc}:{line_no}.",
                                remediation=f"Fix or remove the link to '{raw_target}' in {rel_doc}:{line_no}.",
                            )
                        )
                rev_m = _LAST_REVIEWED_RE.search(line)
                if rev_m:
                    try:
                        reviewed_on = date.fromisoformat(rev_m.group(1))
                        age = (cur_date - reviewed_on).days
                        if age > spec.orientation.max_review_age_days:
                            findings.append(
                                ProjectFinding(
                                    rule="KNOWLEDGE_STALE_DOC_REVIEW",
                                    category="knowledge",
                                    severity="warning",
                                    file=rel_doc,
                                    line=line_no,
                                    message=(
                                        f"Document '{rel_doc}' was last reviewed {age} days ago "
                                        f"({reviewed_on.isoformat()} > {spec.orientation.max_review_age_days}d)."
                                    ),
                                    remediation=f"Review '{rel_doc}' against current code and update 'Last reviewed:'.",
                                )
                            )
                    except ValueError:
                        pass

    # 4. Local verify vs CI workflow parity
    if spec.verify.check_ci_parity:
        ci_cmds = extract_ci_run_commands(repo_root)
        verify_like = [(wf, cmd) for wf, cmd in ci_cmds if _is_verify_like_ci_cmd(cmd)]
        declared_cmds = [c.cmd.strip() for c in spec.verify.commands]
        if verify_like and not declared_cmds:
            findings.append(
                ProjectFinding(
                    rule="ADMISSION_NO_LOCAL_VERIFY_DECLARED",
                    category="admission",
                    severity="warning",
                    file=verify_like[0][0],
                    message=(
                        f"CI defines {len(verify_like)} verification command(s) but .birkin/harness.yaml "
                        "declares no verify.commands."
                    ),
                    remediation="Declare canonical verify.commands in .birkin/harness.yaml mirroring CI.",
                    details={"ci_commands": [cmd for _, cmd in verify_like]},
                )
            )
        elif verify_like and declared_cmds:
            joined_local = "\n".join(declared_cmds).lower()
            for wf, ci_cmd in verify_like:
                # Match core binary/subcommand token (e.g. `pytest`, `ruff check`, `go test`, `cargo clippy`)
                tokens = ci_cmd.split()
                sig = " ".join(tokens[:2]).lower() if len(tokens) >= 2 else ci_cmd.lower()
                if ci_cmd.lower() not in joined_local and sig not in joined_local:
                    findings.append(
                        ProjectFinding(
                            rule="ADMISSION_CI_LOCAL_DRIFT",
                            category="admission",
                            severity="warning",
                            file=wf,
                            message=f"CI command `{ci_cmd}` in {wf} is not covered by verify.commands.",
                            remediation=(
                                f"Add `{ci_cmd}` (or an equivalent command) to verify.commands in "
                                ".birkin/harness.yaml so local and CI admission paths stay identical."
                            ),
                        )
                    )

    _ = found_entry
    return findings


def build_readiness_scorecard(
    repo_root: Path,
    spec: ProjectHarnessSpec,
    guide_findings: list[ProjectFinding],
    sensor_findings: list[ProjectFinding],
    ledger_entries: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Build a 6-axis research-backed harness readiness scorecard (no arbitrary scores)."""
    harness_file = find_harness_file(repo_root)
    all_findings = [*guide_findings, *sensor_findings]

    def _by_cat(cat: str) -> list[ProjectFinding]:
        return [f for f in all_findings if f.category == cat]

    orient_f = _by_cat("orientation")
    know_f = _by_cat("knowledge")
    arch_f = _by_cat("architecture")
    adm_f = _by_cat("admission")
    inv_f = _by_cat("invariant")

    has_entry_doc = any((repo_root / d).is_file() for d in spec.orientation.entry_docs)
    has_layers = bool(spec.architecture.layers or spec.architecture.forbidden_imports)
    has_verify = bool(spec.verify.commands)
    has_hooks = (repo_root / ".git" / "hooks" / "pre-commit").is_file() and (
        "birkin" in (repo_root / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8", errors="replace")
    )

    def _grade(has_capability: bool, findings: list[ProjectFinding]) -> str:
        if any(f.severity == "error" for f in findings):
            return "FAIL"
        if not has_capability or any(f.severity == "warning" for f in findings):
            return "WARN"
        return "PASS"

    return {
        "orientation": {
            "status": _grade(has_entry_doc and harness_file is not None, orient_f),
            "harness_spec": harness_file.relative_to(repo_root).as_posix() if harness_file else None,
            "entry_docs_present": [d for d in spec.orientation.entry_docs if (repo_root / d).is_file()],
            "findings": len(orient_f),
        },
        "knowledge": {
            "status": _grade(True, know_f),
            "findings": len(know_f),
        },
        "architecture": {
            "status": _grade(has_layers, arch_f),
            "layers_declared": len(spec.architecture.layers),
            "forbidden_import_rules": len(spec.architecture.forbidden_imports),
            "findings": len(arch_f),
        },
        "admission": {
            "status": _grade(has_verify, adm_f),
            "verify_commands": [c.name for c in spec.verify.commands],
            "findings": len(adm_f),
        },
        "sensors": {
            "status": _grade(True, inv_f),
            "custom_regex_rules": len(spec.invariants.custom_regex_rules),
            "semantic_rules": len(spec.semantic.rules),
            "semantic_enabled": spec.semantic.enabled,
            "findings": len(inv_f),
        },
        "observability": {
            "status": "PASS" if (ledger_entries or has_hooks) else "WARN",
            "git_pre_commit_wired": has_hooks,
            "receipt_count": len(ledger_entries),
        },
    }
