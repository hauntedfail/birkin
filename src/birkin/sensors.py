"""Deterministic computational sensors for arbitrary multi-language repositories.

Enforces architecture layer DAGs, forbidden imports, file line budgets, secret leaks,
debug leftovers, English-prose invariants, custom regex rules, and canonical verify commands.
"""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from birkin.imports_parser import _detect_go_module, extract_imports_for_file
from birkin.project_models import LayerSpec, ProjectFinding, ProjectHarnessSpec

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PRIVATE_KEY_HEADER", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GITHUB_PAT", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")),
    ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")),
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[0-9]{10,}-[A-Za-z0-9\-]{10,}\b")),
)

_DEBUG_PATTERNS: tuple[tuple[str, re.Pattern[str], set[str]], ...] = (
    ("PYTHON_BREAKPOINT", re.compile(r"\b(?:breakpoint\(\)|pdb\.set_trace\(\))"), {".py"}),
    ("JS_DEBUGGER", re.compile(r"^\s*debugger\s*;?\s*$"), {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}),
)

_CJK_RE = re.compile(r"[\u3040-\u309f\u30a0-\u30ff\u4e00-\u9fff]")
_CODE_EXTENSIONS = {".py", ".go", ".rs", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
_TEXT_EXTENSIONS = _CODE_EXTENSIONS | {".md", ".yaml", ".yml", ".toml", ".json", ".sh", ".bash", ".zsh", ".txt"}


def match_glob(rel_posix: str, pattern: str) -> bool:
    """Match a repo-relative POSIX path against a glob supporting ** recursive segments."""
    pat = pattern.strip().lstrip("./")
    if not pat:
        return False
    # Fast exact/fnmatch check when no ** is present
    if "**" not in pat:
        return fnmatch.fnmatch(rel_posix, pat)
    # Translate glob to regex with ** matching across path separators
    regex_parts: list[str] = ["^"]
    i = 0
    n = len(pat)
    while i < n:
        if pat[i : i + 3] == "**/":
            regex_parts.append("(?:.*/)?")
            i += 3
        elif pat[i : i + 2] == "**":
            regex_parts.append(".*")
            i += 2
        elif pat[i] == "*":
            regex_parts.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            regex_parts.append("[^/]")
            i += 1
        else:
            regex_parts.append(re.escape(pat[i]))
            i += 1
    regex_parts.append("$")
    return re.match("".join(regex_parts), rel_posix) is not None


def matches_any(rel_posix: str, patterns: list[str]) -> bool:
    return any(match_glob(rel_posix, pat) for pat in patterns)


def _layer_for_path(rel_posix: str, layers: list[LayerSpec]) -> LayerSpec | None:
    for layer in layers:
        if matches_any(rel_posix, layer.paths):
            return layer
    return None


def collect_target_files(
    repo_root: Path,
    spec: ProjectHarnessSpec,
    files: list[Path] | None = None,
) -> list[Path]:
    """Collect non-excluded files in repo_root (or filter explicit file list)."""
    resolved_root = repo_root.resolve()
    excludes = spec.project.exclude_globs
    out: list[Path] = []

    if files is not None:
        for f in files:
            p = f if f.is_absolute() else (resolved_root / f)
            p = p.resolve()
            if not p.is_file():
                continue
            try:
                rel = p.relative_to(resolved_root).as_posix()
            except ValueError:
                continue
            if matches_any(rel, excludes):
                continue
            out.append(p)
        return sorted(set(out))

    for dirpath, dirnames, filenames in os.walk(resolved_root):
        rel_dir = Path(dirpath).relative_to(resolved_root).as_posix()
        # Prune excluded directories in-place for speed
        pruned: list[str] = []
        for d in sorted(dirnames):
            child_rel = d if rel_dir == "." else f"{rel_dir}/{d}"
            if matches_any(child_rel, excludes) or matches_any(child_rel + "/x", excludes):
                continue
            pruned.append(d)
        dirnames[:] = pruned

        for fname in sorted(filenames):
            child_rel = fname if rel_dir == "." else f"{rel_dir}/{fname}"
            if matches_any(child_rel, excludes):
                continue
            out.append(Path(dirpath) / fname)
    return out


def _is_comment_line(suffix: str, line: str) -> bool:
    stripped = line.lstrip()
    if suffix in (".py", ".sh", ".bash", ".zsh", ".yaml", ".yml", ".toml"):
        return stripped.startswith("#")
    if suffix in (".go", ".rs", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
        return stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")
    return False


def run_project_sensors(
    repo_root: Path,
    spec: ProjectHarnessSpec,
    *,
    files: list[Path] | None = None,
) -> tuple[list[ProjectFinding], list[str]]:
    """Run all deterministic computational sensors across target files."""
    resolved_root = repo_root.resolve()
    targets = collect_target_files(resolved_root, spec, files=files)
    findings: list[ProjectFinding] = []
    checked_rel: list[str] = []
    go_mod = _detect_go_module(resolved_root)

    compiled_custom: list[tuple[Any, re.Pattern[str]]] = []
    for rule in spec.invariants.custom_regex_rules:
        compiled_custom.append((rule, re.compile(rule.pattern)))

    for path in targets:
        rel = path.relative_to(resolved_root).as_posix()
        suffix = path.suffix.lower()
        checked_rel.append(rel)

        # Skip likely binary files
        if suffix and suffix not in _TEXT_EXTENSIONS:
            continue
        try:
            raw_bytes = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw_bytes[:4096]:
            continue
        text = raw_bytes.decode("utf-8", errors="replace")
        lines = text.splitlines()

        # 1. File line budget (code files only)
        if (
            suffix in _CODE_EXTENSIONS
            and len(lines) > spec.architecture.max_file_lines
            and not matches_any(rel, spec.architecture.file_line_exemptions)
        ):
            findings.append(
                ProjectFinding(
                    rule="ARCH_FILE_TOO_LARGE",
                    category="architecture",
                    severity="warning",
                    file=rel,
                    line=len(lines),
                    message=(
                        f"{rel} has {len(lines)} lines (budget: {spec.architecture.max_file_lines})."
                    ),
                    remediation=(
                        f"Split {rel} along cohesive responsibility boundaries or add a justified "
                        "exemption in architecture.file_line_exemptions."
                    ),
                )
            )

        # 2. Architecture layer DAG & forbidden imports
        if suffix in _CODE_EXTENSIONS and (spec.architecture.layers or spec.architecture.forbidden_imports):
            edges = extract_imports_for_file(path, resolved_root, go_module=go_mod)
            src_layer = _layer_for_path(rel, spec.architecture.layers)

            for edge in edges:
                if src_layer is not None and edge.resolved_path is not None:
                    dst_layer = _layer_for_path(edge.resolved_path, spec.architecture.layers)
                    if (
                        dst_layer is not None
                        and dst_layer.name != src_layer.name
                        and dst_layer.name not in src_layer.allowed_dependencies
                    ):
                        remediation = src_layer.remediation or (
                            f"Layer '{src_layer.name}' may only depend on "
                            f"{src_layer.allowed_dependencies or ['(none)']}. "
                            f"Remove import of '{edge.resolved_path}' (layer '{dst_layer.name}') or invert the dependency."
                        )
                        findings.append(
                            ProjectFinding(
                                rule="ARCH_LAYER_VIOLATION",
                                category="architecture",
                                severity="error",
                                file=rel,
                                line=edge.line,
                                message=(
                                    f"Layer boundary violation: '{rel}' (layer '{src_layer.name}') "
                                    f"imports '{edge.resolved_path}' (layer '{dst_layer.name}')."
                                ),
                                remediation=remediation,
                                details={
                                    "source_layer": src_layer.name,
                                    "target_layer": dst_layer.name,
                                    "raw_import": edge.raw,
                                    "resolved_target": edge.resolved_path,
                                },
                            )
                        )

                for frule in spec.architecture.forbidden_imports:
                    if not matches_any(rel, frule.from_globs):
                        continue
                    haystack = edge.resolved_path or edge.raw
                    if any(
                        fnmatch.fnmatch(edge.raw, pat) or fnmatch.fnmatch(haystack, pat)
                        for pat in frule.forbid_patterns
                    ):
                        findings.append(
                            ProjectFinding(
                                rule=f"ARCH_FORBIDDEN_IMPORT:{frule.id}",
                                category="architecture",
                                severity="error",
                                file=rel,
                                line=edge.line,
                                message=f"{frule.message} (import: {edge.raw})",
                                remediation=frule.remediation,
                                details={"rule_id": frule.id, "raw_import": edge.raw},
                            )
                        )

        # 3. High-precision secret scanner
        if spec.invariants.forbid_secrets and not matches_any(rel, spec.invariants.secret_exempt_globs):
            for line_no, line in enumerate(lines, start=1):
                for secret_kind, pat in _SECRET_PATTERNS:
                    if pat.search(line):
                        findings.append(
                            ProjectFinding(
                                rule=f"INVARIANT_SECRET_LEAK:{secret_kind}",
                                category="invariant",
                                severity="error",
                                file=rel,
                                line=line_no,
                                message=f"Potential hardcoded credential ({secret_kind}) detected in {rel}:{line_no}.",
                                remediation="Remove the literal secret and load it via an environment variable.",
                            )
                        )

        # 4. Debug leftover scanner
        if spec.invariants.forbid_debug_leftovers:
            for line_no, line in enumerate(lines, start=1):
                for dbg_kind, pat, exts in _DEBUG_PATTERNS:
                    if suffix in exts and pat.search(line):
                        findings.append(
                            ProjectFinding(
                                rule=f"INVARIANT_DEBUG_LEFTOVER:{dbg_kind}",
                                category="invariant",
                                severity="error",
                                file=rel,
                                line=line_no,
                                message=f"Debug leftover ({dbg_kind}) found in {rel}:{line_no}.",
                                remediation=f"Remove the debug statement at {rel}:{line_no} before committing.",
                            )
                        )

        # 5. English prose invariant (docs + code comments, honoring exemptions)
        if spec.invariants.english_prose_only and not matches_any(rel, spec.invariants.prose_exempt_globs):
            if suffix == ".md":
                for line_no, line in enumerate(lines, start=1):
                    if _CJK_RE.search(line):
                        findings.append(
                            ProjectFinding(
                                rule="INVARIANT_NON_ENGLISH_PROSE",
                                category="invariant",
                                severity="error",
                                file=rel,
                                line=line_no,
                                message=f"Non-English prose detected in documentation {rel}:{line_no}.",
                                remediation=(
                                    f"Translate prose at {rel}:{line_no} to English, or exempt intentional "
                                    "multilingual fixtures via invariants.prose_exempt_globs."
                                ),
                            )
                        )
                        break
            elif suffix in _CODE_EXTENSIONS:
                for line_no, line in enumerate(lines, start=1):
                    if _is_comment_line(suffix, line) and _CJK_RE.search(line):
                        findings.append(
                            ProjectFinding(
                                rule="INVARIANT_NON_ENGLISH_PROSE",
                                category="invariant",
                                severity="error",
                                file=rel,
                                line=line_no,
                                message=f"Non-English inline comment detected at {rel}:{line_no}.",
                                remediation=f"Translate comment at {rel}:{line_no} to English.",
                            )
                        )
                        break

        # 6. Custom regex rules
        for rule, pat in compiled_custom:
            if not matches_any(rel, rule.globs):
                continue
            if rule.exclude_globs and matches_any(rel, rule.exclude_globs):
                continue
            for line_no, line in enumerate(lines, start=1):
                if pat.search(line):
                    findings.append(
                        ProjectFinding(
                            rule=f"CUSTOM_REGEX:{rule.id}",
                            category="invariant",
                            severity=rule.severity,
                            file=rel,
                            line=line_no,
                            message=f"{rule.message} ({rel}:{line_no})",
                            remediation=rule.remediation,
                            details={"rule_id": rule.id},
                        )
                    )

    return findings, checked_rel


def run_verify_commands(
    repo_root: Path,
    spec: ProjectHarnessSpec,
) -> tuple[list[ProjectFinding], list[dict[str, Any]]]:
    """Run all canonical verify.commands declared in .birkin/harness.yaml."""
    findings: list[ProjectFinding] = []
    results: list[dict[str, Any]] = []

    for vc in spec.verify.commands:
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                vc.cmd,
                cwd=str(repo_root),
                shell=True,
                capture_output=True,
                text=True,
                timeout=vc.timeout_seconds,
                check=False,
            )
            dur_ms = int((time.monotonic() - t0) * 1000)
            ok = proc.returncode == 0
            tail = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()[-1500:]
            results.append(
                {
                    "name": vc.name,
                    "cmd": vc.cmd,
                    "kind": vc.kind,
                    "exit_code": proc.returncode,
                    "duration_ms": dur_ms,
                    "status": "PASS" if ok else "FAIL",
                    "output_tail": tail,
                }
            )
            if not ok:
                findings.append(
                    ProjectFinding(
                        rule=f"ADMISSION_VERIFY_FAILED:{vc.name}",
                        category="admission",
                        severity="error",
                        message=f"Canonical verify command '{vc.name}' (`{vc.cmd}`) failed with exit {proc.returncode}.",
                        remediation=f"Run `{vc.cmd}` locally, fix the reported failures, and re-run `birkin check --run-verify`.",
                        details={"exit_code": proc.returncode, "output_tail": tail[-600:]},
                    )
                )
        except subprocess.TimeoutExpired:
            dur_ms = int((time.monotonic() - t0) * 1000)
            results.append(
                {
                    "name": vc.name,
                    "cmd": vc.cmd,
                    "kind": vc.kind,
                    "exit_code": 124,
                    "duration_ms": dur_ms,
                    "status": "TIMEOUT",
                    "output_tail": f"Timed out after {vc.timeout_seconds}s",
                }
            )
            findings.append(
                ProjectFinding(
                    rule=f"ADMISSION_VERIFY_TIMEOUT:{vc.name}",
                    category="admission",
                    severity="error",
                    message=f"Canonical verify command '{vc.name}' timed out after {vc.timeout_seconds}s.",
                    remediation=f"Investigate hang in `{vc.cmd}` or raise timeout_seconds if justified.",
                )
            )
    return findings, results


def evaluate_regex_rules(spec: ProjectHarnessSpec) -> dict[str, Any]:
    """Proof-of-Life calibration of custom regex rules against their examples_pass/examples_fail."""
    report: list[dict[str, Any]] = []
    all_ok = True
    for rule in spec.invariants.custom_regex_rules:
        pat = re.compile(rule.pattern)
        false_positives = [ex for ex in rule.examples_pass if pat.search(ex) is not None]
        false_negatives = [ex for ex in rule.examples_fail if pat.search(ex) is None]
        missing_fixtures = not rule.examples_pass or not rule.examples_fail
        passed = not false_positives and not false_negatives and not missing_fixtures
        if not passed:
            all_ok = False
        report.append(
            {
                "id": rule.id,
                "kind": "regex",
                "status": "PASS" if passed else "FAIL",
                "examples_pass": len(rule.examples_pass),
                "examples_fail": len(rule.examples_fail),
                "false_positives": false_positives,
                "false_negatives": false_negatives,
                "missing_fixtures": missing_fixtures,
            }
        )
    return {"status": "PASS" if all_ok else "FAIL", "rules": report}
