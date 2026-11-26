"""Vendor-agnostic inferential (semantic) sensor engine and rule self-calibration.

Evaluates narrow, single-predicate rules against changed hunks or files via any
OpenAI-compatible /chat/completions endpoint (e.g. local Magpie), and calibrates
every rule against its own examples_pass / examples_fail fixtures.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from birkin.constants import EXIT_LIVE_CONTRACT, EXIT_LIVE_TRANSIENT, EXIT_PASS
from birkin.project_models import ProjectFinding, ProjectHarnessSpec, SemanticRule

_SEMANTIC_SYSTEM_PROMPT = (
    "You are a strict, narrow code-review predicate evaluator. "
    "Evaluate ONLY the single rule predicate against the provided code/diff. "
    "Return ONLY valid JSON with exact keys: "
    '{"violated": bool, "probability": float (0..1), "confidence": float (0..1), '
    '"line": int or null, "evidence": string (short quote/reason), "suggestion": string}. '
    "Do not wrap in markdown fences or add commentary."
)


def _match_glob(rel_posix: str, pattern: str) -> bool:
    import fnmatch

    pat = pattern.strip().lstrip("./")
    if not pat:
        return False
    if "**" not in pat:
        return fnmatch.fnmatch(rel_posix, pat)
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


def _resolve_api_key(spec: ProjectHarnessSpec) -> str | None:
    env_name = spec.semantic.api_key_env
    if env_name and os.environ.get(env_name):
        return os.environ[env_name].strip()
    parsed = urlparse(spec.semantic.base_url)
    if parsed.hostname in ("127.0.0.1", "localhost", "::1"):
        return "magpie"
    return None


def collect_review_scope(
    repo_root: Path,
    *,
    staged: bool = False,
    diff_ref: str | None = None,
    files: list[Path] | None = None,
    max_chars: int = 24000,
) -> list[tuple[str, str]]:
    """Collect (repo_relative_path, content_or_diff) pairs for semantic evaluation."""
    resolved_root = repo_root.resolve()
    items: list[tuple[str, str]] = []

    if files:
        for f in files:
            p = f if f.is_absolute() else (resolved_root / f)
            p = p.resolve()
            if not p.is_file():
                continue
            try:
                rel = p.relative_to(resolved_root).as_posix()
            except ValueError:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")[:max_chars]
            items.append((rel, text))
        return items

    git_args = ["git", "-C", str(resolved_root), "diff", "--unified=3"]
    if staged:
        git_args.append("--cached")
    elif diff_ref:
        git_args.append(diff_ref)

    try:
        proc = subprocess.run(git_args, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0 or not proc.stdout.strip():
        return []

    # Split unified diff per file
    current_file: str | None = None
    buf: list[str] = []
    for line in proc.stdout.splitlines():
        if line.startswith("diff --git "):
            if current_file and buf:
                items.append((current_file, "\n".join(buf)[:max_chars]))
            parts = line.split()
            current_file = parts[3][2:] if len(parts) >= 4 and parts[3].startswith("b/") else None
            buf = [line]
        elif current_file is not None:
            buf.append(line)
    if current_file and buf:
        items.append((current_file, "\n".join(buf)[:max_chars]))
    return items


def _parse_verdict_json(raw_text: str) -> dict[str, Any]:
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    data = json.loads(cleaned)
    if not isinstance(data, dict):
        raise ValueError("Semantic evaluator response must be a JSON object")
    for req in ("violated", "probability", "confidence"):
        if req not in data:
            raise ValueError(f"Semantic evaluator response missing required key '{req}'")
    prob = data["probability"]
    conf = data["confidence"]
    if isinstance(prob, bool) or not isinstance(prob, (int, float)) or not (0.0 <= float(prob) <= 1.0):
        raise ValueError("probability must be a float in [0, 1]")
    if isinstance(conf, bool) or not isinstance(conf, (int, float)) or not (0.0 <= float(conf) <= 1.0):
        raise ValueError("confidence must be a float in [0, 1]")
    return {
        "violated": bool(data["violated"]),
        "probability": float(prob),
        "confidence": float(conf),
        "line": data.get("line") if isinstance(data.get("line"), int) and not isinstance(data.get("line"), bool) else None,
        "evidence": str(data.get("evidence") or "").strip(),
        "suggestion": str(data.get("suggestion") or "").strip(),
    }


def _query_semantic_predicate(
    client: httpx.Client,
    spec: ProjectHarnessSpec,
    rule: SemanticRule,
    target_label: str,
    snippet: str,
) -> tuple[int, dict[str, Any] | None, str | None]:
    """Send a single narrow Bernoulli predicate request; returns (exit_code, verdict, error_msg)."""
    url = spec.semantic.base_url.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    api_key = _resolve_api_key(spec)
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    user_prompt = (
        f"Rule ID: {rule.id}\n"
        f"Description: {rule.description}\n"
        f"Predicate (answer true if violated): {rule.predicate}\n"
        f"Target: {target_label}\n\n"
        f"Code/Diff:\n{snippet[: spec.semantic.max_diff_chars]}\n"
    )
    body = {
        "model": spec.semantic.model,
        "temperature": 0.0,
        "max_tokens": 256,
        "messages": [
            {"role": "system", "content": _SEMANTIC_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    }

    try:
        resp = client.post(url, headers=headers, json=body)
    except httpx.HTTPError as exc:
        return EXIT_LIVE_TRANSIENT, None, f"Semantic endpoint transport error: {exc}"

    if resp.status_code in (429, 500, 502, 503, 504):
        return EXIT_LIVE_TRANSIENT, None, f"Semantic endpoint transient HTTP {resp.status_code}"
    if resp.status_code != 200:
        return EXIT_LIVE_CONTRACT, None, f"Semantic endpoint contract HTTP {resp.status_code}: {resp.text[:200]}"

    try:
        payload = resp.json()
        if not isinstance(payload, dict):
            raise ValueError("non-object JSON body")
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ValueError("missing choices array")
        content = choices[0].get("message", {}).get("content")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("empty message content")
        verdict = _parse_verdict_json(content)
        return EXIT_PASS, verdict, None
    except Exception as exc:
        return EXIT_LIVE_CONTRACT, None, f"Invalid semantic response payload: {exc}"


def run_semantic_review(
    repo_root: Path,
    spec: ProjectHarnessSpec,
    *,
    staged: bool = False,
    diff_ref: str | None = None,
    files: list[Path] | None = None,
    transport: httpx.BaseTransport | None = None,
) -> tuple[int, list[ProjectFinding], dict[str, Any]]:
    """Run configured semantic rules against the selected diff/file scope."""
    if not spec.semantic.rules:
        return EXIT_PASS, [], {"evaluated": 0, "skipped_reason": "no_semantic_rules"}

    scope = collect_review_scope(
        repo_root,
        staged=staged,
        diff_ref=diff_ref,
        files=files,
        max_chars=spec.semantic.max_diff_chars,
    )
    if not scope:
        return EXIT_PASS, [], {"evaluated": 0, "skipped_reason": "empty_scope"}

    findings: list[ProjectFinding] = []
    worst_code = EXIT_PASS
    evaluated = 0
    advisories = 0
    fix_now = 0

    with httpx.Client(timeout=spec.semantic.timeout_seconds, transport=transport) as client:
        for rel, snippet in scope:
            for rule in spec.semantic.rules:
                if not any(_match_glob(rel, g) for g in rule.globs):
                    continue
                evaluated += 1
                code, verdict, err = _query_semantic_predicate(client, spec, rule, rel, snippet)
                if code != EXIT_PASS or verdict is None:
                    if code == EXIT_LIVE_CONTRACT:
                        worst_code = EXIT_LIVE_CONTRACT
                    elif worst_code == EXIT_PASS:
                        worst_code = code
                    findings.append(
                        ProjectFinding(
                            rule=f"SEMANTIC_PROVIDER_ERROR:{rule.id}",
                            category="semantic",
                            severity="error",
                            file=rel,
                            message=err or f"Semantic evaluation failed for rule '{rule.id}'.",
                            remediation="Check semantic.base_url/model/credentials; provider failure is never approval.",
                        )
                    )
                    continue

                if verdict["violated"] and verdict["probability"] >= rule.threshold:
                    is_blocking = rule.action == "fix_now"
                    if is_blocking:
                        fix_now += 1
                    else:
                        advisories += 1
                    findings.append(
                        ProjectFinding(
                            rule=f"SEMANTIC:{rule.id}",
                            category="semantic",
                            severity="error" if is_blocking else "warning",
                            file=rel,
                            line=verdict["line"],
                            message=(
                                f"{rule.description} "
                                f"(P={verdict['probability']:.2f}, conf={verdict['confidence']:.2f}): "
                                f"{verdict['evidence'] or rule.predicate}"
                            ),
                            remediation=verdict["suggestion"] or rule.remediation,
                            details={
                                "rule_id": rule.id,
                                "action": rule.action,
                                "probability": verdict["probability"],
                                "confidence": verdict["confidence"],
                                "threshold": rule.threshold,
                            },
                        )
                    )

    if worst_code == EXIT_PASS and fix_now > 0:
        from birkin.constants import EXIT_STATIC

        worst_code = EXIT_STATIC

    meta = {
        "evaluated": evaluated,
        "files": [rel for rel, _ in scope],
        "advisories": advisories,
        "fix_now": fix_now,
        "model": spec.semantic.model,
    }
    return worst_code, findings, meta


def evaluate_semantic_rules(
    spec: ProjectHarnessSpec,
    *,
    live: bool = False,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Calibrate semantic rules structurally (and empirically against examples when live/transport given)."""
    report: list[dict[str, Any]] = []
    all_ok = True

    client = (
        httpx.Client(timeout=spec.semantic.timeout_seconds, transport=transport)
        if (live or transport is not None)
        else None
    )
    try:
        for rule in spec.semantic.rules:
            missing_fixtures = not rule.examples_pass or not rule.examples_fail
            fp = 0
            fn = 0
            provider_errors: list[str] = []

            if client is not None and not missing_fixtures:
                for idx, ex in enumerate(rule.examples_pass):
                    code, verdict, err = _query_semantic_predicate(
                        client, spec, rule, f"fixture:pass:{idx}", ex
                    )
                    if code != EXIT_PASS or verdict is None:
                        provider_errors.append(err or "provider_error")
                    elif verdict["violated"] and verdict["probability"] >= rule.threshold:
                        fp += 1
                for idx, ex in enumerate(rule.examples_fail):
                    code, verdict, err = _query_semantic_predicate(
                        client, spec, rule, f"fixture:fail:{idx}", ex
                    )
                    if code != EXIT_PASS or verdict is None:
                        provider_errors.append(err or "provider_error")
                    elif not (verdict["violated"] and verdict["probability"] >= rule.threshold):
                        fn += 1

            passed = (not missing_fixtures) and (fp == 0) and (fn == 0) and (not provider_errors)
            if not passed:
                all_ok = False
            report.append(
                {
                    "id": rule.id,
                    "kind": "semantic",
                    "mode": "empirical" if client is not None else "structural",
                    "status": "PASS" if passed else "FAIL",
                    "examples_pass": len(rule.examples_pass),
                    "examples_fail": len(rule.examples_fail),
                    "false_positives": fp,
                    "false_negatives": fn,
                    "missing_fixtures": missing_fixtures,
                    "provider_errors": provider_errors,
                }
            )
    finally:
        if client is not None:
            client.close()

    return {"status": "PASS" if all_ok else "FAIL", "rules": report}
