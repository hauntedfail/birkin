"""AHE Experience & Decision Observability: distill ledger receipts into steering signals.

Detects recurring violation hotspots, agent thrash loops, self-correction rates,
dead/stale rules eligible for pruning, and before/after harness-edit impact.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from birkin.ledger import read_receipts, resolve_ledger_path, verify_chain
from birkin.project_models import ProjectHarnessSpec


def _parse_ts(raw: Any) -> datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def analyze_telemetry(repo_root: Path, spec: ProjectHarnessSpec) -> dict[str, Any]:
    """Analyze the append-only receipt ledger and produce concrete harness steering recommendations."""
    ledger_path = resolve_ledger_path(repo_root, spec)
    entries = [e for e in read_receipts(ledger_path) if not e.get("_corrupt")]
    chain_ok, chain_errors = verify_chain(read_receipts(ledger_path))

    total_runs = len(entries)
    pass_runs = sum(1 for e in entries if e.get("exit_code") == 0 and e.get("outcome") == "PASS")
    fail_runs = total_runs - pass_runs

    rule_hits: Counter[str] = Counter()
    file_hits: Counter[str] = Counter()
    surface_counts: Counter[str] = Counter()
    rule_events_by_file: dict[tuple[str, str], list[datetime]] = defaultdict(list)

    # Track per-file episode resolution (fail -> subsequent pass on same file)
    open_fail_files: set[str] = set()
    fail_episodes = 0
    resolved_episodes = 0

    # Group outcomes by harness_sha256 in chronological encounter order (AHE Decision Observability)
    harness_order: list[str] = []
    harness_stats: dict[str, dict[str, Any]] = {}

    for entry in entries:
        surface_counts[str(entry.get("surface", "unknown"))] += 1
        ts = _parse_ts(entry.get("recorded_at"))
        hsha = str(entry.get("harness_sha256") or "unknown")
        if hsha not in harness_stats:
            harness_order.append(hsha)
            harness_stats[hsha] = {
                "harness_sha256": hsha[:12],
                "first_seen": entry.get("recorded_at"),
                "runs": 0,
                "passes": 0,
                "total_findings": 0,
            }
        hs = harness_stats[hsha]
        hs["runs"] += 1
        if entry.get("exit_code") == 0 and entry.get("outcome") == "PASS":
            hs["passes"] += 1
        hs["total_findings"] += int(entry.get("finding_count") or 0)

        rc = entry.get("rule_counts")
        affected = [str(f) for f in (entry.get("affected_files") or [])]
        checked = [str(f) for f in (entry.get("files_checked") or [])]

        if isinstance(rc, dict):
            for rule, count in rc.items():
                rule_hits[str(rule)] += int(count)
                if ts is not None:
                    for f in affected or ["<repo>"]:
                        rule_events_by_file[(str(rule), f)].append(ts)

        for f in affected:
            file_hits[f] += 1
            if f not in open_fail_files:
                open_fail_files.add(f)
                fail_episodes += 1

        # If a file was checked and had no findings this run, mark open fail episode resolved
        affected_set = set(affected)
        for f in checked:
            if f in open_fail_files and f not in affected_set:
                open_fail_files.remove(f)
                resolved_episodes += 1

    # Detect thrashing: >= thrash_threshold hits of the same rule on the same file within window
    thrash_window = timedelta(minutes=spec.telemetry.thrash_window_minutes)
    thrash_alerts: list[dict[str, Any]] = []
    for (rule, fpath), times in sorted(rule_events_by_file.items()):
        times.sort()
        max_in_window = 0
        left = 0
        for right, t_r in enumerate(times):
            while t_r - times[left] > thrash_window:
                left += 1
            max_in_window = max(max_in_window, right - left + 1)
        if max_in_window >= spec.telemetry.thrash_threshold:
            thrash_alerts.append(
                {
                    "rule": rule,
                    "file": fpath,
                    "hits_in_window": max_in_window,
                    "window_minutes": spec.telemetry.thrash_window_minutes,
                }
            )

    # Detect stale / never-fired declared rules (Anthropic harness simplification signal)
    declared_rules = [
        *[f"CUSTOM_REGEX:{r.id}" for r in spec.invariants.custom_regex_rules],
        *[f"SEMANTIC:{r.id}" for r in spec.semantic.rules],
        *[f"ARCH_FORBIDDEN_IMPORT:{r.id}" for r in spec.architecture.forbidden_imports],
    ]
    stale_candidates: list[str] = []
    if total_runs >= spec.telemetry.stale_rule_min_runs:
        for rule_name in declared_rules:
            if rule_hits.get(rule_name, 0) == 0:
                stale_candidates.append(rule_name)

    hotspots = [{"rule": r, "hits": c} for r, c in rule_hits.most_common(10)]
    file_hotspots = [{"file": f, "hits": c} for f, c in file_hits.most_common(10)]

    evolution: list[dict[str, Any]] = []
    for hsha in harness_order:
        hs = harness_stats[hsha]
        runs = hs["runs"]
        evolution.append(
            {
                **hs,
                "pass_rate": round(hs["passes"] / runs, 3) if runs else 0.0,
                "avg_findings": round(hs["total_findings"] / runs, 2) if runs else 0.0,
            }
        )

    recommendations: list[str] = []
    for alert in thrash_alerts:
        recommendations.append(
            f"Agent thrashing detected on '{alert['file']}' for rule '{alert['rule']}' "
            f"({alert['hits_in_window']}x in {alert['window_minutes']}m): clarify the rule's remediation text "
            "or promote this constraint into AGENTS.md feedforward guidance."
        )
    for item in hotspots[:3]:
        if item["hits"] >= 3:
            recommendations.append(
                f"Recurring violation '{item['rule']}' ({item['hits']} hits): add a short feedforward example "
                "to AGENTS.md so agents avoid it on the first attempt."
            )
    for stale in stale_candidates:
        recommendations.append(
            f"Rule '{stale}' never fired across {total_runs} runs: verify with `birkin eval-rules` "
            "and prune it if the underlying assumption is obsolete."
        )
    if not chain_ok:
        recommendations.append("Receipt ledger hash chain is broken; inspect tampering or corruption immediately.")

    return {
        "project": spec.project.name,
        "ledger_path": str(ledger_path),
        "chain_ok": chain_ok,
        "chain_errors": chain_errors,
        "total_runs": total_runs,
        "pass_runs": pass_runs,
        "fail_runs": fail_runs,
        "pass_rate": round(pass_runs / total_runs, 3) if total_runs else None,
        "surfaces": dict(surface_counts),
        "hotspots": hotspots,
        "file_hotspots": file_hotspots,
        "thrash_alerts": thrash_alerts,
        "self_correction": {
            "fail_episodes": fail_episodes,
            "resolved_episodes": resolved_episodes,
            "rate": round(resolved_episodes / fail_episodes, 3) if fail_episodes else None,
        },
        "stale_rule_candidates": stale_candidates,
        "harness_evolution": evolution,
        "recommendations": recommendations,
    }
