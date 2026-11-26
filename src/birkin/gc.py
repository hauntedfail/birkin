"""Entropy and garbage-collection scanner for agent-maintained repositories.

Surfaces doc rot, untracked harness drafts, local-vs-CI drift, oversized modules,
architectural violations, and stale/never-fired harness rules in one prioritized report.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

from birkin.guides import audit_guides
from birkin.project_models import ProjectFinding, ProjectSpec
from birkin.sensors import run_project_sensors
from birkin.steer import analyze_telemetry


def _bucket_for_finding(finding: ProjectFinding) -> str:
    if finding.rule in ("KNOWLEDGE_BROKEN_DOC_LINK", "KNOWLEDGE_STALE_DOC_REVIEW", "KNOWLEDGE_MISSING_REQUIRED_DOC"):
        return "doc_rot"
    if finding.rule in (
        "ORIENTATION_UNTRACKED_SPEC_FILE",
        "ORIENTATION_ENTRY_DOC_BLOATED",
        "ORIENTATION_MISSING_ENTRY_DOC",
        "ADMISSION_CI_LOCAL_DRIFT",
        "ADMISSION_NO_LOCAL_VERIFY_DECLARED",
    ):
        return "spec_drift"
    if finding.category == "architecture":
        return "architecture_debt"
    if finding.category == "entropy":
        return "dead_rules"
    return "hygiene"


def run_gc_scan(
    repo_root: Path,
    spec: ProjectSpec,
    *,
    today: date | None = None,
) -> dict[str, Any]:
    """Scan repository for spec and codebase entropy and group items into cleanup buckets."""
    guide_findings = audit_guides(repo_root, spec, today=today)
    sensor_findings, checked_files = run_project_sensors(repo_root, spec)
    telemetry = analyze_telemetry(repo_root, spec)

    dead_rule_findings = [
        ProjectFinding(
            rule="ENTROPY_STALE_RULE",
            category="entropy",
            severity="info",
            message=f"Declared rule '{rule_name}' fired 0 times across {telemetry['total_runs']} runs.",
            remediation=(
                f"Run `birkin eval-rules` to verify '{rule_name}' still detects bad examples, "
                "or remove it to keep rule overhead minimal."
            ),
        )
        for rule_name in telemetry.get("stale_rule_candidates", [])
    ]

    all_findings = [*guide_findings, *sensor_findings, *dead_rule_findings]
    buckets: dict[str, list[dict[str, Any]]] = {
        "doc_rot": [],
        "spec_drift": [],
        "architecture_debt": [],
        "dead_rules": [],
        "hygiene": [],
    }
    for f in all_findings:
        buckets[_bucket_for_finding(f)].append(f.model_dump())

    errors = sum(1 for f in all_findings if f.severity == "error")
    warnings = sum(1 for f in all_findings if f.severity == "warning")
    return {
        "project": spec.project.name,
        "repo": str(repo_root.resolve()),
        "status": "CLEAN" if not all_findings else ("FAIL" if errors > 0 else "WARN"),
        "files_scanned": len(checked_files),
        "total_items": len(all_findings),
        "errors": errors,
        "warnings": warnings,
        "buckets": buckets,
        "findings": [f.model_dump() for f in all_findings],
    }
