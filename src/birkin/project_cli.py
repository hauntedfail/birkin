"""Project-universal Harness Engineering command handlers and human formatters."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from birkin.constants import DEFAULT_HERMES_HOME, EXIT_PASS, EXIT_STATIC, EXIT_TOOL_ERROR
from birkin.gc import run_gc_scan
from birkin.guides import audit_guides, build_readiness_scorecard
from birkin.hooks import (
    extract_claude_edited_paths,
    install_claude_hook,
    install_git_pre_commit_hook,
    install_hermes_plugin,
    read_claude_stdin_payload,
    run_post_edit_hook,
    run_pre_commit_hook,
)
from birkin.ledger import (
    append_receipt,
    canonical_spec_sha256,
    read_receipts,
    resolve_ledger_path,
    verify_receipts_for_current_state,
)
from birkin.project_init import detect_project_spec, render_agent_guide, render_spec_yaml
from birkin.project_models import (
    ProjectFinding,
    ProjectSpec,
    find_repo_root,
    find_spec_file,
    load_project_spec,
)
from birkin.semantic import evaluate_semantic_rules, run_semantic_review
from birkin.sensors import evaluate_regex_rules, run_project_sensors, run_verify_commands
from birkin.steer import analyze_telemetry


def _load_or_detect(path: Path, explicit_spec: Path | None = None) -> tuple[Path, ProjectSpec, Path | None]:
    repo_root = find_repo_root(path)
    if explicit_spec is not None or find_spec_file(repo_root) is not None:
        spec, spec_path = load_project_spec(repo_root, explicit_path=explicit_spec)
        return repo_root, spec, spec_path
    return repo_root, detect_project_spec(repo_root), None


def _emit(data: Any, *, as_json: bool, human: str) -> None:
    if as_json:
        print(json.dumps(data, indent=2))
    else:
        print(human)


def _format_findings(findings: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for f in findings:
        loc = f"{f['file']}:{f['line']}" if f.get("file") and f.get("line") else (f.get("file") or "<repo>")
        lines.append(f"  - [{f['severity'].upper()}] {f['rule']} ({loc}): {f['message']}")
        lines.append(f"    remediation: {f['remediation']}")
    return lines


def handle_init(args: argparse.Namespace) -> int:
    repo_root = find_repo_root(args.path)
    spec = detect_project_spec(repo_root)
    rendered = render_spec_yaml(spec)
    target = repo_root / ".birkin" / "config.yaml"

    if args.write:
        if target.exists() and not args.force:
            err = f"Birkin spec already exists at {target} (pass --force to overwrite)"
            _emit({"status": "ERROR", "error": err}, as_json=args.as_json, human=f"ERROR: {err}")
            return EXIT_TOOL_ERROR
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        out = {
            "status": "WRITTEN",
            "path": str(target),
            "languages": spec.project.languages,
            "verify_commands": [c.cmd for c in spec.verify.commands],
        }
        _emit(
            out,
            as_json=args.as_json,
            human=f"Wrote {target} (languages={spec.project.languages}, verify={len(spec.verify.commands)})",
        )
        return EXIT_PASS

    if args.as_json:
        print(json.dumps(spec.model_dump(mode="json"), indent=2))
    else:
        print(rendered)
    return EXIT_PASS


def handle_guide(args: argparse.Namespace) -> int:
    repo_root, spec, _ = _load_or_detect(args.path, args.spec)
    telemetry = analyze_telemetry(repo_root, spec)
    guide = render_agent_guide(repo_root, spec, steering=telemetry)
    if args.as_json:
        print(json.dumps({"project": spec.project.name, "repo": str(repo_root), "guide": guide}, indent=2))
    else:
        print(guide, end="")
    return EXIT_PASS


def handle_audit(args: argparse.Namespace) -> int:
    t0 = time.monotonic()
    repo_root, spec, spec_path = _load_or_detect(args.path, args.spec)
    guide_findings = audit_guides(repo_root, spec)
    sensor_findings, checked = run_project_sensors(repo_root, spec)
    ledger_entries = read_receipts(resolve_ledger_path(repo_root, spec))
    scorecard = build_readiness_scorecard(repo_root, spec, guide_findings, sensor_findings, ledger_entries)

    all_findings = [*guide_findings, *sensor_findings]
    has_errors = any(f.severity == "error" for f in all_findings)
    exit_code = EXIT_STATIC if has_errors else EXIT_PASS
    dur_ms = int((time.monotonic() - t0) * 1000)

    report = {
        "command": "audit",
        "project": spec.project.name,
        "repo": str(repo_root),
        "spec_path": str(spec_path) if spec_path else None,
        "spec_sha256": canonical_spec_sha256(spec),
        "status": "FAIL" if has_errors else "PASS",
        "exit_code": exit_code,
        "duration_ms": dur_ms,
        "files_scanned": len(checked),
        "scorecard": scorecard,
        "findings": [f.model_dump() for f in all_findings],
    }

    lines = [
        f"birkin audit ({spec.project.name}): status={report['status']} files={len(checked)} ({dur_ms}ms)",
        f"  spec_path: {report['spec_path'] or '(auto-inferred; run `birkin init --write`)'}",
    ]
    for axis, info in scorecard.items():
        lines.append(f"  [{axis:13s}] {info['status']}")
    if report["findings"]:
        lines.append(f"  findings ({len(report['findings'])}):")
        lines.extend(_format_findings(report["findings"]))
    _emit(report, as_json=args.as_json, human="\n".join(lines))
    return exit_code


def handle_check(args: argparse.Namespace) -> int:
    t0 = time.monotonic()
    repo_root, spec, spec_path = _load_or_detect(args.path, args.spec)
    target_files = [Path(f) for f in args.files] if args.files else None

    findings: list[ProjectFinding] = []
    sensor_findings, checked = run_project_sensors(repo_root, spec, files=target_files)
    findings.extend(sensor_findings)

    if target_files is None and not args.no_guides:
        findings.extend(audit_guides(repo_root, spec))

    verify_results: list[dict[str, Any]] = []
    if args.run_verify:
        v_findings, verify_results = run_verify_commands(repo_root, spec)
        findings.extend(v_findings)

    dur_ms = int((time.monotonic() - t0) * 1000)
    has_errors = any(f.severity == "error" for f in findings)
    exit_code = EXIT_STATIC if has_errors else EXIT_PASS

    receipt: dict[str, Any] | None = None
    if spec.telemetry.enabled and not args.no_receipt:
        cmd_label = "verify" if args.run_verify else "check"
        receipt = append_receipt(
            repo_root,
            spec,
            command=cmd_label,
            surface=args.surface,
            outcome="FAIL" if has_errors else "PASS",
            exit_code=exit_code,
            duration_ms=dur_ms,
            findings=[f.model_dump() for f in findings],
            files=checked,
            meta={"verify_commands": [r["name"] for r in verify_results]},
        )
        # Also record a separate `check` receipt when --run-verify passed both sensors and verify
        if args.run_verify:
            sensor_errors = any(f.severity == "error" and f.category != "admission" for f in findings)
            append_receipt(
                repo_root,
                spec,
                command="check",
                surface=args.surface,
                outcome="FAIL" if sensor_errors else "PASS",
                exit_code=EXIT_STATIC if sensor_errors else EXIT_PASS,
                duration_ms=dur_ms,
                findings=[f.model_dump() for f in findings if f.category != "admission"],
                files=checked,
            )

    report = {
        "command": "check",
        "project": spec.project.name,
        "repo": str(repo_root),
        "spec_path": str(spec_path) if spec_path else None,
        "status": "FAIL" if has_errors else "PASS",
        "exit_code": exit_code,
        "duration_ms": dur_ms,
        "files_checked": len(checked),
        "verify_results": verify_results,
        "findings": [f.model_dump() for f in findings],
        "receipt_sha256": receipt["receipt_sha256"] if receipt else None,
    }

    lines = [
        f"birkin check ({spec.project.name}): status={report['status']} "
        f"files={len(checked)} findings={len(findings)} ({dur_ms}ms)"
    ]
    for vr in verify_results:
        lines.append(f"  [verify:{vr['name']}] {vr['status']} ({vr['duration_ms']}ms) `{vr['cmd']}`")
    lines.extend(_format_findings(report["findings"]))
    if receipt:
        lines.append(f"  receipt: {receipt['receipt_sha256'][:16]} (head={str(receipt['git_head'])[:10]})")
    _emit(report, as_json=args.as_json, human="\n".join(lines))
    return exit_code


def handle_review(args: argparse.Namespace) -> int:
    t0 = time.monotonic()
    repo_root, spec, _ = _load_or_detect(args.path, args.spec)
    target_files = [Path(f) for f in args.files] if args.files else None
    code, findings, meta = run_semantic_review(
        repo_root,
        spec,
        staged=args.staged,
        diff_ref=args.diff,
        files=target_files,
    )
    dur_ms = int((time.monotonic() - t0) * 1000)

    if spec.telemetry.enabled and not args.no_receipt and meta.get("evaluated", 0) > 0:
        append_receipt(
            repo_root,
            spec,
            command="review",
            surface="cli",
            outcome="PASS" if code == EXIT_PASS else "FAIL",
            exit_code=code,
            duration_ms=dur_ms,
            findings=[f.model_dump() for f in findings],
            files=meta.get("files", []),
            meta={"model": meta.get("model")},
        )

    report = {
        "command": "review",
        "project": spec.project.name,
        "status": "PASS" if code == EXIT_PASS else "FAIL",
        "exit_code": code,
        "duration_ms": dur_ms,
        "meta": meta,
        "findings": [f.model_dump() for f in findings],
    }
    lines = [
        f"birkin review ({spec.project.name}): status={report['status']} "
        f"evaluated={meta.get('evaluated', 0)} fix_now={meta.get('fix_now', 0)} "
        f"advisories={meta.get('advisories', 0)} ({dur_ms}ms)"
    ]
    lines.extend(_format_findings(report["findings"]))
    _emit(report, as_json=args.as_json, human="\n".join(lines))
    return code


def handle_eval_rules(args: argparse.Namespace) -> int:
    repo_root, spec, _ = _load_or_detect(args.path, args.spec)
    regex_eval = evaluate_regex_rules(spec)
    sem_eval = evaluate_semantic_rules(spec, live=args.live)
    all_rules = [*regex_eval["rules"], *sem_eval["rules"]]
    ok = regex_eval["status"] == "PASS" and sem_eval["status"] == "PASS"
    report = {
        "command": "eval-rules",
        "project": spec.project.name,
        "status": "PASS" if ok else "FAIL",
        "exit_code": EXIT_PASS if ok else EXIT_STATIC,
        "total_rules": len(all_rules),
        "rules": all_rules,
    }
    lines = [f"birkin eval-rules ({spec.project.name}): status={report['status']} rules={len(all_rules)}"]
    for r in all_rules:
        lines.append(
            f"  - [{r['status']}] {r['kind']}:{r['id']} "
            f"(pass={r['examples_pass']} fail={r['examples_fail']} "
            f"fp={r['false_positives'] if isinstance(r['false_positives'], int) else len(r['false_positives'])} "
            f"fn={r['false_negatives'] if isinstance(r['false_negatives'], int) else len(r['false_negatives'])})"
        )
    _emit(report, as_json=args.as_json, human="\n".join(lines))
    return report["exit_code"]


def handle_hook(args: argparse.Namespace) -> int:
    if args.hook_action == "post-edit":
        if args.claude_stdin:
            try:
                payload = read_claude_stdin_payload()
            except Exception:
                return EXIT_PASS
            paths = extract_claude_edited_paths(payload)
            if not paths:
                return EXIT_PASS
            code, findings, feedback = run_post_edit_hook(
                paths,
                surface="claude-hook",
                include_semantic=args.semantic,
                require_spec=False,
            )
            if findings and feedback:
                print(
                    json.dumps(
                        {
                            "hookSpecificOutput": {
                                "hookEventName": "PostToolUse",
                                "additionalContext": feedback,
                            }
                        }
                    )
                )
            return code if args.block_on_error else EXIT_PASS

        paths = [Path(f) for f in args.files]
        code, findings, feedback = run_post_edit_hook(
            paths,
            surface=args.surface,
            include_semantic=args.semantic,
            require_spec=args.require_spec,
        )
        if feedback:
            print(feedback, file=sys.stderr if code != EXIT_PASS else sys.stdout)
        return code if args.block_on_error else EXIT_PASS

    if args.hook_action == "pre-commit":
        repo_root = find_repo_root(args.path)
        code, _, feedback = run_pre_commit_hook(repo_root)
        if feedback:
            print(feedback, file=sys.stderr if code != EXIT_PASS else sys.stdout)
        return code

    if args.hook_action == "pre-complete":
        repo_root, spec, _ = _load_or_detect(args.path, None)
        reqs = [c.strip() for c in args.require.split(",") if c.strip()]
        res = verify_receipts_for_current_state(
            repo_root,
            spec,
            required_commands=reqs,
            require_clean=args.require_clean,
        )
        ok = res["status"] == "PASS"
        if not ok:
            print(
                f"[birkin] Completion blocked: missing passing receipts for exact current state: "
                f"{res['missing']} (chain_ok={res['chain_ok']}). Run `birkin check --run-verify` first.",
                file=sys.stderr,
            )
        return EXIT_PASS if ok else EXIT_STATIC

    return EXIT_TOOL_ERROR


def handle_install_hooks(args: argparse.Namespace) -> int:
    results: list[dict[str, Any]] = []
    targets = ["git", "claude", "hermes"] if args.target == "all" else [args.target]
    repo_root = find_repo_root(args.path)

    for target in targets:
        if target == "git":
            results.append(install_git_pre_commit_hook(repo_root))
        elif target == "claude":
            settings_path = (
                Path.home() / ".claude" / "settings.json"
                if args.global_install
                else (repo_root / ".claude" / "settings.local.json")
            )
            results.append(install_claude_hook(settings_path))
        elif target == "hermes":
            plugins_dir = args.hermes_home / "plugins"
            results.append(install_hermes_plugin(plugins_dir))

    report = {"command": "install-hooks", "status": "PASS", "installed": results}
    lines = ["birkin install-hooks:"]
    for item in results:
        lines.append(f"  - [{item['target']}] {item['status']} -> {item['path']}")
    _emit(report, as_json=args.as_json, human="\n".join(lines))
    return EXIT_PASS


def handle_receipt(args: argparse.Namespace) -> int:
    repo_root, spec, _ = _load_or_detect(args.path, args.spec)
    reqs = [c.strip() for c in args.require.split(",") if c.strip()]
    res = verify_receipts_for_current_state(
        repo_root,
        spec,
        required_commands=reqs,
        require_clean=args.require_clean,
    )
    ok = res["status"] == "PASS"
    lines = [
        f"birkin receipt verify ({spec.project.name}): status={res['status']} "
        f"chain_ok={res['chain_ok']} head={str(res['git_head'])[:10]} dirty={res['git_dirty']}",
        f"  matched: {list(res['matched'].keys())}",
        f"  missing: {res['missing']}",
    ]
    _emit(res, as_json=args.as_json, human="\n".join(lines))
    return EXIT_PASS if ok else EXIT_STATIC


def handle_steer(args: argparse.Namespace) -> int:
    repo_root, spec, _ = _load_or_detect(args.path, args.spec)
    report = analyze_telemetry(repo_root, spec)
    lines = [
        f"birkin steer ({spec.project.name}): runs={report['total_runs']} "
        f"pass_rate={report['pass_rate']} chain_ok={report['chain_ok']}",
        f"  surfaces: {report['surfaces']}",
        f"  self_correction: {report['self_correction']}",
    ]
    if report["hotspots"]:
        lines.append("  top hotspots:")
        for h in report["hotspots"][:5]:
            lines.append(f"    - {h['rule']}: {h['hits']} hit(s)")
    if report["thrash_alerts"]:
        lines.append("  thrash alerts:")
        for a in report["thrash_alerts"]:
            lines.append(f"    - {a['file']} :: {a['rule']} ({a['hits_in_window']}x in {a['window_minutes']}m)")
    if report["spec_evolution"]:
        lines.append("  spec evolution (by spec_sha256):")
        for ev in report["spec_evolution"][-5:]:
            lines.append(
                f"    - {ev['spec_sha256']}: runs={ev['runs']} pass_rate={ev['pass_rate']} avg_findings={ev['avg_findings']}"
            )
    if report["recommendations"]:
        lines.append("  recommendations:")
        for rec in report["recommendations"]:
            lines.append(f"    * {rec}")
    _emit(report, as_json=args.as_json, human="\n".join(lines))
    return EXIT_PASS if report["chain_ok"] else EXIT_STATIC


def handle_gc(args: argparse.Namespace) -> int:
    repo_root, spec, _ = _load_or_detect(args.path, args.spec)
    report = run_gc_scan(repo_root, spec)
    lines = [
        f"birkin gc ({spec.project.name}): status={report['status']} "
        f"files={report['files_scanned']} items={report['total_items']} "
        f"(errors={report['errors']}, warnings={report['warnings']})"
    ]
    for bucket, items in report["buckets"].items():
        if items:
            lines.append(f"  [{bucket}] ({len(items)}):")
            lines.extend(_format_findings(items))
    _emit(report, as_json=args.as_json, human="\n".join(lines))
    return EXIT_STATIC if report["errors"] > 0 else EXIT_PASS


def register_project_subcommands(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Attach all project-universal Birkin subcommands to the CLI parser."""

    def add_project_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("path", nargs="?", type=Path, default=Path("."))
        sp.add_argument("--spec", type=Path, default=None, help="Explicit .birkin/config.yaml path")
        sp.add_argument("--json", action="store_true", dest="as_json")

    p_init = sub.add_parser("init", help="Auto-detect repo stack and preview or write .birkin/config.yaml")
    p_init.add_argument("path", nargs="?", type=Path, default=Path("."))
    p_init.add_argument("--write", action="store_true", help="Write .birkin/config.yaml to disk")
    p_init.add_argument("--force", action="store_true", help="Overwrite an existing .birkin/config.yaml")
    p_init.add_argument("--json", action="store_true", dest="as_json")

    p_guide = sub.add_parser("guide", help="Emit compact feedforward brief for coding agents")
    add_project_common(p_guide)

    p_audit = sub.add_parser("audit", help="Run 6-axis harness engineering readiness audit on any repo")
    add_project_common(p_audit)

    p_check = sub.add_parser("check", help="Run deterministic computational sensors and optional verify commands")
    add_project_common(p_check)
    p_check.add_argument("--files", nargs="*", default=None, help="Restrict sensors to specific files")
    p_check.add_argument("--run-verify", action="store_true", help="Also execute canonical verify.commands")
    p_check.add_argument("--no-guides", action="store_true", help="Skip orientation/doc-link checks")
    p_check.add_argument("--no-receipt", action="store_true", help="Do not append receipt to ledger")
    p_check.add_argument("--surface", default="cli", help="Execution surface label recorded in receipt")

    p_review = sub.add_parser("review", help="Run narrow semantic (inferential) rules against diffs or files")
    add_project_common(p_review)
    p_review.add_argument("--staged", action="store_true", help="Review staged git diff")
    p_review.add_argument("--diff", default=None, help="Review git diff against ref (e.g. HEAD~1)")
    p_review.add_argument("--files", nargs="*", default=None, help="Review explicit file(s)")
    p_review.add_argument("--no-receipt", action="store_true")

    p_eval = sub.add_parser("eval-rules", help="Calibrate custom regex and semantic rules on pass/fail fixtures")
    add_project_common(p_eval)
    p_eval.add_argument("--live", action="store_true", help="Also execute semantic fixtures against live endpoint")

    p_hook = sub.add_parser("hook", help="Real-time agent/git hook adapter (post-edit, pre-commit, pre-complete)")
    hsub = p_hook.add_subparsers(dest="hook_action", required=True)

    p_hpost = hsub.add_parser("post-edit", help="Sub-second edit-time feedback hook")
    p_hpost.add_argument("--files", nargs="*", default=[], help="Edited file path(s)")
    p_hpost.add_argument("--claude-stdin", action="store_true", help="Read Claude Code PostToolUse JSON from stdin")
    p_hpost.add_argument("--semantic", action="store_true", help="Also run semantic rules if enabled")
    p_hpost.add_argument("--block-on-error", action="store_true", help="Exit non-zero on error findings")
    p_hpost.add_argument("--require-spec", action="store_true", help="Run even when no .birkin/config.yaml exists")
    p_hpost.add_argument("--surface", default="hook")

    p_hpre = hsub.add_parser("pre-commit", help="Git pre-commit hook over staged files")
    p_hpre.add_argument("path", nargs="?", type=Path, default=Path("."))

    p_hcomp = hsub.add_parser("pre-complete", help="Verify exact-revision receipts before claiming completion")
    p_hcomp.add_argument("path", nargs="?", type=Path, default=Path("."))
    p_hcomp.add_argument("--require", default="check,verify", help="Comma-separated required passing commands")
    p_hcomp.add_argument("--require-clean", action="store_true")

    p_inst = sub.add_parser("install-hooks", help="Idempotently wire Birkin into git, Claude Code, and Hermes")
    p_inst.add_argument("path", nargs="?", type=Path, default=Path("."))
    p_inst.add_argument("--target", choices=["git", "claude", "hermes", "all"], required=True)
    p_inst.add_argument("--global", dest="global_install", action="store_true", help="Install Claude hook globally")
    p_inst.add_argument("--hermes-home", type=Path, default=DEFAULT_HERMES_HOME)
    p_inst.add_argument("--json", action="store_true", dest="as_json")

    p_rcpt = sub.add_parser("receipt", help="Verify hash-chained revision-pinned receipts")
    rsub = p_rcpt.add_subparsers(dest="receipt_action", required=True)
    p_rver = rsub.add_parser("verify", help="Prove exact current HEAD/tree has passing receipts")
    add_project_common(p_rver)
    p_rver.add_argument("--require", default="check", help="Comma-separated required commands (e.g. check,verify)")
    p_rver.add_argument("--require-clean", action="store_true")

    for alias in ("steer", "telemetry"):
        p_st = sub.add_parser(alias, help="AHE experience & decision observability steering report")
        add_project_common(p_st)

    p_gc = sub.add_parser("gc", help="Entropy and garbage-collection sweep across docs, harness, and code")
    add_project_common(p_gc)


PROJECT_COMMANDS = {
    "init": handle_init,
    "guide": handle_guide,
    "audit": handle_audit,
    "check": handle_check,
    "review": handle_review,
    "eval-rules": handle_eval_rules,
    "hook": handle_hook,
    "install-hooks": handle_install_hooks,
    "receipt": handle_receipt,
    "steer": handle_steer,
    "telemetry": handle_steer,
    "gc": handle_gc,
}
