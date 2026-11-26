#!/usr/bin/env python3
"""CLI entrypoint for Birkin — Universal Harness Engineering Engine & Hermes Verifier.

Exit codes:
  0 = PASS
  1 = STATIC / POLICY / HARNESS VIOLATION
  2 = LIVE CONTRACT VIOLATION (404/401/403/400, missing model, context mismatch, invalid semantic response)
  3 = LIVE TRANSIENT UNAVAILABLE (429/5xx/network/timeout)
  4 = RUNTIME DRIFT (gateway process older than config/.env or code SHA mismatch)
  5 = TOOL / IO / SCHEMA ERROR
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from birkin.config_utils import (
    canonical_config_sha256,
    load_policy,
    load_yaml_file,
    parse_dotenv_keys,
    read_env_secret,
)
from birkin.constants import (
    DEFAULT_HERMES_HOME,
    EXIT_DRIFT,
    EXIT_LIVE_CONTRACT,
    EXIT_LIVE_TRANSIENT,
    EXIT_PASS,
    EXIT_STATIC,
    EXIT_TOOL_ERROR,
)
from birkin.drift import verify_drift
from birkin.live import verify_live
from birkin.models import (
    CompressionInvariantsPolicy,
    DriftInvariantsPolicy,
    FallbackPolicy,
    Finding,
    HarnessPolicy,
    LiveContractPolicy,
    ProviderInvariantsPolicy,
    SkillsInvariantsPolicy,
)
from birkin.project_cli import PROJECT_COMMANDS, register_project_subcommands
from birkin.report import combine_exit_codes, format_human, write_state_atomic
from birkin.static import verify_static

__all__ = [
    "CompressionInvariantsPolicy",
    "DEFAULT_HERMES_HOME",
    "DriftInvariantsPolicy",
    "EXIT_DRIFT",
    "EXIT_LIVE_CONTRACT",
    "EXIT_LIVE_TRANSIENT",
    "EXIT_PASS",
    "EXIT_STATIC",
    "EXIT_TOOL_ERROR",
    "FallbackPolicy",
    "Finding",
    "HarnessPolicy",
    "LiveContractPolicy",
    "ProviderInvariantsPolicy",
    "SkillsInvariantsPolicy",
    "build_parser",
    "canonical_config_sha256",
    "load_policy",
    "load_yaml_file",
    "main",
    "parse_dotenv_keys",
    "read_env_secret",
    "verify_drift",
    "verify_live",
    "verify_static",
]


def _add_hermes_subcommands(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--home", type=Path, default=DEFAULT_HERMES_HOME)
        sp.add_argument("--config", type=Path, default=None)
        sp.add_argument("--policy", type=Path, default=None)
        sp.add_argument("--env", type=Path, default=None)
        sp.add_argument("--json", action="store_true", dest="as_json")

    add_common(sub.add_parser("static", help="[Hermes] Run structural, semantic, and policy checks"))

    p_live = sub.add_parser("live", help="[Hermes] Run live provider /v1/models contract checks")
    add_common(p_live)
    p_live.add_argument("--probe", action="store_true", help="Also run 1-token micro-probe")
    p_live.add_argument("--timeout", type=float, default=None)

    add_common(sub.add_parser("drift", help="[Hermes] Prove running gateway matches on-disk config and code"))

    p_all = sub.add_parser("all", help="[Hermes] Run static, optional live, and drift checks")
    add_common(p_all)
    p_all.add_argument("--live", action="store_true", help="Include live /v1/models contract check")
    p_all.add_argument("--probe", action="store_true", help="Include 1-token micro-probe (implies --live)")
    p_all.add_argument("--timeout", type=float, default=None)
    p_all.add_argument(
        "--skip-drift",
        action="store_true",
        help="Skip live gateway drift check (for CLI-only/CI runs)",
    )
    p_all.add_argument("--no-write-state", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="birkin",
        description="Birkin — Portable Harness Engineering Engine & Hermes Runtime Verifier",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # Project-universal harness engineering commands
    register_project_subcommands(sub)

    # Hermes runtime verifier (top-level backward-compatible aliases + `birkin hermes ...`)
    _add_hermes_subcommands(sub)
    p_hermes = sub.add_parser("hermes", help="Hermes Agent runtime verifier (static, live, drift, all)")
    hsub = p_hermes.add_subparsers(dest="hermes_command", required=True)
    _add_hermes_subcommands(hsub)

    return p


def _run_hermes_command(args: argparse.Namespace, cmd: str) -> int:
    hermes_home: Path = args.home
    config_path: Path = args.config or (hermes_home / "config.yaml")
    explicit_policy: Path | None = args.policy
    policy_path: Path = explicit_policy or (hermes_home / "birkin-policy.yaml")
    env_path: Path = args.env or (hermes_home / ".env")

    try:
        cfg = load_yaml_file(config_path)
        if explicit_policy is not None:
            if not explicit_policy.exists():
                raise FileNotFoundError(f"Explicit policy file not found: {explicit_policy}")
            policy = load_policy(explicit_policy)
        elif policy_path.exists():
            policy = load_policy(policy_path)
        else:
            policy = HarnessPolicy()
    except Exception as exc:
        err = {
            "command": cmd,
            "status": "ERROR",
            "exit_code": EXIT_TOOL_ERROR,
            "error": str(exc),
        }
        print(json.dumps(err, indent=2) if args.as_json else f"ERROR: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR

    cfg_sha256 = canonical_config_sha256(cfg)
    sections: dict[str, Any] = {}
    codes: list[int] = []

    if cmd in ("static", "all"):
        c, f = verify_static(cfg, policy, env_path=env_path, skills_dir=hermes_home / "skills")
        codes.append(c)
        sections["static"] = {
            "exit_code": c,
            "findings": [item.model_dump() for item in f],
        }

    if cmd == "live" or (cmd == "all" and (args.live or args.probe)):
        c, f, meta = verify_live(
            cfg,
            policy,
            env_path=env_path,
            probe=getattr(args, "probe", False),
            timeout=getattr(args, "timeout", None),
        )
        codes.append(c)
        sections["live"] = {
            "exit_code": c,
            "meta": meta,
            "findings": [item.model_dump() for item in f],
        }

    if cmd == "drift" or (cmd == "all" and not getattr(args, "skip_drift", False)):
        c, f, meta = verify_drift(
            config_path,
            env_path,
            hermes_home,
            policy,
            config_sha256=cfg_sha256,
        )
        codes.append(c)
        sections["drift"] = {
            "exit_code": c,
            "meta": meta,
            "findings": [item.model_dump() for item in f],
        }

    final_code = combine_exit_codes(codes)
    report = {
        "command": cmd,
        "checked_at": datetime.now(UTC).isoformat(),
        "status": "PASS" if final_code == EXIT_PASS else "FAIL",
        "exit_code": final_code,
        "config_sha256": cfg_sha256,
        "sections": sections,
    }

    if cmd == "all" and not getattr(args, "no_write_state", False):
        state_file = hermes_home / "state" / "birkin.json"
        try:
            write_state_atomic(state_file, report)
        except OSError as exc:
            print(f"WARNING: failed to write {state_file}: {exc}", file=sys.stderr)

    if args.as_json:
        print(json.dumps(report, indent=2))
    else:
        print(format_human(report))

    return final_code


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command in PROJECT_COMMANDS:
        try:
            return PROJECT_COMMANDS[args.command](args)
        except Exception as exc:
            as_json = bool(getattr(args, "as_json", False))
            err = {
                "command": args.command,
                "status": "ERROR",
                "exit_code": EXIT_TOOL_ERROR,
                "error": str(exc),
            }
            print(json.dumps(err, indent=2) if as_json else f"ERROR: {exc}", file=sys.stderr)
            return EXIT_TOOL_ERROR

    hermes_cmd = args.hermes_command if args.command == "hermes" else args.command
    return _run_hermes_command(args, hermes_cmd)


if __name__ == "__main__":
    raise SystemExit(main())
