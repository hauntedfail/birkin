"""Layer 3: Live gateway runtime drift verification."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from birkin.config_utils import is_number
from birkin.constants import EXIT_DRIFT, EXIT_PASS
from birkin.models import Finding, HarnessPolicy


def _pid_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def _git_head_sha(repo_dir: Path) -> str | None:
    if not (repo_dir / ".git").exists():
        return None
    try:
        res = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except OSError:
        return None
    return None


def _resolve_gateway_create_time(
    lifecycle: dict[str, Any],
    gw_state: dict[str, Any],
) -> float | None:
    """Resolve gateway process creation epoch seconds from lifecycle or gateway_state.

    `gateway.lifecycle.json` stores `create_time` / `start_time` in float epoch seconds,
    whereas `gateway_state.json` stores `start_time` as `round(create_time * 100)` (centiseconds).
    """
    for candidate in (lifecycle.get("create_time"), lifecycle.get("start_time")):
        if is_number(candidate) and float(candidate) > 0:
            return float(candidate)
    gw_start = gw_state.get("start_time")
    if is_number(gw_start) and float(gw_start) > 0:
        val = float(gw_start)
        # Centiseconds since epoch (~1.7e11 in 2026) -> seconds (~1.7e9).
        return val / 100.0 if val > 1e11 else val
    return None


def verify_drift(
    config_path: Path,
    env_path: Path,
    hermes_home: Path,
    policy: HarnessPolicy,
    *,
    pid_alive_fn: Any = _pid_is_alive,
    git_head_fn: Any = _git_head_sha,
    config_sha256: str | None = None,
) -> tuple[int, list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    lifecycle_path = hermes_home / "state" / "gateway.lifecycle.json"
    gw_state_path = hermes_home / "gateway_state.json"

    meta: dict[str, Any] = {
        "config_path": str(config_path),
        "config_mtime": config_path.stat().st_mtime if config_path.exists() else None,
        "env_mtime": env_path.stat().st_mtime if env_path.exists() else None,
        "gateway_pid": None,
        "gateway_create_time": None,
    }

    lifecycle: dict[str, Any] = {}
    if lifecycle_path.exists():
        try:
            loaded = json.loads(lifecycle_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                lifecycle = loaded
            else:
                raise ValueError(f"expected JSON object, got {type(loaded).__name__}")
        except Exception as exc:
            findings.append(
                Finding(
                    rule="DRIFT_LIFECYCLE_UNREADABLE",
                    layer="drift",
                    message=f"Could not parse {lifecycle_path}: {exc}",
                    remediation="Inspect gateway lifecycle state file.",
                )
            )

    gw_state: dict[str, Any] = {}
    if gw_state_path.exists():
        try:
            loaded_state = json.loads(gw_state_path.read_text(encoding="utf-8"))
            if isinstance(loaded_state, dict):
                gw_state = loaded_state
            else:
                raise ValueError(f"expected JSON object, got {type(loaded_state).__name__}")
        except Exception as exc:
            findings.append(
                Finding(
                    rule="DRIFT_GATEWAY_STATE_UNREADABLE",
                    layer="drift",
                    message=f"Could not parse {gw_state_path}: {exc}",
                    remediation="Inspect gateway_state.json or restart the gateway.",
                )
            )

    pid = lifecycle.get("pid") or gw_state.get("pid")
    create_time = _resolve_gateway_create_time(lifecycle, gw_state)
    meta["gateway_pid"] = pid
    meta["gateway_create_time"] = create_time

    if not pid or isinstance(pid, bool):
        findings.append(
            Finding(
                rule="DRIFT_GATEWAY_STATE_MISSING",
                layer="drift",
                message="No running gateway PID recorded in gateway.lifecycle.json or gateway_state.json.",
                remediation="Start or check the gateway with `hermes gateway status`.",
            )
        )
        return EXIT_DRIFT, findings, meta

    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        findings.append(
            Finding(
                rule="DRIFT_GATEWAY_PID_INVALID",
                layer="drift",
                message=f"Recorded gateway PID {pid!r} is not a valid integer.",
                remediation="Inspect gateway state files and restart the gateway.",
            )
        )
        return EXIT_DRIFT, findings, meta

    if not pid_alive_fn(pid_int):
        findings.append(
            Finding(
                rule="DRIFT_GATEWAY_PID_DEAD",
                layer="drift",
                message=f"Recorded gateway PID {pid_int} is not running.",
                remediation="Restart gateway via `hermes gateway restart`.",
                details={"pid": pid_int},
            )
        )
        return EXIT_DRIFT, findings, meta

    gw_reported_state = gw_state.get("gateway_state")
    if isinstance(gw_reported_state, str) and gw_reported_state and gw_reported_state != "running":
        findings.append(
            Finding(
                rule="DRIFT_GATEWAY_NOT_RUNNING",
                layer="drift",
                message=f"gateway_state.json reports gateway_state={gw_reported_state!r} for PID {pid_int}.",
                remediation="Inspect `hermes gateway status` and restart if needed.",
                details={"pid": pid_int, "gateway_state": gw_reported_state},
            )
        )

    # Authoritative config hash check when gateway_state.json exposes loaded_config_sha256.
    loaded_cfg_sha = gw_state.get("loaded_config_sha256")
    config_checked_by_hash = False
    if isinstance(loaded_cfg_sha, str) and loaded_cfg_sha and config_sha256:
        config_checked_by_hash = True
        meta["loaded_config_sha256"] = loaded_cfg_sha
        if loaded_cfg_sha != config_sha256:
            findings.append(
                Finding(
                    rule="DRIFT_CONFIG_SHA_MISMATCH",
                    layer="drift",
                    message=(
                        f"Gateway PID {pid_int} loaded config_sha256={loaded_cfg_sha[:12]}, "
                        f"but on-disk config.yaml hashes to {config_sha256[:12]}."
                    ),
                    remediation="Run `hermes gateway restart` from a separate shell to load the current config.",
                    details={
                        "pid": pid_int,
                        "loaded_config_sha256": loaded_cfg_sha,
                        "on_disk_config_sha256": config_sha256,
                    },
                )
            )

    needs_mtime_check = (
        (policy.drift_invariants.check_config_mtime_vs_gateway_start and not config_checked_by_hash)
        or policy.drift_invariants.check_env_mtime_vs_gateway_start
    )

    if create_time is not None:
        gw_iso = datetime.fromtimestamp(create_time, tz=UTC).isoformat()
        meta["gateway_started_utc"] = gw_iso

        if (
            policy.drift_invariants.check_config_mtime_vs_gateway_start
            and not config_checked_by_hash
            and config_path.exists()
        ):
            cfg_mtime = config_path.stat().st_mtime
            if cfg_mtime > create_time:
                cfg_iso = datetime.fromtimestamp(cfg_mtime, tz=UTC).isoformat()
                findings.append(
                    Finding(
                        rule="DRIFT_CONFIG_NEWER_THAN_GATEWAY",
                        layer="drift",
                        message=(
                            f"config.yaml was modified at {cfg_iso}, after gateway PID {pid_int} "
                            f"started at {gw_iso} (in-memory config/fallback_providers may be stale)."
                        ),
                        remediation="Run `hermes gateway restart` from a separate shell to load the current config.",
                        details={
                            "pid": pid_int,
                            "gateway_create_time": create_time,
                            "config_mtime": cfg_mtime,
                        },
                    )
                )

        if policy.drift_invariants.check_env_mtime_vs_gateway_start and env_path.exists():
            env_mtime = env_path.stat().st_mtime
            if env_mtime > create_time:
                env_iso = datetime.fromtimestamp(env_mtime, tz=UTC).isoformat()
                findings.append(
                    Finding(
                        rule="DRIFT_ENV_NEWER_THAN_GATEWAY",
                        layer="drift",
                        message=(
                            f".env was modified at {env_iso}, after gateway PID {pid_int} "
                            f"started at {gw_iso}."
                        ),
                        remediation="Run `/reload` or `hermes gateway restart` from a separate shell.",
                        details={
                            "pid": pid_int,
                            "gateway_create_time": create_time,
                            "env_mtime": env_mtime,
                        },
                    )
                )
    elif needs_mtime_check:
        findings.append(
            Finding(
                rule="DRIFT_GATEWAY_START_TIME_MISSING",
                layer="drift",
                message=(
                    f"Gateway PID {pid_int} is alive, but no process start/create timestamp was found "
                    "in gateway.lifecycle.json or gateway_state.json; cannot prove config/.env freshness."
                ),
                remediation="Inspect gateway state files or restart the gateway to refresh lifecycle metadata.",
                details={"pid": pid_int},
            )
        )

    if policy.drift_invariants.check_code_sha_vs_repo_head:
        running_sha = gw_state.get("code_sha")
        head_sha = git_head_fn(hermes_home / "hermes-agent")
        meta["running_code_sha"] = running_sha
        meta["repo_head_sha"] = head_sha
        if running_sha and head_sha and running_sha != head_sha:
            findings.append(
                Finding(
                    rule="DRIFT_CODE_SHA_MISMATCH",
                    layer="drift",
                    message=(
                        f"Gateway PID {pid_int} is running code_sha={running_sha[:12]}, "
                        f"but hermes-agent HEAD is {head_sha[:12]}."
                    ),
                    remediation="Run `hermes gateway restart` from a separate shell.",
                    details={"running_code_sha": running_sha, "repo_head_sha": head_sha},
                )
            )

    exit_code = EXIT_DRIFT if any(f.severity == "error" for f in findings) else EXIT_PASS
    return exit_code, findings, meta
