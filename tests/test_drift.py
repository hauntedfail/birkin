"""Unit tests for Layer 3 (`verify_drift`) using injected PID and git hooks."""

from __future__ import annotations

import json
import os
from pathlib import Path

from birkin import EXIT_DRIFT, EXIT_PASS, HarnessPolicy, verify_drift


def _setup_home(tmp_path: Path, *, cfg_mtime: float = 1_700_000_000.0, env_mtime: float = 1_700_000_000.0) -> tuple[Path, Path]:
    cfg = tmp_path / "config.yaml"
    env = tmp_path / ".env"
    cfg.write_text("model:\n  default: group/lvmh\n", encoding="utf-8")
    env.write_text("SIBYL_API_KEY=tok\n", encoding="utf-8")
    os.utime(cfg, (cfg_mtime, cfg_mtime))
    os.utime(env, (env_mtime, env_mtime))
    return cfg, env


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_drift_passes_when_gateway_fresh_and_sha_matches(tmp_path: Path) -> None:
    cfg, env = _setup_home(tmp_path, cfg_mtime=1_700_000_000.0, env_mtime=1_700_000_000.0)
    _write_json(
        tmp_path / "state" / "gateway.lifecycle.json",
        {"pid": 4242, "create_time": 1_700_000_100.0},
    )
    _write_json(
        tmp_path / "gateway_state.json",
        {"pid": 4242, "gateway_state": "running", "code_sha": "abc123def456"},
    )

    code, findings, meta = verify_drift(
        cfg,
        env,
        tmp_path,
        HarnessPolicy(),
        pid_alive_fn=lambda pid: pid == 4242,
        git_head_fn=lambda _repo: "abc123def456",
    )
    assert code == EXIT_PASS
    assert findings == []
    assert meta["gateway_pid"] == 4242


def test_drift_fails_when_state_missing_or_pid_dead(tmp_path: Path) -> None:
    cfg, env = _setup_home(tmp_path)
    code_missing, findings_missing, _ = verify_drift(
        cfg, env, tmp_path, HarnessPolicy(), pid_alive_fn=lambda _p: True, git_head_fn=lambda _r: None
    )
    assert code_missing == EXIT_DRIFT
    assert findings_missing[0].rule == "DRIFT_GATEWAY_STATE_MISSING"

    _write_json(tmp_path / "state" / "gateway.lifecycle.json", {"pid": 9999, "create_time": 1_700_000_100.0})
    code_dead, findings_dead, _ = verify_drift(
        cfg, env, tmp_path, HarnessPolicy(), pid_alive_fn=lambda _p: False, git_head_fn=lambda _r: None
    )
    assert code_dead == EXIT_DRIFT
    assert findings_dead[0].rule == "DRIFT_GATEWAY_PID_DEAD"


def test_drift_detects_stale_config_env_and_code_sha(tmp_path: Path) -> None:
    cfg, env = _setup_home(tmp_path, cfg_mtime=1_700_000_500.0, env_mtime=1_700_000_600.0)
    _write_json(
        tmp_path / "state" / "gateway.lifecycle.json",
        {"pid": 4242, "create_time": 1_700_000_100.0},
    )
    _write_json(
        tmp_path / "gateway_state.json",
        {"pid": 4242, "gateway_state": "running", "code_sha": "oldsha000000"},
    )

    code, findings, _ = verify_drift(
        cfg,
        env,
        tmp_path,
        HarnessPolicy(),
        pid_alive_fn=lambda _p: True,
        git_head_fn=lambda _r: "newsha111111",
    )
    assert code == EXIT_DRIFT
    rules = {f.rule for f in findings}
    assert "DRIFT_CONFIG_NEWER_THAN_GATEWAY" in rules
    assert "DRIFT_ENV_NEWER_THAN_GATEWAY" in rules
    assert "DRIFT_CODE_SHA_MISMATCH" in rules


def test_drift_uses_centisecond_start_time_from_gateway_state_fallback(tmp_path: Path) -> None:
    cfg, env = _setup_home(tmp_path, cfg_mtime=1_700_000_000.0, env_mtime=1_700_000_000.0)
    # No gateway.lifecycle.json; only gateway_state.json with centisecond start_time.
    _write_json(
        tmp_path / "gateway_state.json",
        {
            "pid": 4242,
            "gateway_state": "running",
            "start_time": 170000010000,  # 1_700_000_100.00 seconds
            "code_sha": "same",
        },
    )
    code, findings, meta = verify_drift(
        cfg,
        env,
        tmp_path,
        HarnessPolicy(),
        pid_alive_fn=lambda _p: True,
        git_head_fn=lambda _r: "same",
    )
    assert code == EXIT_PASS
    assert findings == []
    assert meta["gateway_create_time"] == 1_700_000_100.0


def test_drift_fails_closed_when_start_time_missing(tmp_path: Path) -> None:
    cfg, env = _setup_home(tmp_path)
    _write_json(tmp_path / "gateway_state.json", {"pid": 4242, "gateway_state": "running"})

    code, findings, _ = verify_drift(
        cfg,
        env,
        tmp_path,
        HarnessPolicy(),
        pid_alive_fn=lambda _p: True,
        git_head_fn=lambda _r: None,
    )
    assert code == EXIT_DRIFT
    assert "DRIFT_GATEWAY_START_TIME_MISSING" in {f.rule for f in findings}


def test_drift_prefers_loaded_config_sha256_when_present(tmp_path: Path) -> None:
    # Even if config mtime is newer than gateway start, matching loaded_config_sha256 passes config check.
    cfg, env = _setup_home(tmp_path, cfg_mtime=1_700_000_500.0, env_mtime=1_700_000_000.0)
    _write_json(
        tmp_path / "state" / "gateway.lifecycle.json",
        {"pid": 4242, "create_time": 1_700_000_100.0},
    )
    _write_json(
        tmp_path / "gateway_state.json",
        {
            "pid": 4242,
            "gateway_state": "running",
            "loaded_config_sha256": "deadbeef" * 8,
        },
    )

    code_ok, findings_ok, _ = verify_drift(
        cfg,
        env,
        tmp_path,
        HarnessPolicy(),
        pid_alive_fn=lambda _p: True,
        git_head_fn=lambda _r: None,
        config_sha256="deadbeef" * 8,
    )
    assert code_ok == EXIT_PASS
    assert findings_ok == []

    code_bad, findings_bad, _ = verify_drift(
        cfg,
        env,
        tmp_path,
        HarnessPolicy(),
        pid_alive_fn=lambda _p: True,
        git_head_fn=lambda _r: None,
        config_sha256="00000000" * 8,
    )
    assert code_bad == EXIT_DRIFT
    assert "DRIFT_CONFIG_SHA_MISMATCH" in {f.rule for f in findings_bad}
