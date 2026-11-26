"""CLI orchestration, fail-closed policy loading, and atomic state persistence tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from birkin import (
    EXIT_DRIFT,
    EXIT_LIVE_CONTRACT,
    EXIT_LIVE_TRANSIENT,
    EXIT_PASS,
    EXIT_STATIC,
    EXIT_TOOL_ERROR,
    main,
)
from birkin.report import combine_exit_codes


def _valid_config() -> dict[str, Any]:
    return {
        "model": {
            "provider": "custom",
            "default": "group/lvmh",
            "base_url": "https://example.invalid/llm/v1",
        },
        "providers": {
            "custom": {
                "base_url": "https://example.invalid/llm/v1",
                "key_env": "TEST_API_KEY",
                "models": {"group/lvmh": {"context_length": 200000}},
            }
        },
        "compression": {"threshold": 0.65, "target_ratio": 0.4},
        "fallback_providers": [],
    }


def test_explicit_missing_policy_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(_valid_config()), encoding="utf-8")
    env_path = tmp_path / ".env"
    env_path.write_text("TEST_API_KEY=ok\n", encoding="utf-8")

    rc = main(
        [
            "static",
            "--home",
            str(tmp_path),
            "--config",
            str(cfg_path),
            "--env",
            str(env_path),
            "--policy",
            str(tmp_path / "does-not-exist.yaml"),
            "--json",
        ]
    )
    assert rc == EXIT_TOOL_ERROR
    err_payload = json.loads(capsys.readouterr().err)
    assert err_payload["status"] == "ERROR"
    assert err_payload["exit_code"] == EXIT_TOOL_ERROR


def test_all_skip_drift_writes_state_atomically(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(_valid_config()), encoding="utf-8")
    env_path = tmp_path / ".env"
    env_path.write_text("TEST_API_KEY=ok\n", encoding="utf-8")

    rc = main(
        [
            "all",
            "--home",
            str(tmp_path),
            "--config",
            str(cfg_path),
            "--env",
            str(env_path),
            "--skip-drift",
            "--json",
        ]
    )
    assert rc == EXIT_PASS
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "PASS"
    assert "drift" not in out["sections"]

    state_file = tmp_path / "state" / "birkin.json"
    assert state_file.exists()
    persisted = json.loads(state_file.read_text(encoding="utf-8"))
    assert persisted["status"] == "PASS"
    # No leftover temporary files
    assert list((tmp_path / "state").glob(".birkin.*.tmp")) == []


def test_exit_code_precedence() -> None:
    assert combine_exit_codes([EXIT_PASS, EXIT_LIVE_TRANSIENT]) == EXIT_LIVE_TRANSIENT
    assert combine_exit_codes([EXIT_LIVE_TRANSIENT, EXIT_DRIFT]) == EXIT_DRIFT
    assert combine_exit_codes([EXIT_DRIFT, EXIT_LIVE_CONTRACT]) == EXIT_LIVE_CONTRACT
    assert combine_exit_codes([EXIT_LIVE_CONTRACT, EXIT_STATIC]) == EXIT_STATIC
    assert combine_exit_codes([EXIT_STATIC, EXIT_TOOL_ERROR]) == EXIT_TOOL_ERROR
    assert combine_exit_codes([]) == EXIT_PASS
