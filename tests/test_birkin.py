"""Regression and proof-of-life negative tests for Birkin."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from birkin import (
    EXIT_PASS,
    EXIT_STATIC,
    HarnessPolicy,
    canonical_config_sha256,
    load_policy,
    main,
    verify_static,
)


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
                "api_key_env": "TEST_API_KEY",
                "models": {
                    "group/lvmh": {"context_length": 200000},
                    "group/aux": {"context_length": 128000},
                },
            }
        },
        "auxiliary": {
            "compression": {
                "provider": "auto",
                "model": "group/aux",
            }
        },
        "compression": {
            "threshold": 0.65,
            "target_ratio": 0.4,
        },
        "fallback_providers": [],
    }


def _write_env(tmp_path: Path, content: str = "TEST_API_KEY=dummy-token\n") -> Path:
    env_path = tmp_path / ".env"
    env_path.write_text(content, encoding="utf-8")
    return env_path


def test_static_passes_on_valid_config(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)
    policy = HarnessPolicy()
    code, findings = verify_static(_valid_config(), policy, env_path=env_path)
    assert code == EXIT_PASS
    assert findings == []


def test_static_rejects_forbidden_opus_fallback(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)
    cfg = _valid_config()
    cfg["fallback_providers"] = [{"provider": "anthropic", "model": "claude-opus-4-6"}]
    policy = load_policy(Path(__file__).resolve().parents[1] / "birkin-policy.example.yaml")

    code, findings = verify_static(cfg, policy, env_path=env_path)
    assert code == EXIT_STATIC
    rules = {f.rule for f in findings}
    assert "POLICY_FORBIDDEN_FALLBACK" in rules


def test_static_rejects_unapproved_fallback_fail_closed(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)
    cfg = _valid_config()
    cfg["fallback_providers"] = [{"provider": "openai", "model": "gpt-5-mini"}]
    policy = HarnessPolicy()

    code, findings = verify_static(cfg, policy, env_path=env_path)
    assert code == EXIT_STATIC
    rules = {f.rule for f in findings}
    assert "POLICY_UNAPPROVED_FALLBACK" in rules


def test_static_rejects_missing_fallback_providers_key(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)
    cfg = _valid_config()
    del cfg["fallback_providers"]
    policy = HarnessPolicy()

    code, findings = verify_static(cfg, policy, env_path=env_path)
    assert code == EXIT_STATIC
    assert findings


def test_static_rejects_missing_default_context_length(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)
    cfg = _valid_config()
    cfg["providers"]["custom"]["models"]["group/lvmh"] = {}
    policy = HarnessPolicy()

    code, findings = verify_static(cfg, policy, env_path=env_path)
    assert code == EXIT_STATIC
    assert findings


def test_static_rejects_invalid_compression_ratio(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)
    cfg = _valid_config()
    cfg["compression"] = {"threshold": 0.5, "target_ratio": 0.6}
    policy = HarnessPolicy()

    code, findings = verify_static(cfg, policy, env_path=env_path)
    assert code == EXIT_STATIC
    assert findings


def test_canonical_config_sha256_strips_secrets() -> None:
    cfg_a = _valid_config()
    cfg_b = _valid_config()
    cfg_a["api_key"] = "secret-a"
    cfg_b["api_key"] = "secret-b"
    assert canonical_config_sha256(cfg_a) == canonical_config_sha256(cfg_b)


def test_cli_static_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(_valid_config()), encoding="utf-8")
    env_path = _write_env(tmp_path)
    policy_path = Path(__file__).resolve().parents[1] / "birkin-policy.example.yaml"

    rc = main(
        [
            "static",
            "--home",
            str(tmp_path),
            "--config",
            str(cfg_path),
            "--policy",
            str(policy_path),
            "--env",
            str(env_path),
            "--json",
        ]
    )
    assert rc == EXIT_PASS
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "PASS"
    assert payload["exit_code"] == EXIT_PASS
