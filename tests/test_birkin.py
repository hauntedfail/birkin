"""Regression, static invariant, policy, dotenv, and secret-hygiene tests for Birkin."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pydantic
import pytest
import yaml

from birkin import (
    EXIT_PASS,
    EXIT_STATIC,
    HarnessPolicy,
    canonical_config_sha256,
    load_policy,
    main,
    parse_dotenv_keys,
    read_env_secret,
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


def test_static_enforces_api_key_env_and_key_env_presence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TEST_API_KEY", raising=False)
    empty_env = _write_env(tmp_path, content="# no key\n")
    policy = HarnessPolicy()

    # api_key_env is actually enforced now (previously silently skipped)
    code, findings = verify_static(_valid_config(), policy, env_path=empty_env)
    assert code == EXIT_STATIC
    assert "SEMANTIC_KEY_ENV_MISSING" in {f.rule for f in findings}

    # key_env is also enforced
    cfg = _valid_config()
    del cfg["providers"]["custom"]["api_key_env"]
    cfg["providers"]["custom"]["key_env"] = "TEST_API_KEY"
    code2, findings2 = verify_static(cfg, policy, env_path=empty_env)
    assert code2 == EXIT_STATIC
    assert "SEMANTIC_KEY_ENV_MISSING" in {f.rule for f in findings2}


def test_static_rejects_forbidden_opus_fallback(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)
    cfg = _valid_config()
    cfg["fallback_providers"] = [{"provider": "anthropic", "model": "claude-opus-4-6"}]
    policy = load_policy(Path(__file__).resolve().parents[1] / "birkin-policy.example.yaml")

    code, findings = verify_static(cfg, policy, env_path=env_path)
    assert code == EXIT_STATIC
    rules = {f.rule for f in findings}
    assert "POLICY_FORBIDDEN_FALLBACK" in rules


def test_static_rejects_forbidden_opus_in_default_and_auxiliary(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)
    cfg = _valid_config()
    cfg["model"]["default"] = "claude-opus-4-6"
    cfg["providers"]["custom"]["models"]["claude-opus-4-6"] = {"context_length": 200000}
    cfg["auxiliary"]["vision"] = {"provider": "auto", "model": "anthropic/claude-opus-4-6"}
    cfg["providers"]["custom"]["models"]["anthropic/claude-opus-4-6"] = {"context_length": 200000}

    code, findings = verify_static(cfg, HarnessPolicy(), env_path=env_path)
    assert code == EXIT_STATIC
    rules = {f.rule for f in findings}
    assert "POLICY_FORBIDDEN_DEFAULT_MODEL" in rules
    assert "POLICY_FORBIDDEN_AUX_MODEL" in rules


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
    assert "POLICY_FALLBACK_NOT_EXPLICIT" in {f.rule for f in findings}


def test_static_rejects_legacy_fallback_model(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)
    cfg = _valid_config()
    cfg["fallback_model"] = {"provider": "openai", "model": "gpt-5"}

    code, findings = verify_static(cfg, HarnessPolicy(), env_path=env_path)
    assert code == EXIT_STATIC
    assert "POLICY_LEGACY_FALLBACK_MODEL_FORBIDDEN" in {f.rule for f in findings}


def test_static_rejects_missing_default_context_length(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)
    cfg = _valid_config()
    cfg["providers"]["custom"]["models"]["group/lvmh"] = {}
    policy = HarnessPolicy()

    code, findings = verify_static(cfg, policy, env_path=env_path)
    assert code == EXIT_STATIC
    assert "SEMANTIC_DEFAULT_CONTEXT_LENGTH_MISSING" in {f.rule for f in findings}


def test_static_rejects_auxiliary_model_missing_context_length(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)
    cfg = _valid_config()
    cfg["providers"]["custom"]["models"]["group/aux"] = {}

    code, findings = verify_static(cfg, HarnessPolicy(), env_path=env_path)
    assert code == EXIT_STATIC
    assert "SEMANTIC_AUX_CONTEXT_LENGTH_MISSING" in {f.rule for f in findings}


def test_static_supports_custom_providers_list_and_models_list(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)
    cfg: dict[str, Any] = {
        "model": {
            "provider": "my-custom",
            "default": "group/lvmh",
            "base_url": "https://example.invalid/llm/v1",
        },
        "custom_providers": [
            {
                "slug": "my-custom",
                "base_url": "https://example.invalid/llm/v1",
                "key_env": "TEST_API_KEY",
                "models": [
                    {"id": "group/lvmh", "context_length": 200000},
                ],
            }
        ],
        "compression": {"threshold": 0.7, "target_ratio": 0.2},
        "fallback_providers": [],
    }
    code, findings = verify_static(cfg, HarnessPolicy(), env_path=env_path)
    assert code == EXIT_PASS
    assert findings == []


def test_static_rejects_invalid_and_boolean_compression_values(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)
    cfg = _valid_config()
    cfg["compression"] = {"threshold": 0.5, "target_ratio": 0.6}
    code, findings = verify_static(cfg, HarnessPolicy(), env_path=env_path)
    assert code == EXIT_STATIC
    assert "SEMANTIC_COMPRESSION_RATIO_INVALID" in {f.rule for f in findings}

    # Python bool is a subclass of int; must be rejected as non-numeric.
    cfg_bool = _valid_config()
    cfg_bool["compression"] = {"threshold": True, "target_ratio": False}
    code_b, findings_b = verify_static(cfg_bool, HarnessPolicy(), env_path=env_path)
    assert code_b == EXIT_STATIC
    assert "SCHEMA_COMPRESSION_THRESHOLD_INVALID" in {f.rule for f in findings_b}


def test_policy_rejects_unknown_keys_fail_closed(tmp_path: Path) -> None:
    bad_policy = tmp_path / "bad-policy.yaml"
    bad_policy.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "fallback_providers": {
                    "forbiden_patterns": ["*opus*"],  # intentional typo
                },
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(pydantic.ValidationError):
        load_policy(bad_policy)


def test_canonical_config_sha256_strips_secrets_without_blinding_tokens_or_env_names() -> None:
    cfg_a = _valid_config()
    cfg_b = _valid_config()
    cfg_a["api_key"] = "secret-a"
    cfg_b["api_key"] = "secret-b"
    cfg_a["bot_token"] = "tok-1"
    cfg_b["bot_token"] = "tok-2"
    assert canonical_config_sha256(cfg_a) == canonical_config_sha256(cfg_b)

    # Non-secret config keys containing 'token' or 'api_key_env' MUST affect the hash.
    cfg_c = _valid_config()
    cfg_d = _valid_config()
    cfg_c["max_tokens"] = 4096
    cfg_d["max_tokens"] = 8192
    assert canonical_config_sha256(cfg_c) != canonical_config_sha256(cfg_d)

    cfg_e = _valid_config()
    cfg_f = _valid_config()
    cfg_e["providers"]["custom"]["api_key_env"] = "ENV_ONE"
    cfg_f["providers"]["custom"]["api_key_env"] = "ENV_TWO"
    assert canonical_config_sha256(cfg_e) != canonical_config_sha256(cfg_f)


def test_dotenv_parsing_export_quotes_comments_and_last_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("KEY_A", raising=False)
    monkeypatch.delenv("KEY_B", raising=False)
    monkeypatch.delenv("KEY_C", raising=False)
    env_path = _write_env(
        tmp_path,
        content=(
            'export KEY_A="first"\n'
            'KEY_A="second" # trailing comment\n'
            "KEY_B=plain_value # inline comment\n"
            "KEY_C='quoted#not_comment'\n"
            "EMPTY_KEY=\n"
        ),
    )
    keys = parse_dotenv_keys(env_path)
    assert keys["KEY_A"] is True
    assert keys["KEY_B"] is True
    assert keys["KEY_C"] is True
    assert keys["EMPTY_KEY"] is False

    assert read_env_secret(env_path, "KEY_A") == "second"
    assert read_env_secret(env_path, "KEY_B") == "plain_value"
    assert read_env_secret(env_path, "KEY_C") == "quoted#not_comment"


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


def test_static_rejects_forbidden_hub_and_software_process_skills(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)
    skills_dir = tmp_path / "skills"
    bad_dir = skills_dir / "software-process-hub"
    bad_dir.mkdir(parents=True)
    (bad_dir / "SKILL.md").write_text(
        "---\nname: software-process-hub\ndescription: bad\n---\n# Bad\n",
        encoding="utf-8",
    )
    archived = skills_dir / ".archive" / "legacy-hub"
    archived.mkdir(parents=True)
    (archived / "SKILL.md").write_text(
        "---\nname: legacy-hub\ndescription: ignored\n---\n# Ignored\n",
        encoding="utf-8",
    )

    policy = HarnessPolicy()
    code, findings = verify_static(_valid_config(), policy, env_path=env_path, skills_dir=skills_dir)
    assert code == EXIT_STATIC
    rules = {f.rule for f in findings}
    assert "POLICY_FORBIDDEN_SKILL_NAME" in rules
    assert all(".archive" not in f.message for f in findings)


def test_static_allows_github_workflow_and_engineering_workflow_skills(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)
    skills_dir = tmp_path / "skills"
    for name in ("github-workflow", "engineering-workflow"):
        d = skills_dir / name
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: ok\n---\n# OK\n",
            encoding="utf-8",
        )

    policy = HarnessPolicy()
    code, findings = verify_static(_valid_config(), policy, env_path=env_path, skills_dir=skills_dir)
    assert code == EXIT_PASS
    assert findings == []
