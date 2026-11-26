"""Unit tests for Layer 2 (`verify_live`) using httpx.MockTransport."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from birkin import (
    EXIT_LIVE_CONTRACT,
    EXIT_LIVE_TRANSIENT,
    EXIT_PASS,
    HarnessPolicy,
    verify_live,
)


def _live_config() -> dict[str, Any]:
    return {
        "model": {
            "provider": "custom",
            "default": "group/lvmh",
            "base_url": "https://api.example.invalid/v1",
        },
        "providers": {
            "custom": {
                "base_url": "https://api.example.invalid/v1",
                "api_key_env": "LIVE_TEST_KEY",
                "models": {
                    "group/lvmh": {"context_length": 200000},
                    "group/aux": {"context_length": 128000},
                },
            }
        },
        "auxiliary": {
            "compression": {"provider": "auto", "model": "group/aux"},
        },
        "fallback_providers": [],
    }


def _write_env(tmp_path: Path) -> Path:
    p = tmp_path / ".env"
    p.write_text("LIVE_TEST_KEY=tok-secret\n", encoding="utf-8")
    return p


def test_live_passes_on_matching_catalog_and_sends_bearer_token(tmp_path: Path) -> None:
    seen_auth: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_auth.append(request.headers.get("Authorization", ""))
        return httpx.Response(
            200,
            json={
                "data": [
                    {"id": "group/lvmh", "context_length": 200000},
                    {"id": "group/aux", "context_length": 128000},
                ]
            },
        )

    code, findings, meta = verify_live(
        _live_config(),
        HarnessPolicy(),
        env_path=_write_env(tmp_path),
        transport=httpx.MockTransport(handler),
    )
    assert code == EXIT_PASS
    assert findings == []
    assert meta["catalog_count"] == 2
    assert seen_auth == ["Bearer tok-secret"]


def test_live_catalog_sha256_reflects_context_length_changes(tmp_path: Path) -> None:
    def make_transport(ctx: int) -> httpx.MockTransport:
        return httpx.MockTransport(
            lambda _req: httpx.Response(
                200,
                json={"data": [{"id": "group/lvmh", "context_length": ctx}]},
            )
        )

    policy = HarnessPolicy()
    policy.live_contract.require_catalog_context_length_coverage = False
    _, _, meta1 = verify_live(_live_config(), policy, env_path=_write_env(tmp_path), transport=make_transport(200000))
    _, _, meta2 = verify_live(_live_config(), policy, env_path=_write_env(tmp_path), transport=make_transport(128000))
    assert meta1["catalog_sha256"] != meta2["catalog_sha256"]


def test_live_classifies_401_as_contract_and_503_as_transient(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)
    code_401, findings_401, _ = verify_live(
        _live_config(),
        HarnessPolicy(),
        env_path=env_path,
        transport=httpx.MockTransport(lambda _r: httpx.Response(401, json={"error": "unauthorized"})),
    )
    assert code_401 == EXIT_LIVE_CONTRACT
    assert findings_401[0].rule == "LIVE_CATALOG_HTTP_ERROR"

    code_503, findings_503, _ = verify_live(
        _live_config(),
        HarnessPolicy(),
        env_path=env_path,
        transport=httpx.MockTransport(lambda _r: httpx.Response(503, text="overloaded")),
    )
    assert code_503 == EXIT_LIVE_TRANSIENT
    assert findings_503[0].rule == "LIVE_TRANSIENT_HTTP"


def test_live_handles_protocol_error_and_non_object_json(tmp_path: Path) -> None:
    env_path = _write_env(tmp_path)

    def raise_protocol_error(request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError("server disconnected", request=request)

    code_proto, findings_proto, _ = verify_live(
        _live_config(),
        HarnessPolicy(),
        env_path=env_path,
        transport=httpx.MockTransport(raise_protocol_error),
    )
    assert code_proto == EXIT_LIVE_TRANSIENT
    assert findings_proto[0].rule == "LIVE_NETWORK_UNAVAILABLE"

    code_list, findings_list, _ = verify_live(
        _live_config(),
        HarnessPolicy(),
        env_path=env_path,
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, json=["not-an-object"])),
    )
    assert code_list == EXIT_LIVE_CONTRACT
    assert findings_list[0].rule == "LIVE_CATALOG_INVALID_JSON"


def test_live_detects_missing_models_and_context_mismatch(tmp_path: Path) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"id": "group/lvmh", "context_length": 100000},  # configured 200000 > 100000
                    {"id": "group/new", "context_length": 64000},  # undeclared in config
                ]
            },
        )

    code, findings, _ = verify_live(
        _live_config(),
        HarnessPolicy(),
        env_path=_write_env(tmp_path),
        transport=httpx.MockTransport(handler),
    )
    assert code == EXIT_LIVE_CONTRACT
    rules = {f.rule for f in findings}
    assert "LIVE_AUX_MODEL_NOT_IN_CATALOG" in rules
    assert "LIVE_CONTEXT_EXCEEDS_ADVERTISED" in rules
    assert "LIVE_MODEL_CONTEXT_UNDECLARED" in rules


def test_live_probe_checks_all_active_models_and_rejects_html_200(tmp_path: Path) -> None:
    probed: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/models"):
            return httpx.Response(
                200,
                json={
                    "data": [
                        {"id": "group/lvmh", "context_length": 200000},
                        {"id": "group/aux", "context_length": 128000},
                    ]
                },
            )
        payload = request.read().decode("utf-8")
        if '"group/lvmh"' in payload:
            probed.append("group/lvmh")
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})
        probed.append("group/aux")
        return httpx.Response(200, text="<html>captive portal</html>")

    code, findings, meta = verify_live(
        _live_config(),
        HarnessPolicy(),
        env_path=_write_env(tmp_path),
        probe=True,
        transport=httpx.MockTransport(handler),
    )
    assert code == EXIT_LIVE_CONTRACT
    assert probed == ["group/lvmh", "group/aux"]
    assert meta["probed_models"] == ["group/lvmh", "group/aux"]
    assert "LIVE_PROBE_INVALID_JSON" in {f.rule for f in findings}
