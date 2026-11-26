"""Layer 2: Live provider /v1/models contract and optional micro-probe verification."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from birkin.config_utils import (
    extract_context_length,
    is_positive_int,
    norm_url,
    resolve_api_key,
    resolve_provider_block,
    resolve_provider_models,
)
from birkin.constants import EXIT_LIVE_CONTRACT, EXIT_LIVE_TRANSIENT, EXIT_PASS
from birkin.models import Finding, HarnessPolicy

_TRANSIENT_HTTP_CODES = frozenset({429, 500, 502, 503, 504})


def _advertised_context_length(mobj: dict[str, Any]) -> int | None:
    for key in ("context_length", "max_model_len"):
        val = mobj.get(key)
        if is_positive_int(val):
            return val
    return None


def _collect_probe_models(
    cfg: dict[str, Any],
    active_provider: str,
    default_model: str,
) -> list[str]:
    probe_models: list[str] = [default_model]
    aux_cfg = cfg.get("auxiliary")
    if isinstance(aux_cfg, dict):
        for role_cfg in aux_cfg.values():
            if not isinstance(role_cfg, dict):
                continue
            aux_model = str(role_cfg.get("model", "") or "").strip()
            aux_provider = str(role_cfg.get("provider", "auto") or "auto").strip()
            if aux_model and aux_provider in ("auto", active_provider) and aux_model not in probe_models:
                probe_models.append(aux_model)
    return probe_models


def verify_live(
    cfg: dict[str, Any],
    policy: HarnessPolicy,
    env_path: Path | None = None,
    probe: bool = False,
    timeout: float | None = None,
    transport: httpx.BaseTransport | None = None,
) -> tuple[int, list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    meta: dict[str, Any] = {
        "checked_at": datetime.now(UTC).isoformat(),
        "endpoint": None,
        "catalog_count": 0,
        "probe_enabled": probe,
    }

    model_cfg = cfg.get("model") if isinstance(cfg.get("model"), dict) else {}
    active_provider = str(model_cfg.get("provider", "") or "").strip()
    default_model = str(model_cfg.get("default", "") or "").strip()
    provider_block = resolve_provider_block(cfg, active_provider) or {}
    base_url = norm_url(str(model_cfg.get("base_url") or provider_block.get("base_url") or ""))
    api_key = resolve_api_key(model_cfg, provider_block, env_path)

    if not base_url:
        findings.append(
            Finding(
                rule="LIVE_BASE_URL_MISSING",
                layer="live",
                message="Cannot run live contract check: no base_url configured.",
                remediation="Configure model.base_url or providers.<active>.base_url.",
            )
        )
        return EXIT_LIVE_CONTRACT, findings, meta

    models_url = f"{base_url}/models"
    meta["endpoint"] = models_url
    req_timeout = timeout if timeout is not None else policy.live_contract.timeout_seconds
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    client_kwargs: dict[str, Any] = {"timeout": req_timeout}
    if transport is not None:
        client_kwargs["transport"] = transport

    try:
        with httpx.Client(**client_kwargs) as client:
            resp = client.get(models_url, headers=headers)
            meta["http_status"] = resp.status_code

            if resp.status_code in _TRANSIENT_HTTP_CODES:
                findings.append(
                    Finding(
                        rule="LIVE_TRANSIENT_HTTP",
                        layer="live",
                        message=f"GET {models_url} returned transient HTTP {resp.status_code}.",
                        remediation="Retry later; do not treat transient outage as config corruption.",
                        details={"status_code": resp.status_code},
                    )
                )
                return EXIT_LIVE_TRANSIENT, findings, meta

            if resp.status_code != 200:
                findings.append(
                    Finding(
                        rule="LIVE_CATALOG_HTTP_ERROR",
                        layer="live",
                        message=f"GET {models_url} returned HTTP {resp.status_code}.",
                        remediation="Verify base_url and API credentials in ~/.hermes/.env.",
                        details={"status_code": resp.status_code},
                    )
                )
                return EXIT_LIVE_CONTRACT, findings, meta

            try:
                body = resp.json()
            except Exception as exc:
                findings.append(
                    Finding(
                        rule="LIVE_CATALOG_INVALID_JSON",
                        layer="live",
                        message=f"GET {models_url} returned non-JSON payload: {exc}",
                        remediation="Check upstream gateway /v1/models response.",
                    )
                )
                return EXIT_LIVE_CONTRACT, findings, meta

            if not isinstance(body, dict):
                findings.append(
                    Finding(
                        rule="LIVE_CATALOG_INVALID_JSON",
                        layer="live",
                        message=(
                            f"GET {models_url} returned JSON {type(body).__name__}, "
                            "expected an OpenAI-compatible object with 'data'."
                        ),
                        remediation="Check upstream gateway /v1/models response format.",
                    )
                )
                return EXIT_LIVE_CONTRACT, findings, meta

            data = body.get("data")
            if not isinstance(data, list) or not data:
                findings.append(
                    Finding(
                        rule="LIVE_CATALOG_EMPTY",
                        layer="live",
                        message=f"GET {models_url} returned empty or missing 'data' list.",
                        remediation="Inspect upstream gateway routing group configuration.",
                    )
                )
                return EXIT_LIVE_CONTRACT, findings, meta

            catalog: dict[str, dict[str, Any]] = {}
            for item in data:
                if isinstance(item, dict) and item.get("id"):
                    catalog[str(item["id"])] = item
            meta["catalog_count"] = len(catalog)
            catalog_fingerprint = [
                [mid, _advertised_context_length(catalog[mid])] for mid in sorted(catalog.keys())
            ]
            meta["catalog_sha256"] = hashlib.sha256(
                json.dumps(catalog_fingerprint, separators=(",", ":")).encode("utf-8")
            ).hexdigest()

            provider_models = resolve_provider_models(provider_block)

            # 1. Active default model must exist in live catalog
            if default_model and default_model not in catalog:
                findings.append(
                    Finding(
                        rule="LIVE_DEFAULT_MODEL_NOT_IN_CATALOG",
                        layer="live",
                        message=f"model.default='{default_model}' is not advertised by {models_url}.",
                        remediation="Update model.default to a model present in /v1/models.",
                        details={"model": default_model},
                    )
                )

            # 2. Auxiliary models targeting active provider must exist in live catalog
            aux_cfg = cfg.get("auxiliary")
            if isinstance(aux_cfg, dict):
                for role, role_cfg in aux_cfg.items():
                    if not isinstance(role_cfg, dict):
                        continue
                    aux_model = str(role_cfg.get("model", "") or "").strip()
                    aux_provider = str(role_cfg.get("provider", "auto") or "auto").strip()
                    if aux_model and aux_provider in ("auto", active_provider):
                        if aux_model not in catalog:
                            findings.append(
                                Finding(
                                    rule="LIVE_AUX_MODEL_NOT_IN_CATALOG",
                                    layer="live",
                                    message=(
                                        f"auxiliary.{role}.model='{aux_model}' is not served by "
                                        f"{models_url} (causes 404 fallback stalls)."
                                    ),
                                    remediation=(
                                        f"Run `hermes config set auxiliary.{role}.model ''` "
                                        "or choose a model from /v1/models."
                                    ),
                                    details={"role": role, "model": aux_model},
                                )
                            )

            # 3. Every catalog model advertising context_length must be covered in config.yaml
            if policy.live_contract.require_catalog_context_length_coverage:
                for mid, mobj in sorted(catalog.items()):
                    adv = _advertised_context_length(mobj)
                    if adv is None:
                        continue
                    configured = extract_context_length(provider_models, mid)
                    if configured is None:
                        findings.append(
                            Finding(
                                rule="LIVE_MODEL_CONTEXT_UNDECLARED",
                                layer="live",
                                message=(
                                    f"Provider model '{mid}' advertises context_length={adv}, "
                                    f"but is missing from providers.{active_provider}.models "
                                    "(switching to it triggers 256k probe-down & skill pruning)."
                                ),
                                remediation=(
                                    f"Run `hermes config set providers.{active_provider}.models."
                                    f"{mid}.context_length {adv}`."
                                ),
                                details={"model": mid, "advertised_context_length": adv},
                            )
                        )
                    elif configured > adv:
                        findings.append(
                            Finding(
                                rule="LIVE_CONTEXT_EXCEEDS_ADVERTISED",
                                layer="live",
                                message=(
                                    f"providers.{active_provider}.models.{mid}.context_length="
                                    f"{configured} exceeds advertised limit {adv}."
                                ),
                                remediation=(
                                    f"Run `hermes config set providers.{active_provider}.models."
                                    f"{mid}.context_length {adv}`."
                                ),
                                details={
                                    "model": mid,
                                    "configured_context_length": configured,
                                    "advertised_context_length": adv,
                                },
                            )
                        )

            # 4. Optional Tier B micro-probe
            if probe and default_model:
                comp_url = f"{base_url}/chat/completions"
                probe_models = _collect_probe_models(cfg, active_provider, default_model)
                meta["probed_models"] = probe_models
                for pm in probe_models:
                    pr = client.post(
                        comp_url,
                        headers={**headers, "Content-Type": "application/json"},
                        json={
                            "model": pm,
                            "max_tokens": 1,
                            "temperature": 0,
                            "messages": [{"role": "user", "content": "ping"}],
                        },
                    )
                    if pr.status_code in _TRANSIENT_HTTP_CODES:
                        findings.append(
                            Finding(
                                rule="LIVE_PROBE_TRANSIENT",
                                layer="live",
                                message=f"Micro-probe for '{pm}' returned transient HTTP {pr.status_code}.",
                                remediation="Retry later; upstream rate-limited or transiently unavailable.",
                                details={"model": pm, "status_code": pr.status_code},
                            )
                        )
                    elif pr.status_code != 200:
                        findings.append(
                            Finding(
                                rule="LIVE_PROBE_CONTRACT_ERROR",
                                layer="live",
                                message=f"Micro-probe for '{pm}' failed with HTTP {pr.status_code}.",
                                remediation="Verify model routing on upstream gateway.",
                                details={"model": pm, "status_code": pr.status_code},
                            )
                        )
                    else:
                        try:
                            probe_body = pr.json()
                        except Exception as exc:
                            findings.append(
                                Finding(
                                    rule="LIVE_PROBE_INVALID_JSON",
                                    layer="live",
                                    message=f"Micro-probe for '{pm}' returned HTTP 200 non-JSON payload: {exc}",
                                    remediation="Verify upstream endpoint is an OpenAI-compatible API, not a proxy error page.",
                                    details={"model": pm},
                                )
                            )
                            continue
                        if not isinstance(probe_body, dict) or "error" in probe_body:
                            findings.append(
                                Finding(
                                    rule="LIVE_PROBE_CONTRACT_ERROR",
                                    layer="live",
                                    message=f"Micro-probe for '{pm}' returned HTTP 200 with invalid/error JSON body.",
                                    remediation="Inspect upstream gateway response for chat/completions.",
                                    details={"model": pm},
                                )
                            )

    except httpx.HTTPError as exc:
        findings.append(
            Finding(
                rule="LIVE_NETWORK_UNAVAILABLE",
                layer="live",
                message=f"HTTP transport error reaching {models_url}: {exc}",
                remediation="Check network connectivity and upstream gateway availability.",
            )
        )
        return EXIT_LIVE_TRANSIENT, findings, meta

    error_findings = [f for f in findings if f.severity == "error"]
    if any(f.rule.startswith("LIVE_") and "TRANSIENT" not in f.rule for f in error_findings):
        return EXIT_LIVE_CONTRACT, findings, meta
    if any("TRANSIENT" in f.rule for f in error_findings):
        return EXIT_LIVE_TRANSIENT, findings, meta
    return EXIT_PASS, findings, meta
