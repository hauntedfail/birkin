#!/usr/bin/env python3
"""Deterministic mechanical verifier for Hermes Agent configuration, provider
contracts, and live gateway runtime drift.

Exit codes:
  0 = PASS
  1 = STATIC / POLICY VIOLATION
  2 = LIVE CONTRACT VIOLATION (404/401/403/400, missing model, context mismatch)
  3 = LIVE TRANSIENT UNAVAILABLE (429/5xx/network/timeout)
  4 = RUNTIME DRIFT (gateway process older than config/.env or code SHA mismatch)
  5 = TOOL / IO ERROR
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml
from pydantic import BaseModel, Field

EXIT_PASS = 0
EXIT_STATIC = 1
EXIT_LIVE_CONTRACT = 2
EXIT_LIVE_TRANSIENT = 3
EXIT_DRIFT = 4
EXIT_TOOL_ERROR = 5

DEFAULT_HERMES_HOME = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes")))
SECRET_KEY_TOKENS = ("api_key", "secret", "token", "password", "private_key")


class Finding(BaseModel):
    rule: str
    severity: str = "error"  # "error" | "warning" | "info"
    layer: str  # "static" | "policy" | "live" | "drift"
    message: str
    remediation: str
    details: dict[str, Any] = Field(default_factory=dict)


class FallbackPolicy(BaseModel):
    allowed: list[dict[str, str]] = Field(default_factory=list)
    forbidden_patterns: list[str] = Field(default_factory=lambda: ["*opus*", "*claude-opus*"])
    require_explicit_list: bool = True
    forbid_legacy_fallback_model: bool = True


class ProviderInvariantsPolicy(BaseModel):
    require_context_length_for_default: bool = True
    require_auxiliary_models_declared: bool = True
    require_key_env_present: bool = True


class CompressionInvariantsPolicy(BaseModel):
    threshold_min: float = 0.1
    threshold_max: float = 0.95
    require_target_ratio_lt_threshold: bool = True


class LiveContractPolicy(BaseModel):
    timeout_seconds: float = 10.0
    require_catalog_context_length_coverage: bool = True


class DriftInvariantsPolicy(BaseModel):
    check_config_mtime_vs_gateway_start: bool = True
    check_env_mtime_vs_gateway_start: bool = True
    check_code_sha_vs_repo_head: bool = True


class SkillsInvariantsPolicy(BaseModel):
    forbidden_name_patterns: list[str] = Field(
        default_factory=lambda: ["*-hub", "*-hub-*", "hub", "*software-process*"]
    )


class HarnessPolicy(BaseModel):
    version: int = 1
    fallback_providers: FallbackPolicy = Field(default_factory=FallbackPolicy)
    provider_invariants: ProviderInvariantsPolicy = Field(default_factory=ProviderInvariantsPolicy)
    compression_invariants: CompressionInvariantsPolicy = Field(
        default_factory=CompressionInvariantsPolicy
    )
    live_contract: LiveContractPolicy = Field(default_factory=LiveContractPolicy)
    drift_invariants: DriftInvariantsPolicy = Field(default_factory=DriftInvariantsPolicy)
    skills_invariants: SkillsInvariantsPolicy = Field(default_factory=SkillsInvariantsPolicy)


def _strip_secrets(obj: Any) -> Any:
    if isinstance(obj, dict):
        cleaned: dict[str, Any] = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if any(tok in kl for tok in SECRET_KEY_TOKENS):
                cleaned[k] = "<REDACTED>" if v else ""
            else:
                cleaned[k] = _strip_secrets(v)
        return cleaned
    if isinstance(obj, list):
        return [_strip_secrets(item) for item in obj]
    return obj


def canonical_config_sha256(cfg: dict[str, Any]) -> str:
    sanitized = _strip_secrets(cfg)
    payload = json.dumps(sanitized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_yaml_file(path: Path) -> dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path} did not parse to a YAML mapping")
    return raw


def load_policy(path: Path) -> HarnessPolicy:
    return HarnessPolicy.model_validate(load_yaml_file(path))


def parse_dotenv_keys(env_path: Path) -> dict[str, bool]:
    """Return mapping of env key -> whether non-empty value is present. Never returns values."""
    present: dict[str, bool] = {}
    if not env_path.exists():
        return present
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key:
            present[key] = bool(val)
    return present


def read_env_secret(env_path: Path, key_name: str) -> str:
    val = os.environ.get(key_name, "").strip()
    if val:
        return val
    if not env_path.exists():
        return ""
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == key_name:
            return v.strip().strip('"').strip("'")
    return ""


def _norm_url(url: str) -> str:
    return (url or "").strip().rstrip("/")


def _extract_context_length(models_map: dict[str, Any], model_id: str) -> int | None:
    entry = models_map.get(model_id)
    if isinstance(entry, dict):
        val = entry.get("context_length")
        if isinstance(val, int) and not isinstance(val, bool) and val > 0:
            return val
    return None


def _extract_skill_frontmatter_name(skill_md: Path) -> str | None:
    try:
        text = skill_md.read_text(encoding="utf-8")
    except OSError:
        return None
    if not text.startswith("---"):
        return None
    parts = text.split("---", 2)
    if len(parts) < 3:
        return None
    try:
        fm = yaml.safe_load(parts[1])
    except Exception:
        return None
    if isinstance(fm, dict) and isinstance(fm.get("name"), str):
        return fm["name"].strip()
    return None


def verify_static(
    cfg: dict[str, Any],
    policy: HarnessPolicy,
    env_path: Path | None = None,
    skills_dir: Path | None = None,
) -> tuple[int, list[Finding]]:
    findings: list[Finding] = []

    # --- Layer 1A: Structural checks ---
    model_cfg = cfg.get("model")
    providers_cfg = cfg.get("providers")
    if not isinstance(model_cfg, dict):
        findings.append(
            Finding(
                rule="SCHEMA_MODEL_MISSING",
                layer="static",
                message="Top-level 'model' mapping is missing or invalid.",
                remediation="Set 'model.default' and 'model.provider' via `hermes config set`.",
            )
        )
        return EXIT_STATIC, findings

    if not isinstance(providers_cfg, dict):
        findings.append(
            Finding(
                rule="SCHEMA_PROVIDERS_MISSING",
                layer="static",
                message="Top-level 'providers' mapping is missing or invalid.",
                remediation="Define the active provider under 'providers.<name>' in config.yaml.",
            )
        )
        return EXIT_STATIC, findings

    active_provider = str(model_cfg.get("provider", "")).strip()
    default_model = str(model_cfg.get("default", "")).strip()
    model_base_url = _norm_url(str(model_cfg.get("base_url", "")))

    if not active_provider:
        findings.append(
            Finding(
                rule="SCHEMA_ACTIVE_PROVIDER_EMPTY",
                layer="static",
                message="'model.provider' is empty.",
                remediation="Run `hermes config set model.provider <provider>`.",
            )
        )
    if not default_model:
        findings.append(
            Finding(
                rule="SCHEMA_DEFAULT_MODEL_EMPTY",
                layer="static",
                message="'model.default' is empty.",
                remediation="Run `hermes config set model.default <model_id>`.",
            )
        )

    # --- Layer 1B: Cross-field semantic invariants ---
    provider_block = providers_cfg.get(active_provider) if active_provider else None
    provider_models: dict[str, Any] = {}
    if active_provider and not isinstance(provider_block, dict):
        findings.append(
            Finding(
                rule="SEMANTIC_PROVIDER_UNDECLARED",
                layer="static",
                message=f"Active provider '{active_provider}' is not defined under 'providers'.",
                remediation=f"Declare 'providers.{active_provider}' or update 'model.provider'.",
                details={"active_provider": active_provider},
            )
        )
    elif isinstance(provider_block, dict):
        prov_url = _norm_url(str(provider_block.get("base_url", "")))
        if model_base_url and prov_url and model_base_url != prov_url:
            findings.append(
                Finding(
                    rule="SEMANTIC_BASE_URL_MISMATCH",
                    layer="static",
                    message=(
                        f"model.base_url ('{model_base_url}') does not match "
                        f"providers.{active_provider}.base_url ('{prov_url}')."
                    ),
                    remediation="Align model.base_url and providers.<active>.base_url.",
                    details={"model_base_url": model_base_url, "provider_base_url": prov_url},
                )
            )

        raw_models = provider_block.get("models")
        if isinstance(raw_models, dict):
            provider_models = raw_models

        if policy.provider_invariants.require_context_length_for_default and default_model:
            if _extract_context_length(provider_models, default_model) is None:
                findings.append(
                    Finding(
                        rule="SEMANTIC_DEFAULT_CONTEXT_LENGTH_MISSING",
                        layer="static",
                        message=(
                            f"Default model '{default_model}' lacks a positive context_length "
                            f"under providers.{active_provider}.models (causes 256k probe-down)."
                        ),
                        remediation=(
                            f"Run `hermes config set providers.{active_provider}.models."
                            f"{default_model}.context_length <tokens>`."
                        ),
                        details={"provider": active_provider, "model": default_model},
                    )
                )

        if policy.provider_invariants.require_key_env_present:
            key_env = str(model_cfg.get("key_env") or provider_block.get("key_env") or "").strip()
            if key_env:
                dotenv_presence = parse_dotenv_keys(env_path) if env_path else {}
                in_proc = bool(os.environ.get(key_env, "").strip())
                if not (in_proc or dotenv_presence.get(key_env, False)):
                    findings.append(
                        Finding(
                            rule="SEMANTIC_KEY_ENV_MISSING",
                            layer="static",
                            message=(
                                f"Required credential env var '{key_env}' is absent or empty "
                                "in process environment and .env."
                            ),
                            remediation=f"Set '{key_env}' in ~/.hermes/.env.",
                            details={"key_env": key_env},
                        )
                    )

    # Auxiliary model coherence
    aux_cfg = cfg.get("auxiliary")
    if policy.provider_invariants.require_auxiliary_models_declared and isinstance(aux_cfg, dict):
        for role, role_cfg in aux_cfg.items():
            if not isinstance(role_cfg, dict):
                continue
            aux_model = str(role_cfg.get("model", "") or "").strip()
            if not aux_model:
                continue
            aux_provider = str(role_cfg.get("provider", "auto") or "auto").strip()
            if aux_provider in ("auto", active_provider):
                if aux_model not in provider_models:
                    findings.append(
                        Finding(
                            rule="SEMANTIC_AUX_MODEL_UNDECLARED",
                            layer="static",
                            message=(
                                f"auxiliary.{role}.model='{aux_model}' (provider='{aux_provider}') "
                                f"is not declared under providers.{active_provider}.models "
                                "(risk of 404 and 45-200s fallback stalls)."
                            ),
                            remediation=(
                                f"Run `hermes config set auxiliary.{role}.model ''` to use auto "
                                f"resolution, or set a model valid on '{active_provider}'."
                            ),
                            details={
                                "role": role,
                                "model": aux_model,
                                "aux_provider": aux_provider,
                                "active_provider": active_provider,
                            },
                        )
                    )

    # Compression ratio invariants
    comp_cfg = cfg.get("compression")
    if isinstance(comp_cfg, dict) and comp_cfg.get("enabled", True):
        threshold = comp_cfg.get("threshold")
        target_ratio = comp_cfg.get("target_ratio")
        ci = policy.compression_invariants
        if not isinstance(threshold, (int, float)) or not (
            ci.threshold_min <= float(threshold) <= ci.threshold_max
        ):
            findings.append(
                Finding(
                    rule="SCHEMA_COMPRESSION_THRESHOLD_INVALID",
                    layer="static",
                    message=(
                        f"compression.threshold={threshold!r} outside allowed range "
                        f"[{ci.threshold_min}, {ci.threshold_max}]."
                    ),
                    remediation="Set compression.threshold within the allowed range.",
                )
            )
        if ci.require_target_ratio_lt_threshold and isinstance(threshold, (int, float)):
            if not isinstance(target_ratio, (int, float)) or not (
                0 < float(target_ratio) < float(threshold)
            ):
                findings.append(
                    Finding(
                        rule="SEMANTIC_COMPRESSION_RATIO_INVALID",
                        layer="static",
                        message=(
                            f"compression.target_ratio={target_ratio!r} must satisfy "
                            f"0 < target_ratio < threshold ({threshold!r})."
                        ),
                        remediation="Adjust compression.target_ratio below compression.threshold.",
                    )
                )

    # --- Layer 1C: Forbidden-policy lint (fail-closed) ---
    fb_policy = policy.fallback_providers
    if fb_policy.forbid_legacy_fallback_model and cfg.get("fallback_model"):
        findings.append(
            Finding(
                rule="POLICY_LEGACY_FALLBACK_MODEL_FORBIDDEN",
                layer="policy",
                message=f"Legacy 'fallback_model' is set ({cfg.get('fallback_model')!r}).",
                remediation="Run `hermes config unset fallback_model`.",
            )
        )

    if "fallback_providers" not in cfg:
        if fb_policy.require_explicit_list:
            findings.append(
                Finding(
                    rule="POLICY_FALLBACK_NOT_EXPLICIT",
                    layer="policy",
                    message=(
                        "'fallback_providers' key is omitted from config.yaml; "
                        "policy requires an explicit list (e.g. `fallback_providers: []`)."
                    ),
                    remediation="Run `hermes config set fallback_providers '[]'`.",
                )
            )
    else:
        fb_list = cfg.get("fallback_providers")
        if not isinstance(fb_list, list):
            findings.append(
                Finding(
                    rule="SCHEMA_FALLBACK_PROVIDERS_TYPE",
                    layer="static",
                    message=f"'fallback_providers' must be a list, got {type(fb_list).__name__}.",
                    remediation="Run `hermes config set fallback_providers '[]'`.",
                )
            )
        else:
            allowed_pairs = {
                (str(a.get("provider", "")).strip(), str(a.get("model", "")).strip())
                for a in fb_policy.allowed
            }
            for idx, item in enumerate(fb_list):
                if isinstance(item, dict):
                    fb_prov = str(item.get("provider", "")).strip()
                    fb_model = str(item.get("model", "")).strip()
                else:
                    fb_prov = ""
                    fb_model = str(item).strip()
                combined = f"{fb_prov}/{fb_model}" if fb_prov else fb_model
                matched_forbidden = [
                    pat
                    for pat in fb_policy.forbidden_patterns
                    if fnmatch.fnmatch(fb_model.lower(), pat.lower())
                    or fnmatch.fnmatch(combined.lower(), pat.lower())
                ]
                if matched_forbidden:
                    findings.append(
                        Finding(
                            rule="POLICY_FORBIDDEN_FALLBACK",
                            layer="policy",
                            message=(
                                f"fallback_providers[{idx}] ('{combined}') matches forbidden "
                                f"policy pattern(s): {matched_forbidden}."
                            ),
                            remediation="Remove unauthorized fallback via `hermes config set fallback_providers '[]'`.",
                            details={"index": idx, "provider": fb_prov, "model": fb_model},
                        )
                    )
                elif (fb_prov, fb_model) not in allowed_pairs:
                    findings.append(
                        Finding(
                            rule="POLICY_UNAPPROVED_FALLBACK",
                            layer="policy",
                            message=(
                                f"fallback_providers[{idx}] ('{combined}') is not in "
                                "birkin-policy.yaml fallback_providers.allowed."
                            ),
                            remediation=(
                                "Remove it (`hermes config set fallback_providers '[]'`) "
                                "or obtain owner approval to add it to birkin-policy.yaml."
                            ),
                            details={"index": idx, "provider": fb_prov, "model": fb_model},
                        )
                    )

    # --- Layer 1D: Skill naming invariants (fail-closed) ---
    skill_patterns = policy.skills_invariants.forbidden_name_patterns
    if skills_dir is not None and skills_dir.is_dir() and skill_patterns:
        for skill_md in sorted(skills_dir.rglob("SKILL.md")):
            rel_parts = skill_md.relative_to(skills_dir).parts
            if any(part.startswith(".") for part in rel_parts):
                continue
            dir_name = skill_md.parent.name
            fm_name = _extract_skill_frontmatter_name(skill_md) or ""
            candidates = [("directory", dir_name)]
            if fm_name and fm_name != dir_name:
                candidates.append(("frontmatter", fm_name))
            for source, candidate in candidates:
                matched = [
                    pat
                    for pat in skill_patterns
                    if fnmatch.fnmatch(candidate.lower(), pat.lower())
                ]
                if matched:
                    findings.append(
                        Finding(
                            rule="POLICY_FORBIDDEN_SKILL_NAME",
                            layer="policy",
                            message=(
                                f"Skill {source} name '{candidate}' ({skill_md}) matches forbidden "
                                f"policy pattern(s): {matched}."
                            ),
                            remediation=(
                                "Rename the skill directory and SKILL.md frontmatter `name:` "
                                "to remove forbidden naming tokens (e.g. `-hub`, `software-process`)."
                            ),
                            details={
                                "path": str(skill_md),
                                "source": source,
                                "name": candidate,
                                "patterns": matched,
                            },
                        )
                    )

    exit_code = EXIT_STATIC if any(f.severity == "error" for f in findings) else EXIT_PASS
    return exit_code, findings


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
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "endpoint": None,
        "catalog_count": 0,
        "probe_enabled": probe,
    }

    model_cfg = cfg.get("model") or {}
    providers_cfg = cfg.get("providers") or {}
    active_provider = str(model_cfg.get("provider", "")).strip()
    default_model = str(model_cfg.get("default", "")).strip()
    provider_block = providers_cfg.get(active_provider) if isinstance(providers_cfg, dict) else {}
    provider_block = provider_block if isinstance(provider_block, dict) else {}
    base_url = _norm_url(str(model_cfg.get("base_url") or provider_block.get("base_url") or ""))
    key_env = str(model_cfg.get("key_env") or provider_block.get("key_env") or "").strip()
    api_key = read_env_secret(env_path, key_env) if (env_path and key_env) else os.environ.get(key_env, "")

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

            if resp.status_code in (429, 500, 502, 503, 504):
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
            meta["catalog_sha256"] = hashlib.sha256(
                json.dumps(sorted(catalog.keys())).encode("utf-8")
            ).hexdigest()

            provider_models = provider_block.get("models")
            provider_models = provider_models if isinstance(provider_models, dict) else {}

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
                    adv = mobj.get("context_length") or mobj.get("max_model_len")
                    if not isinstance(adv, int) or adv <= 0:
                        continue
                    configured = _extract_context_length(provider_models, mid)
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
                probe_models = [default_model]
                if isinstance(aux_cfg, dict):
                    comp_aux = aux_cfg.get("compression")
                    if isinstance(comp_aux, dict):
                        cm = str(comp_aux.get("model", "") or "").strip()
                        cp = str(comp_aux.get("provider", "auto") or "auto").strip()
                        if cm and cp in ("auto", active_provider) and cm not in probe_models:
                            probe_models.append(cm)
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
                    if pr.status_code in (429, 500, 502, 503, 504):
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

    except (httpx.TimeoutException, httpx.NetworkError) as exc:
        findings.append(
            Finding(
                rule="LIVE_NETWORK_UNAVAILABLE",
                layer="live",
                message=f"Network/timeout error reaching {models_url}: {exc}",
                remediation="Check network connectivity and upstream gateway availability.",
            )
        )
        return EXIT_LIVE_TRANSIENT, findings, meta

    if any(f.rule.startswith("LIVE_") and "TRANSIENT" not in f.rule for f in findings):
        return EXIT_LIVE_CONTRACT, findings, meta
    if any("TRANSIENT" in f.rule for f in findings):
        return EXIT_LIVE_TRANSIENT, findings, meta
    return EXIT_PASS, findings, meta


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


def verify_drift(
    config_path: Path,
    env_path: Path,
    hermes_home: Path,
    policy: HarnessPolicy,
    *,
    pid_alive_fn: Any = _pid_is_alive,
    git_head_fn: Any = _git_head_sha,
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
            lifecycle = json.loads(lifecycle_path.read_text(encoding="utf-8"))
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
            gw_state = json.loads(gw_state_path.read_text(encoding="utf-8"))
        except Exception:
            gw_state = {}

    pid = lifecycle.get("pid") or gw_state.get("pid")
    create_time = lifecycle.get("create_time") or lifecycle.get("start_time")
    meta["gateway_pid"] = pid
    meta["gateway_create_time"] = create_time

    if not pid:
        findings.append(
            Finding(
                rule="DRIFT_GATEWAY_STATE_MISSING",
                layer="drift",
                message="No running gateway PID recorded in gateway.lifecycle.json or gateway_state.json.",
                remediation="Start or check the gateway with `hermes gateway status`.",
            )
        )
        return EXIT_DRIFT, findings, meta

    if not pid_alive_fn(int(pid)):
        findings.append(
            Finding(
                rule="DRIFT_GATEWAY_PID_DEAD",
                layer="drift",
                message=f"Recorded gateway PID {pid} is not running.",
                remediation="Restart gateway via `hermes gateway restart`.",
                details={"pid": pid},
            )
        )
        return EXIT_DRIFT, findings, meta

    if isinstance(create_time, (int, float)):
        gw_iso = datetime.fromtimestamp(float(create_time), tz=timezone.utc).isoformat()
        meta["gateway_started_utc"] = gw_iso

        if policy.drift_invariants.check_config_mtime_vs_gateway_start and config_path.exists():
            cfg_mtime = config_path.stat().st_mtime
            if cfg_mtime > float(create_time):
                cfg_iso = datetime.fromtimestamp(cfg_mtime, tz=timezone.utc).isoformat()
                findings.append(
                    Finding(
                        rule="DRIFT_CONFIG_NEWER_THAN_GATEWAY",
                        layer="drift",
                        message=(
                            f"config.yaml was modified at {cfg_iso}, after gateway PID {pid} "
                            f"started at {gw_iso} (in-memory config/fallback_providers may be stale)."
                        ),
                        remediation="Run `hermes gateway restart` from a separate shell to load the current config.",
                        details={
                            "pid": pid,
                            "gateway_create_time": create_time,
                            "config_mtime": cfg_mtime,
                        },
                    )
                )

        if policy.drift_invariants.check_env_mtime_vs_gateway_start and env_path.exists():
            env_mtime = env_path.stat().st_mtime
            if env_mtime > float(create_time):
                env_iso = datetime.fromtimestamp(env_mtime, tz=timezone.utc).isoformat()
                findings.append(
                    Finding(
                        rule="DRIFT_ENV_NEWER_THAN_GATEWAY",
                        layer="drift",
                        message=(
                            f".env was modified at {env_iso}, after gateway PID {pid} "
                            f"started at {gw_iso}."
                        ),
                        remediation="Run `/reload` or `hermes gateway restart` from a separate shell.",
                        details={
                            "pid": pid,
                            "gateway_create_time": create_time,
                            "env_mtime": env_mtime,
                        },
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
                        f"Gateway PID {pid} is running code_sha={running_sha[:12]}, "
                        f"but hermes-agent HEAD is {head_sha[:12]}."
                    ),
                    remediation="Run `hermes gateway restart` from a separate shell.",
                    details={"running_code_sha": running_sha, "repo_head_sha": head_sha},
                )
            )

    exit_code = EXIT_DRIFT if findings else EXIT_PASS
    return exit_code, findings, meta


def _combine_exit_codes(codes: list[int]) -> int:
    # Severity precedence: tool error > static/policy > live contract > drift > transient > pass
    precedence = [
        EXIT_TOOL_ERROR,
        EXIT_STATIC,
        EXIT_LIVE_CONTRACT,
        EXIT_DRIFT,
        EXIT_LIVE_TRANSIENT,
        EXIT_PASS,
    ]
    for code in precedence:
        if code in codes:
            return code
    return EXIT_PASS


def _format_human(report: dict[str, Any]) -> str:
    lines = [
        f"birkin ({report['command']}): status={report['status']} exit_code={report['exit_code']}",
        f"  config_sha256: {report.get('config_sha256', 'n/a')}",
    ]
    for name, sec in report.get("sections", {}).items():
        lines.append(f"  [{name}] exit_code={sec['exit_code']} findings={len(sec['findings'])}")
        for f in sec["findings"]:
            lines.append(f"    - {f['rule']} ({f['severity']}): {f['message']}")
            lines.append(f"      remediation: {f['remediation']}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="birkin", description="Birkin — Mechanical Hermes harness verifier")
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--home", type=Path, default=DEFAULT_HERMES_HOME)
        sp.add_argument("--config", type=Path, default=None)
        sp.add_argument("--policy", type=Path, default=None)
        sp.add_argument("--env", type=Path, default=None)
        sp.add_argument("--json", action="store_true", dest="as_json")

    add_common(sub.add_parser("static", help="Run structural, semantic, and policy checks"))

    p_live = sub.add_parser("live", help="Run live provider /v1/models contract checks")
    add_common(p_live)
    p_live.add_argument("--probe", action="store_true", help="Also run 1-token micro-probe")
    p_live.add_argument("--timeout", type=float, default=None)

    add_common(sub.add_parser("drift", help="Prove running gateway matches on-disk config and code"))

    p_all = sub.add_parser("all", help="Run static, optional live, and drift checks")
    add_common(p_all)
    p_all.add_argument("--live", action="store_true", help="Include live /v1/models contract check")
    p_all.add_argument("--probe", action="store_true", help="Include 1-token micro-probe (implies --live)")
    p_all.add_argument("--timeout", type=float, default=None)
    p_all.add_argument("--no-write-state", action="store_true")

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    hermes_home: Path = args.home
    config_path: Path = args.config or (hermes_home / "config.yaml")
    policy_path: Path = args.policy or (hermes_home / "birkin-policy.yaml")
    env_path: Path = args.env or (hermes_home / ".env")

    try:
        cfg = load_yaml_file(config_path)
        policy = load_policy(policy_path) if policy_path.exists() else HarnessPolicy()
    except Exception as exc:
        err = {
            "command": args.command,
            "status": "ERROR",
            "exit_code": EXIT_TOOL_ERROR,
            "error": str(exc),
        }
        print(json.dumps(err, indent=2) if args.as_json else f"ERROR: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR

    sections: dict[str, Any] = {}
    codes: list[int] = []

    if args.command in ("static", "all"):
        c, f = verify_static(cfg, policy, env_path=env_path, skills_dir=hermes_home / "skills")
        codes.append(c)
        sections["static"] = {
            "exit_code": c,
            "findings": [item.model_dump() for item in f],
        }

    if args.command == "live" or (args.command == "all" and (args.live or args.probe)):
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

    if args.command in ("drift", "all"):
        c, f, meta = verify_drift(config_path, env_path, hermes_home, policy)
        codes.append(c)
        sections["drift"] = {
            "exit_code": c,
            "meta": meta,
            "findings": [item.model_dump() for item in f],
        }

    final_code = _combine_exit_codes(codes)
    report = {
        "command": args.command,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if final_code == EXIT_PASS else "FAIL",
        "exit_code": final_code,
        "config_sha256": canonical_config_sha256(cfg),
        "sections": sections,
    }

    if args.command == "all" and not getattr(args, "no_write_state", False):
        state_file = hermes_home / "state" / "birkin.json"
        try:
            state_file.parent.mkdir(parents=True, exist_ok=True)
            state_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass

    if args.as_json:
        print(json.dumps(report, indent=2))
    else:
        print(_format_human(report))

    return final_code


if __name__ == "__main__":
    raise SystemExit(main())
