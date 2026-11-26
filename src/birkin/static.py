"""Layer 1: Structural, cross-field semantic, and fail-closed policy verification."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Any

import yaml

from birkin.config_utils import (
    extract_context_length,
    is_number,
    norm_url,
    parse_dotenv_keys,
    resolve_key_env,
    resolve_provider_block,
    resolve_provider_models,
)
from birkin.constants import EXIT_PASS, EXIT_STATIC
from birkin.models import Finding, HarnessPolicy


def _match_forbidden(provider: str, model: str, patterns: list[str]) -> list[str]:
    if not model and not provider:
        return []
    combined = f"{provider}/{model}" if provider else model
    model_l = model.lower()
    combined_l = combined.lower()
    return [
        pat
        for pat in patterns
        if fnmatch.fnmatch(model_l, pat.lower()) or fnmatch.fnmatch(combined_l, pat.lower())
    ]


def _extract_skill_frontmatter_name(skill_md: Path) -> str | None:
    try:
        lines = skill_md.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    if not lines or lines[0].strip() != "---":
        return None
    end_idx: int | None = None
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            end_idx = idx
            break
    if end_idx is None:
        return None
    try:
        fm = yaml.safe_load("\n".join(lines[1:end_idx]))
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
    custom_providers_cfg = cfg.get("custom_providers")
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

    if not isinstance(providers_cfg, dict) and not isinstance(custom_providers_cfg, list):
        findings.append(
            Finding(
                rule="SCHEMA_PROVIDERS_MISSING",
                layer="static",
                message="Top-level 'providers' mapping (or 'custom_providers' list) is missing or invalid.",
                remediation="Define the active provider under 'providers.<name>' in config.yaml.",
            )
        )
        return EXIT_STATIC, findings

    active_provider = str(model_cfg.get("provider", "") or "").strip()
    default_model = str(model_cfg.get("default", "") or "").strip()
    model_base_url = norm_url(str(model_cfg.get("base_url", "") or ""))

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
    provider_block = resolve_provider_block(cfg, active_provider)
    provider_models: dict[str, dict[str, Any]] = {}
    if active_provider and provider_block is None:
        findings.append(
            Finding(
                rule="SEMANTIC_PROVIDER_UNDECLARED",
                layer="static",
                message=f"Active provider '{active_provider}' is not defined under 'providers' or 'custom_providers'.",
                remediation=f"Declare 'providers.{active_provider}' or update 'model.provider'.",
                details={"active_provider": active_provider},
            )
        )
    elif provider_block is not None:
        prov_url = norm_url(str(provider_block.get("base_url", "") or ""))
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

        provider_models = resolve_provider_models(provider_block)

        if policy.provider_invariants.require_context_length_for_default and default_model:
            if extract_context_length(provider_models, default_model) is None:
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
            key_env = resolve_key_env(model_cfg, provider_block)
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
                elif extract_context_length(provider_models, aux_model) is None:
                    findings.append(
                        Finding(
                            rule="SEMANTIC_AUX_CONTEXT_LENGTH_MISSING",
                            layer="static",
                            message=(
                                f"auxiliary.{role}.model='{aux_model}' lacks a positive "
                                f"context_length under providers.{active_provider}.models."
                            ),
                            remediation=(
                                f"Run `hermes config set providers.{active_provider}.models."
                                f"{aux_model}.context_length <tokens>`."
                            ),
                            details={
                                "role": role,
                                "model": aux_model,
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
        if not is_number(threshold) or not (ci.threshold_min <= float(threshold) <= ci.threshold_max):
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
        if ci.require_target_ratio_lt_threshold and is_number(threshold):
            if not is_number(target_ratio) or not (0 < float(target_ratio) < float(threshold)):
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

    if fb_policy.enforce_forbidden_globally and fb_policy.forbidden_patterns:
        if default_model:
            matched_default = _match_forbidden(
                active_provider, default_model, fb_policy.forbidden_patterns
            )
            if matched_default:
                combined = f"{active_provider}/{default_model}" if active_provider else default_model
                findings.append(
                    Finding(
                        rule="POLICY_FORBIDDEN_DEFAULT_MODEL",
                        layer="policy",
                        message=(
                            f"model.default ('{combined}') matches forbidden "
                            f"policy pattern(s): {matched_default}."
                        ),
                        remediation="Set `model.default` to an allowed model.",
                        details={"provider": active_provider, "model": default_model},
                    )
                )
        if isinstance(aux_cfg, dict):
            for role, role_cfg in aux_cfg.items():
                if not isinstance(role_cfg, dict):
                    continue
                aux_model = str(role_cfg.get("model", "") or "").strip()
                if not aux_model:
                    continue
                aux_provider = str(role_cfg.get("provider", "auto") or "auto").strip()
                eff_provider = active_provider if aux_provider == "auto" else aux_provider
                matched_aux = _match_forbidden(eff_provider, aux_model, fb_policy.forbidden_patterns)
                if matched_aux:
                    combined = f"{eff_provider}/{aux_model}" if eff_provider else aux_model
                    findings.append(
                        Finding(
                            rule="POLICY_FORBIDDEN_AUX_MODEL",
                            layer="policy",
                            message=(
                                f"auxiliary.{role}.model ('{combined}') matches forbidden "
                                f"policy pattern(s): {matched_aux}."
                            ),
                            remediation=f"Run `hermes config set auxiliary.{role}.model ''` or pick an allowed model.",
                            details={"role": role, "provider": eff_provider, "model": aux_model},
                        )
                    )

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
                    fb_prov = str(item.get("provider", "") or "").strip()
                    fb_model = str(item.get("model", "") or "").strip()
                else:
                    fb_prov = ""
                    fb_model = str(item).strip()
                combined = f"{fb_prov}/{fb_model}" if fb_prov else fb_model
                matched_forbidden = _match_forbidden(
                    fb_prov, fb_model, fb_policy.forbidden_patterns
                )
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
