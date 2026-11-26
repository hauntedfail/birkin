"""Data models and fail-closed policy schema for Birkin."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Finding(BaseModel):
    rule: str
    severity: Literal["error", "warning", "info"] = "error"
    layer: Literal["static", "policy", "live", "drift"]
    message: str
    remediation: str
    details: dict[str, Any] = Field(default_factory=dict)


class _StrictPolicyModel(BaseModel):
    """Base policy model: reject unknown keys so typos fail closed."""

    model_config = ConfigDict(extra="forbid")


class FallbackPolicy(_StrictPolicyModel):
    allowed: list[dict[str, str]] = Field(default_factory=list)
    forbidden_patterns: list[str] = Field(default_factory=lambda: ["*opus*", "*claude-opus*"])
    require_explicit_list: bool = True
    forbid_legacy_fallback_model: bool = True
    enforce_forbidden_globally: bool = True


class ProviderInvariantsPolicy(_StrictPolicyModel):
    require_context_length_for_default: bool = True
    require_auxiliary_models_declared: bool = True
    require_key_env_present: bool = True


class CompressionInvariantsPolicy(_StrictPolicyModel):
    threshold_min: float = 0.1
    threshold_max: float = 0.95
    require_target_ratio_lt_threshold: bool = True


class LiveContractPolicy(_StrictPolicyModel):
    timeout_seconds: float = 10.0
    require_catalog_context_length_coverage: bool = True


class DriftInvariantsPolicy(_StrictPolicyModel):
    check_config_mtime_vs_gateway_start: bool = True
    check_env_mtime_vs_gateway_start: bool = True
    check_code_sha_vs_repo_head: bool = True


class SkillsInvariantsPolicy(_StrictPolicyModel):
    forbidden_name_patterns: list[str] = Field(
        default_factory=lambda: ["*-hub", "*-hub-*", "hub", "*software-process*"]
    )


class HarnessPolicy(_StrictPolicyModel):
    version: int = 1
    fallback_providers: FallbackPolicy = Field(default_factory=FallbackPolicy)
    provider_invariants: ProviderInvariantsPolicy = Field(default_factory=ProviderInvariantsPolicy)
    compression_invariants: CompressionInvariantsPolicy = Field(
        default_factory=CompressionInvariantsPolicy
    )
    live_contract: LiveContractPolicy = Field(default_factory=LiveContractPolicy)
    drift_invariants: DriftInvariantsPolicy = Field(default_factory=DriftInvariantsPolicy)
    skills_invariants: SkillsInvariantsPolicy = Field(default_factory=SkillsInvariantsPolicy)
