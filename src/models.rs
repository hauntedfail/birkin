//! Data models and fail-closed Hermes runtime policy schema for Birkin.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub rule: String,
    #[serde(default = "default_error_severity")]
    pub severity: String,
    pub layer: String,
    pub message: String,
    pub remediation: String,
    #[serde(default)]
    pub details: BTreeMap<String, Value>,
}

fn default_error_severity() -> String {
    "error".to_string()
}

fn default_true() -> bool {
    true
}

fn default_version() -> u32 {
    1
}

fn default_forbidden_patterns() -> Vec<String> {
    vec!["*opus*".to_string(), "*claude-opus*".to_string()]
}

fn default_threshold_min() -> f64 {
    0.1
}

fn default_threshold_max() -> f64 {
    0.95
}

fn default_live_timeout() -> f64 {
    10.0
}

fn default_skill_patterns() -> Vec<String> {
    vec![
        "*-hub".to_string(),
        "*-hub-*".to_string(),
        "hub".to_string(),
        "*software-process*".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FallbackEntry {
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FallbackPolicy {
    #[serde(default)]
    pub allowed: Vec<FallbackEntry>,
    #[serde(default = "default_forbidden_patterns")]
    pub forbidden_patterns: Vec<String>,
    #[serde(default = "default_true")]
    pub require_explicit_list: bool,
    #[serde(default = "default_true")]
    pub forbid_legacy_fallback_model: bool,
    #[serde(default = "default_true")]
    pub enforce_forbidden_globally: bool,
}

impl Default for FallbackPolicy {
    fn default() -> Self {
        Self {
            allowed: Vec::new(),
            forbidden_patterns: default_forbidden_patterns(),
            require_explicit_list: true,
            forbid_legacy_fallback_model: true,
            enforce_forbidden_globally: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProviderInvariantsPolicy {
    #[serde(default = "default_true")]
    pub require_context_length_for_default: bool,
    #[serde(default = "default_true")]
    pub require_auxiliary_models_declared: bool,
    #[serde(default = "default_true")]
    pub require_key_env_present: bool,
}

impl Default for ProviderInvariantsPolicy {
    fn default() -> Self {
        Self {
            require_context_length_for_default: true,
            require_auxiliary_models_declared: true,
            require_key_env_present: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompressionInvariantsPolicy {
    #[serde(default = "default_threshold_min")]
    pub threshold_min: f64,
    #[serde(default = "default_threshold_max")]
    pub threshold_max: f64,
    #[serde(default = "default_true")]
    pub require_target_ratio_lt_threshold: bool,
}

impl Default for CompressionInvariantsPolicy {
    fn default() -> Self {
        Self {
            threshold_min: default_threshold_min(),
            threshold_max: default_threshold_max(),
            require_target_ratio_lt_threshold: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LiveContractPolicy {
    #[serde(default = "default_live_timeout")]
    pub timeout_seconds: f64,
    #[serde(default = "default_true")]
    pub require_catalog_context_length_coverage: bool,
}

impl Default for LiveContractPolicy {
    fn default() -> Self {
        Self {
            timeout_seconds: default_live_timeout(),
            require_catalog_context_length_coverage: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DriftInvariantsPolicy {
    #[serde(default = "default_true")]
    pub check_config_mtime_vs_gateway_start: bool,
    #[serde(default = "default_true")]
    pub check_env_mtime_vs_gateway_start: bool,
    #[serde(default = "default_true")]
    pub check_code_sha_vs_repo_head: bool,
}

impl Default for DriftInvariantsPolicy {
    fn default() -> Self {
        Self {
            check_config_mtime_vs_gateway_start: true,
            check_env_mtime_vs_gateway_start: true,
            check_code_sha_vs_repo_head: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SkillsInvariantsPolicy {
    #[serde(default = "default_skill_patterns")]
    pub forbidden_name_patterns: Vec<String>,
}

impl Default for SkillsInvariantsPolicy {
    fn default() -> Self {
        Self {
            forbidden_name_patterns: default_skill_patterns(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicy {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub fallback_providers: FallbackPolicy,
    #[serde(default)]
    pub provider_invariants: ProviderInvariantsPolicy,
    #[serde(default)]
    pub compression_invariants: CompressionInvariantsPolicy,
    #[serde(default)]
    pub live_contract: LiveContractPolicy,
    #[serde(default)]
    pub drift_invariants: DriftInvariantsPolicy,
    #[serde(default)]
    pub skills_invariants: SkillsInvariantsPolicy,
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self {
            version: default_version(),
            fallback_providers: FallbackPolicy::default(),
            provider_invariants: ProviderInvariantsPolicy::default(),
            compression_invariants: CompressionInvariantsPolicy::default(),
            live_contract: LiveContractPolicy::default(),
            drift_invariants: DriftInvariantsPolicy::default(),
            skills_invariants: SkillsInvariantsPolicy::default(),
        }
    }
}
