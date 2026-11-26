//! Layer 1: Hermes structural, cross-field semantic, policy, and skill-naming verification.

use crate::config_utils::{
    as_number, extract_context_length, get_str, norm_url, parse_dotenv_keys, resolve_key_env,
    resolve_provider_block, resolve_provider_models,
};
use crate::constants::{EXIT_PASS, EXIT_STATIC};
use crate::glob::fnmatch_ci;
use crate::models::{Finding, RuntimePolicy};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

fn match_forbidden(provider: &str, model: &str, patterns: &[String]) -> Vec<String> {
    if model.is_empty() && provider.is_empty() {
        return Vec::new();
    }
    let combined = if provider.is_empty() {
        model.to_string()
    } else {
        format!("{provider}/{model}")
    };
    patterns
        .iter()
        .filter(|pat| fnmatch_ci(model, pat) || fnmatch_ci(&combined, pat))
        .cloned()
        .collect()
}

fn extract_skill_frontmatter_name(skill_md: &Path) -> Option<String> {
    let text = fs::read_to_string(skill_md).ok()?;
    let lines: Vec<&str> = text.lines().collect();
    if lines.first()?.trim() != "---" {
        return None;
    }
    let end_idx = lines.iter().skip(1).position(|l| l.trim() == "---")? + 1;
    let fm_text = lines[1..end_idx].join("\n");
    let val: serde_yaml::Value = serde_yaml::from_str(&fm_text).ok()?;
    val.as_mapping()?
        .get(serde_yaml::Value::String("name".into()))?
        .as_str()
        .map(|s| s.trim().to_string())
}

fn make_finding(
    rule: &str,
    layer: &str,
    message: String,
    remediation: String,
    details: BTreeMap<String, Value>,
) -> Finding {
    Finding {
        rule: rule.to_string(),
        severity: "error".to_string(),
        layer: layer.to_string(),
        message,
        remediation,
        details,
    }
}

pub fn verify_static(
    cfg_val: &Value,
    policy: &RuntimePolicy,
    env_path: Option<&Path>,
    skills_dir: Option<&Path>,
) -> (i32, Vec<Finding>) {
    let mut findings = Vec::new();
    let Some(cfg) = cfg_val.as_object() else {
        findings.push(make_finding(
            "SCHEMA_MODEL_MISSING",
            "static",
            "Top-level config must be a YAML mapping.".into(),
            "Verify ~/.hermes/config.yaml syntax.".into(),
            BTreeMap::new(),
        ));
        return (EXIT_STATIC, findings);
    };

    let Some(model_cfg) = cfg.get("model").and_then(Value::as_object) else {
        findings.push(make_finding(
            "SCHEMA_MODEL_MISSING",
            "static",
            "Top-level 'model' mapping is missing or invalid.".into(),
            "Set 'model.default' and 'model.provider' via `hermes config set`.".into(),
            BTreeMap::new(),
        ));
        return (EXIT_STATIC, findings);
    };

    let has_providers = cfg.get("providers").and_then(Value::as_object).is_some();
    let has_custom = cfg
        .get("custom_providers")
        .and_then(Value::as_array)
        .is_some();
    if !has_providers && !has_custom {
        findings.push(make_finding(
            "SCHEMA_PROVIDERS_MISSING",
            "static",
            "Top-level 'providers' mapping (or 'custom_providers' list) is missing or invalid."
                .into(),
            "Define the active provider under 'providers.<name>' in config.yaml.".into(),
            BTreeMap::new(),
        ));
        return (EXIT_STATIC, findings);
    }

    let active_provider = get_str(model_cfg, "provider");
    let default_model = get_str(model_cfg, "default");
    let model_base_url = norm_url(get_str(model_cfg, "base_url"));

    if active_provider.is_empty() {
        findings.push(make_finding(
            "SCHEMA_ACTIVE_PROVIDER_EMPTY",
            "static",
            "'model.provider' is empty.".into(),
            "Run `hermes config set model.provider <provider>`.".into(),
            BTreeMap::new(),
        ));
    }
    if default_model.is_empty() {
        findings.push(make_finding(
            "SCHEMA_DEFAULT_MODEL_EMPTY",
            "static",
            "'model.default' is empty.".into(),
            "Run `hermes config set model.default <model_id>`.".into(),
            BTreeMap::new(),
        ));
    }

    // Layer 1B: Cross-field semantic invariants
    let provider_block = resolve_provider_block(cfg, active_provider);
    let mut provider_models = BTreeMap::new();
    if !active_provider.is_empty() && provider_block.is_none() {
        findings.push(make_finding(
            "SEMANTIC_PROVIDER_UNDECLARED",
            "static",
            format!(
                "Active provider '{active_provider}' is not defined under 'providers' or 'custom_providers'."
            ),
            format!("Declare 'providers.{active_provider}' or update 'model.provider'."),
            BTreeMap::new(),
        ));
    } else if let Some(pblock) = provider_block {
        provider_models = resolve_provider_models(Some(pblock));
        let prov_base_url = norm_url(get_str(pblock, "base_url"));
        if !model_base_url.is_empty() && !prov_base_url.is_empty() && model_base_url != prov_base_url
        {
            let mut details = BTreeMap::new();
            details.insert("model_base_url".into(), json!(model_base_url));
            details.insert("provider_base_url".into(), json!(prov_base_url));
            findings.push(make_finding(
                "SEMANTIC_BASE_URL_MISMATCH",
                "static",
                format!(
                    "model.base_url ('{model_base_url}') does not match providers.{active_provider}.base_url ('{prov_base_url}')."
                ),
                format!("Align model.base_url and providers.{active_provider}.base_url."),
                details,
            ));
        }
        if !default_model.is_empty()
            && policy.provider_invariants.require_context_length_for_default
            && extract_context_length(&provider_models, default_model).is_none()
        {
            let mut details = BTreeMap::new();
            details.insert("provider".into(), json!(active_provider));
            details.insert("model".into(), json!(default_model));
            findings.push(make_finding(
                "SEMANTIC_DEFAULT_CONTEXT_LENGTH_MISSING",
                "static",
                format!(
                    "Active model.default='{default_model}' lacks a positive context_length under providers.{active_provider}.models."
                ),
                format!(
                    "Run `hermes config set providers.{active_provider}.models.{default_model}.context_length <tokens>`."
                ),
                details,
            ));
        }
        if policy.provider_invariants.require_key_env_present {
            let key_env = resolve_key_env(model_cfg, Some(pblock));
            if !key_env.is_empty() {
                let dotenv_presence = env_path
                    .map(parse_dotenv_keys)
                    .unwrap_or_default();
                let in_proc = env::var(&key_env)
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false);
                if !(in_proc || *dotenv_presence.get(&key_env).unwrap_or(&false)) {
                    let mut details = BTreeMap::new();
                    details.insert("key_env".into(), json!(key_env));
                    findings.push(make_finding(
                        "SEMANTIC_KEY_ENV_MISSING",
                        "static",
                        format!(
                            "Required credential env var '{key_env}' is absent or empty in process environment and .env."
                        ),
                        format!("Set '{key_env}' in ~/.hermes/.env."),
                        details,
                    ));
                }
            }
        }
    }

    // Auxiliary model coherence
    let aux_cfg = cfg.get("auxiliary").and_then(Value::as_object);
    if policy.provider_invariants.require_auxiliary_models_declared {
        if let Some(aux_map) = aux_cfg {
            for (role, role_val) in aux_map {
                let Some(role_cfg) = role_val.as_object() else {
                    continue;
                };
                let aux_model = get_str(role_cfg, "model");
                if aux_model.is_empty() {
                    continue;
                }
                let aux_provider = {
                    let p = get_str(role_cfg, "provider");
                    if p.is_empty() { "auto" } else { p }
                };
                if aux_provider == "auto" || aux_provider == active_provider {
                    if !provider_models.contains_key(aux_model) {
                        let mut details = BTreeMap::new();
                        details.insert("role".into(), json!(role));
                        details.insert("model".into(), json!(aux_model));
                        details.insert("aux_provider".into(), json!(aux_provider));
                        details.insert("active_provider".into(), json!(active_provider));
                        findings.push(make_finding(
                            "SEMANTIC_AUX_MODEL_UNDECLARED",
                            "static",
                            format!(
                                "auxiliary.{role}.model='{aux_model}' (provider='{aux_provider}') is not declared under providers.{active_provider}.models (risk of 404 and 45-200s fallback stalls)."
                            ),
                            format!(
                                "Run `hermes config set auxiliary.{role}.model ''` to use auto resolution, or set a model valid on '{active_provider}'."
                            ),
                            details,
                        ));
                    } else if extract_context_length(&provider_models, aux_model).is_none() {
                        let mut details = BTreeMap::new();
                        details.insert("role".into(), json!(role));
                        details.insert("model".into(), json!(aux_model));
                        details.insert("active_provider".into(), json!(active_provider));
                        findings.push(make_finding(
                            "SEMANTIC_AUX_CONTEXT_LENGTH_MISSING",
                            "static",
                            format!(
                                "auxiliary.{role}.model='{aux_model}' lacks a positive context_length under providers.{active_provider}.models."
                            ),
                            format!(
                                "Run `hermes config set providers.{active_provider}.models.{aux_model}.context_length <tokens>`."
                            ),
                            details,
                        ));
                    }
                }
            }
        }
    }

    // Compression ratio invariants
    if let Some(comp_cfg) = cfg.get("compression").and_then(Value::as_object) {
        let enabled = comp_cfg
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if enabled {
            let threshold = as_number(comp_cfg.get("threshold"));
            let target_ratio = as_number(comp_cfg.get("target_ratio"));
            let ci = &policy.compression_invariants;
            let threshold_ok = threshold
                .map(|t| t >= ci.threshold_min && t <= ci.threshold_max)
                .unwrap_or(false);
            if !threshold_ok {
                findings.push(make_finding(
                    "SCHEMA_COMPRESSION_THRESHOLD_INVALID",
                    "static",
                    format!(
                        "compression.threshold={:?} outside allowed range [{}, {}].",
                        comp_cfg.get("threshold"),
                        ci.threshold_min,
                        ci.threshold_max
                    ),
                    "Set compression.threshold within the allowed range.".into(),
                    BTreeMap::new(),
                ));
            }
            if ci.require_target_ratio_lt_threshold {
                if let Some(th) = threshold {
                    let ratio_ok = target_ratio.map(|r| r > 0.0 && r < th).unwrap_or(false);
                    if !ratio_ok {
                        findings.push(make_finding(
                            "SEMANTIC_COMPRESSION_RATIO_INVALID",
                            "static",
                            format!(
                                "compression.target_ratio={:?} must satisfy 0 < target_ratio < threshold ({th}).",
                                comp_cfg.get("target_ratio")
                            ),
                            "Adjust compression.target_ratio below compression.threshold.".into(),
                            BTreeMap::new(),
                        ));
                    }
                }
            }
        }
    }

    // Layer 1C: Forbidden-policy lint (fail-closed)
    let fb_policy = &policy.fallback_providers;
    if fb_policy.enforce_forbidden_globally && !fb_policy.forbidden_patterns.is_empty() {
        if !default_model.is_empty() {
            let matched = match_forbidden(
                active_provider,
                default_model,
                &fb_policy.forbidden_patterns,
            );
            if !matched.is_empty() {
                let combined = if active_provider.is_empty() {
                    default_model.to_string()
                } else {
                    format!("{active_provider}/{default_model}")
                };
                let mut details = BTreeMap::new();
                details.insert("provider".into(), json!(active_provider));
                details.insert("model".into(), json!(default_model));
                findings.push(make_finding(
                    "POLICY_FORBIDDEN_DEFAULT_MODEL",
                    "policy",
                    format!(
                        "model.default ('{combined}') matches forbidden policy pattern(s): {matched:?}."
                    ),
                    "Set `model.default` to an allowed model.".into(),
                    details,
                ));
            }
        }
        if let Some(aux_map) = aux_cfg {
            for (role, role_val) in aux_map {
                let Some(role_cfg) = role_val.as_object() else {
                    continue;
                };
                let aux_model = get_str(role_cfg, "model");
                if aux_model.is_empty() {
                    continue;
                }
                let aux_provider = {
                    let p = get_str(role_cfg, "provider");
                    if p.is_empty() { "auto" } else { p }
                };
                let eff_provider = if aux_provider == "auto" {
                    active_provider
                } else {
                    aux_provider
                };
                let matched = match_forbidden(eff_provider, aux_model, &fb_policy.forbidden_patterns);
                if !matched.is_empty() {
                    let combined = if eff_provider.is_empty() {
                        aux_model.to_string()
                    } else {
                        format!("{eff_provider}/{aux_model}")
                    };
                    let mut details = BTreeMap::new();
                    details.insert("role".into(), json!(role));
                    details.insert("provider".into(), json!(eff_provider));
                    details.insert("model".into(), json!(aux_model));
                    findings.push(make_finding(
                        "POLICY_FORBIDDEN_AUX_MODEL",
                        "policy",
                        format!(
                            "auxiliary.{role}.model ('{combined}') matches forbidden policy pattern(s): {matched:?}."
                        ),
                        format!(
                            "Run `hermes config set auxiliary.{role}.model ''` or pick an allowed model."
                        ),
                        details,
                    ));
                }
            }
        }
    }

    if fb_policy.forbid_legacy_fallback_model {
        let has_legacy = match cfg.get("fallback_model") {
            None | Some(Value::Null) => false,
            Some(Value::String(s)) => !s.trim().is_empty(),
            Some(Value::Object(m)) => !m.is_empty(),
            Some(Value::Bool(b)) => *b,
            _ => true,
        };
        if has_legacy {
            findings.push(make_finding(
                "POLICY_LEGACY_FALLBACK_MODEL_FORBIDDEN",
                "policy",
                format!("Legacy 'fallback_model' is set ({:?}).", cfg.get("fallback_model")),
                "Run `hermes config unset fallback_model`.".into(),
                BTreeMap::new(),
            ));
        }
    }

    match cfg.get("fallback_providers") {
        None => {
            if fb_policy.require_explicit_list {
                findings.push(make_finding(
                    "POLICY_FALLBACK_NOT_EXPLICIT",
                    "policy",
                    "'fallback_providers' key is omitted from config.yaml; policy requires an explicit list (e.g. `fallback_providers: []`).".into(),
                    "Run `hermes config set fallback_providers '[]'`.".into(),
                    BTreeMap::new(),
                ));
            }
        }
        Some(Value::Array(fb_list)) => {
            let allowed_pairs: HashSet<(String, String)> = fb_policy
                .allowed
                .iter()
                .map(|a| (a.provider.trim().to_string(), a.model.trim().to_string()))
                .collect();
            for (idx, item) in fb_list.iter().enumerate() {
                let (fb_prov, fb_model) = match item {
                    Value::Object(map) => (
                        get_str(map, "provider").to_string(),
                        get_str(map, "model").to_string(),
                    ),
                    Value::String(s) => (String::new(), s.trim().to_string()),
                    other => (String::new(), other.to_string()),
                };
                let combined = if fb_prov.is_empty() {
                    fb_model.clone()
                } else {
                    format!("{fb_prov}/{fb_model}")
                };
                let matched_forbidden =
                    match_forbidden(&fb_prov, &fb_model, &fb_policy.forbidden_patterns);
                if !matched_forbidden.is_empty() {
                    let mut details = BTreeMap::new();
                    details.insert("index".into(), json!(idx));
                    details.insert("provider".into(), json!(fb_prov));
                    details.insert("model".into(), json!(fb_model));
                    findings.push(make_finding(
                        "POLICY_FORBIDDEN_FALLBACK",
                        "policy",
                        format!(
                            "fallback_providers[{idx}] ('{combined}') matches forbidden policy pattern(s): {matched_forbidden:?}."
                        ),
                        "Remove unauthorized fallback via `hermes config set fallback_providers '[]'`.".into(),
                        details,
                    ));
                } else if !allowed_pairs.contains(&(fb_prov.clone(), fb_model.clone())) {
                    let mut details = BTreeMap::new();
                    details.insert("index".into(), json!(idx));
                    details.insert("provider".into(), json!(fb_prov));
                    details.insert("model".into(), json!(fb_model));
                    findings.push(make_finding(
                        "POLICY_UNAPPROVED_FALLBACK",
                        "policy",
                        format!(
                            "fallback_providers[{idx}] ('{combined}') is not in birkin-policy.yaml fallback_providers.allowed."
                        ),
                        "Remove it (`hermes config set fallback_providers '[]'`) or obtain owner approval to add it to birkin-policy.yaml.".into(),
                        details,
                    ));
                }
            }
        }
        Some(other) => {
            findings.push(make_finding(
                "POLICY_FALLBACK_INVALID_TYPE",
                "policy",
                format!("'fallback_providers' must be a list, got {other}."),
                "Run `hermes config set fallback_providers '[]'`.".into(),
                BTreeMap::new(),
            ));
        }
    }

    // Layer 1D: Skill naming invariants (fail-closed)
    let skill_patterns = &policy.skills_invariants.forbidden_name_patterns;
    if let Some(sdir) = skills_dir {
        if sdir.is_dir() && !skill_patterns.is_empty() {
            let mut skill_files = Vec::new();
            for entry in WalkDir::new(sdir).into_iter().filter_map(Result::ok) {
                if entry.file_type().is_file() && entry.file_name() == "SKILL.md" {
                    let rel = entry.path().strip_prefix(sdir).unwrap_or(entry.path());
                    let has_dot = rel.components().any(|c| {
                        c.as_os_str()
                            .to_str()
                            .map(|s| s.starts_with('.'))
                            .unwrap_or(false)
                    });
                    if !has_dot {
                        skill_files.push(entry.into_path());
                    }
                }
            }
            skill_files.sort();
            for skill_md in skill_files {
                let dir_name = skill_md
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();
                let fm_name = extract_skill_frontmatter_name(&skill_md).unwrap_or_default();
                let mut candidates = vec![("directory", dir_name.clone())];
                if !fm_name.is_empty() && fm_name != dir_name {
                    candidates.push(("frontmatter", fm_name));
                }
                for (source, candidate) in candidates {
                    let matched: Vec<String> = skill_patterns
                        .iter()
                        .filter(|pat| fnmatch_ci(&candidate, pat))
                        .cloned()
                        .collect();
                    if !matched.is_empty() {
                        let mut details = BTreeMap::new();
                        details.insert("path".into(), json!(skill_md.to_string_lossy()));
                        details.insert("source".into(), json!(source));
                        details.insert("name".into(), json!(candidate));
                        details.insert("patterns".into(), json!(matched));
                        findings.push(make_finding(
                            "POLICY_FORBIDDEN_SKILL_NAME",
                            "policy",
                            format!(
                                "Skill {source} name '{candidate}' ({}) matches forbidden policy pattern(s): {matched:?}.",
                                skill_md.display()
                            ),
                            "Rename the skill directory and SKILL.md frontmatter `name:` to remove forbidden naming tokens (e.g. `-hub`, `software-process`).".into(),
                            details,
                        ));
                    }
                }
            }
        }
    }

    let exit_code = if findings.iter().any(|f| f.severity == "error") {
        EXIT_STATIC
    } else {
        EXIT_PASS
    };
    (exit_code, findings)
}
