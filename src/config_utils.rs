//! Configuration loading, secret hygiene, dotenv parsing, and provider lookup helpers.

use crate::models::RuntimePolicy;
use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;

const NON_SECRET_SUFFIXES: &[&str] = &[
    "_env",
    "_env_var",
    "_env_vars",
    "_tokens",
    "_token_limit",
    "_token_budget",
    "_token_count",
    "_token_threshold",
    "_count",
    "_limit",
    "_budget",
    "_threshold",
    "_window",
    "_mode",
    "_path",
    "_file",
    "_cmd",
    "_from",
];

const SECRET_EXACT_KEYS: &[&str] = &[
    "api_key",
    "apikey",
    "secret",
    "client_secret",
    "token",
    "access_token",
    "refresh_token",
    "auth_token",
    "bot_token",
    "bearer_token",
    "password",
    "passwd",
    "private_key",
    "signing_key",
    "webhook_secret",
];

const SECRET_SUFFIXES: &[&str] = &[
    "_api_key",
    "_apikey",
    "_secret",
    "_token",
    "_password",
    "_passwd",
    "_private_key",
    "_signing_key",
];

pub fn as_number(val: Option<&Value>) -> Option<f64> {
    match val {
        Some(Value::Number(n)) => n.as_f64(),
        _ => None,
    }
}

pub fn as_positive_int(val: Option<&Value>) -> Option<u64> {
    match val {
        Some(Value::Number(n)) => n.as_u64().filter(|&v| v > 0),
        _ => None,
    }
}

fn is_secret_key(key: &str) -> bool {
    let kl = key.trim().to_lowercase();
    if kl.is_empty() {
        return false;
    }
    if SECRET_EXACT_KEYS.contains(&kl.as_str()) {
        return true;
    }
    if NON_SECRET_SUFFIXES.iter().any(|s| kl.ends_with(s)) {
        return false;
    }
    SECRET_SUFFIXES.iter().any(|s| kl.ends_with(s))
}

fn is_truthy(val: &Value) -> bool {
    match val {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
    }
}

/// Recursively redact secret keys and normalize object key order for deterministic hashing.
pub fn canonicalize_json(val: &Value, strip_secrets: bool) -> Value {
    match val {
        Value::Object(map) => {
            let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
            for (k, v) in map {
                if strip_secrets && is_secret_key(k) {
                    let replacement = if is_truthy(v) { "<REDACTED>" } else { "" };
                    sorted.insert(k.clone(), Value::String(replacement.to_string()));
                } else {
                    sorted.insert(k.clone(), canonicalize_json(v, strip_secrets));
                }
            }
            let mut out = Map::new();
            for (k, v) in sorted {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(
            arr.iter()
                .map(|item| canonicalize_json(item, strip_secrets))
                .collect(),
        ),
        other => other.clone(),
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Deterministic SHA-256 fingerprint of config with secret values redacted.
pub fn canonical_config_sha256(cfg: &Value) -> String {
    let sanitized = canonicalize_json(cfg, true);
    let payload = serde_json::to_string(&sanitized).unwrap_or_default();
    sha256_hex(payload.as_bytes())
}

/// Load a YAML file into a JSON Value, requiring a top-level mapping.
pub fn load_yaml_mapping(path: &Path) -> Result<Value, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("Failed reading {}: {e}", path.display()))?;
    let yaml_val: serde_yaml::Value = serde_yaml::from_str(&text)
        .map_err(|e| format!("Invalid YAML in {}: {e}", path.display()))?;
    if !yaml_val.is_mapping() {
        return Err(format!("{} did not parse to a YAML mapping", path.display()));
    }
    serde_json::to_value(&yaml_val)
        .map_err(|e| format!("Failed converting YAML mapping in {}: {e}", path.display()))
}

/// Load a fail-closed Hermes `RuntimePolicy` from YAML.
pub fn load_policy(path: &Path) -> Result<RuntimePolicy, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("Failed reading {}: {e}", path.display()))?;
    let yaml_val: serde_yaml::Value = serde_yaml::from_str(&text)
        .map_err(|e| format!("Invalid YAML in {}: {e}", path.display()))?;
    if !yaml_val.is_mapping() {
        return Err(format!("{} did not parse to a YAML mapping", path.display()));
    }
    serde_yaml::from_value(yaml_val)
        .map_err(|e| format!("Policy schema validation failed in {}: {e}", path.display()))
}

fn unquote_dotenv_value(raw_val: &str) -> String {
    let val = raw_val.trim();
    if val.is_empty() {
        return String::new();
    }
    let first = val.chars().next().unwrap();
    if first == '"' || first == '\'' {
        let mut escaped = false;
        let mut out = String::new();
        for ch in val[1..].chars() {
            if first == '"' && ch == '\\' && !escaped {
                escaped = true;
                continue;
            }
            if ch == first && !escaped {
                return out;
            }
            out.push(ch);
            escaped = false;
        }
        return val[1..].to_string();
    }
    let chars: Vec<char> = val.chars().collect();
    for (idx, &ch) in chars.iter().enumerate() {
        if ch == '#' && idx > 0 && chars[idx - 1].is_whitespace() {
            return chars[..idx].iter().collect::<String>().trim().to_string();
        }
    }
    val.to_string()
}

fn parse_dotenv_entries(env_path: &Path) -> BTreeMap<String, String> {
    let mut entries = BTreeMap::new();
    let Ok(text) = fs::read_to_string(env_path) else {
        return entries;
    };
    let key_re = Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap();
    for raw_line in text.lines() {
        let mut line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("export ") {
            line = rest.trim_start();
            if !line.contains('=') {
                continue;
            }
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            if !key.is_empty() && key_re.is_match(key) {
                entries.insert(key.to_string(), unquote_dotenv_value(v));
            }
        }
    }
    entries
}

/// Return mapping of env key -> whether non-empty value is present. Never returns secret values.
pub fn parse_dotenv_keys(env_path: &Path) -> BTreeMap<String, bool> {
    parse_dotenv_entries(env_path)
        .into_iter()
        .map(|(k, v)| (k, !v.is_empty()))
        .collect()
}

/// Resolve secret from process env first, then `.env` file (last definition wins).
pub fn read_env_secret(env_path: Option<&Path>, key_name: &str) -> String {
    if key_name.is_empty() {
        return String::new();
    }
    if let Ok(val) = env::var(key_name) {
        let t = val.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    let Some(path) = env_path else {
        return String::new();
    };
    parse_dotenv_entries(path)
        .get(key_name)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub fn norm_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

pub fn get_str<'a>(obj: &'a Map<String, Value>, key: &str) -> &'a str {
    obj.get(key).and_then(Value::as_str).unwrap_or("").trim()
}

/// Find the active provider block under `providers.<name>` or `custom_providers[]`.
pub fn resolve_provider_block<'a>(
    cfg: &'a Map<String, Value>,
    active_provider: &str,
) -> Option<&'a Map<String, Value>> {
    if active_provider.is_empty() {
        return None;
    }
    if let Some(Value::Object(providers)) = cfg.get("providers") {
        if let Some(Value::Object(block)) = providers.get(active_provider) {
            return Some(block);
        }
    }
    if let Some(Value::Array(custom_providers)) = cfg.get("custom_providers") {
        for entry in custom_providers {
            if let Value::Object(map) = entry {
                let slug = {
                    let s = get_str(map, "slug");
                    if !s.is_empty() {
                        s
                    } else {
                        get_str(map, "name")
                    }
                };
                if slug == active_provider {
                    return Some(map);
                }
            }
        }
    }
    None
}

/// Normalize provider `models` (mapping or list) into `{model_id: metadata_map}`.
pub fn resolve_provider_models(
    provider_block: Option<&Map<String, Value>>,
) -> BTreeMap<String, Map<String, Value>> {
    let mut normalized = BTreeMap::new();
    let Some(block) = provider_block else {
        return normalized;
    };
    match block.get("models") {
        Some(Value::Object(map)) => {
            for (mid, meta) in map {
                let id = mid.trim();
                if id.is_empty() {
                    continue;
                }
                let meta_map = meta.as_object().cloned().unwrap_or_default();
                normalized.insert(id.to_string(), meta_map);
            }
        }
        Some(Value::Array(arr)) => {
            for item in arr {
                match item {
                    Value::String(s) => {
                        let id = s.trim();
                        if !id.is_empty() {
                            normalized.insert(id.to_string(), Map::new());
                        }
                    }
                    Value::Object(map) => {
                        let id = ["id", "model", "name"]
                            .iter()
                            .map(|k| get_str(map, k))
                            .find(|s| !s.is_empty())
                            .unwrap_or("");
                        if !id.is_empty() {
                            normalized.insert(id.to_string(), map.clone());
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    normalized
}

pub fn extract_context_length(
    models_map: &BTreeMap<String, Map<String, Value>>,
    model_id: &str,
) -> Option<u64> {
    models_map
        .get(model_id)
        .and_then(|meta| as_positive_int(meta.get("context_length")))
}

pub fn resolve_key_env(
    model_cfg: &Map<String, Value>,
    provider_block: Option<&Map<String, Value>>,
) -> String {
    for key in ["key_env", "api_key_env"] {
        let v = get_str(model_cfg, key);
        if !v.is_empty() {
            return v.to_string();
        }
    }
    if let Some(pb) = provider_block {
        for key in ["key_env", "api_key_env"] {
            let v = get_str(pb, key);
            if !v.is_empty() {
                return v.to_string();
            }
        }
    }
    String::new()
}

pub fn resolve_api_key(
    model_cfg: &Map<String, Value>,
    provider_block: Option<&Map<String, Value>>,
    env_path: Option<&Path>,
) -> String {
    let key_env = resolve_key_env(model_cfg, provider_block);
    if !key_env.is_empty() {
        let secret = read_env_secret(env_path, &key_env);
        if !secret.is_empty() {
            return secret;
        }
    }
    let candidates = [
        get_str(model_cfg, "api_key"),
        provider_block.map(|b| get_str(b, "api_key")).unwrap_or(""),
    ];
    for raw in candidates {
        if raw.is_empty() {
            continue;
        }
        if raw.starts_with("${") && raw.ends_with('}') && raw.len() > 3 {
            let env_name = raw[2..raw.len() - 1].trim();
            return read_env_secret(env_path, env_name);
        }
        return raw.to_string();
    }
    String::new()
}
