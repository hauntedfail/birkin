//! Layer 2: Live provider `/v1/models` contract and optional 1-token micro-probe verification.

use crate::config_utils::{
    as_positive_int, extract_context_length, get_str, norm_url, resolve_api_key,
    resolve_provider_block, resolve_provider_models, sha256_hex,
};
use crate::constants::{EXIT_LIVE_CONTRACT, EXIT_LIVE_TRANSIENT, EXIT_PASS};
use crate::models::{Finding, RuntimePolicy};
use chrono::Utc;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

pub(crate) fn is_transient_http(status: u16) -> bool {
    status == 429 || (500..=599).contains(&status)
}

pub(crate) fn advertised_context_length(mobj: &Map<String, Value>) -> Option<u64> {
    as_positive_int(mobj.get("context_length"))
        .or_else(|| as_positive_int(mobj.get("max_model_len")))
}

pub(crate) struct FetchedCatalog {
    pub endpoint: String,
    pub http_status: u16,
    pub catalog: BTreeMap<String, Map<String, Value>>,
    pub catalog_sha256: String,
}

pub(crate) struct CatalogFetchError {
    pub exit_code: i32,
    pub endpoint: String,
    pub http_status: Option<u16>,
    pub finding: Finding,
}

pub(crate) fn fetch_models_catalog(
    base_url: &str,
    api_key: &str,
    timeout_secs: f64,
) -> Result<FetchedCatalog, Box<CatalogFetchError>> {
    let models_url = format!("{base_url}/models");
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs_f64(timeout_secs.max(0.5)))
        .build();

    let mut req = agent.get(&models_url);
    if !api_key.is_empty() {
        req = req.set("Authorization", &format!("Bearer {api_key}"));
    }

    let (status, body_text) = match req.call() {
        Ok(resp) => {
            let st = resp.status();
            let txt = resp.into_string().unwrap_or_default();
            (st, txt)
        }
        Err(ureq::Error::Status(code, resp)) => {
            let txt = resp.into_string().unwrap_or_default();
            (code, txt)
        }
        Err(ureq::Error::Transport(err)) => {
            return Err(Box::new(CatalogFetchError {
                exit_code: EXIT_LIVE_TRANSIENT,
                endpoint: models_url.clone(),
                http_status: None,
                finding: live_finding(
                    "LIVE_NETWORK_UNAVAILABLE",
                    format!("HTTP transport error reaching {models_url}: {err}"),
                    "Check network connectivity and upstream gateway availability.".into(),
                    BTreeMap::new(),
                ),
            }));
        }
    };

    if is_transient_http(status) {
        let mut details = BTreeMap::new();
        details.insert("status_code".into(), json!(status));
        return Err(Box::new(CatalogFetchError {
            exit_code: EXIT_LIVE_TRANSIENT,
            endpoint: models_url.clone(),
            http_status: Some(status),
            finding: live_finding(
                "LIVE_TRANSIENT_HTTP",
                format!("GET {models_url} returned transient HTTP {status}."),
                "Retry later; do not treat transient outage as config corruption.".into(),
                details,
            ),
        }));
    }
    if status != 200 {
        let mut details = BTreeMap::new();
        details.insert("status_code".into(), json!(status));
        return Err(Box::new(CatalogFetchError {
            exit_code: EXIT_LIVE_CONTRACT,
            endpoint: models_url.clone(),
            http_status: Some(status),
            finding: live_finding(
                "LIVE_CATALOG_HTTP_ERROR",
                format!("GET {models_url} returned HTTP {status}."),
                "Verify base_url and API key credentials.".into(),
                details,
            ),
        }));
    }

    let body: Value = match serde_json::from_str(&body_text) {
        Ok(v) => v,
        Err(err) => {
            return Err(Box::new(CatalogFetchError {
                exit_code: EXIT_LIVE_CONTRACT,
                endpoint: models_url.clone(),
                http_status: Some(status),
                finding: live_finding(
                    "LIVE_CATALOG_INVALID_JSON",
                    format!("GET {models_url} returned invalid JSON: {err}"),
                    "Verify endpoint serves OpenAI-compatible JSON.".into(),
                    BTreeMap::new(),
                ),
            }));
        }
    };

    let Some(data_arr) = body.get("data").and_then(Value::as_array) else {
        return Err(Box::new(CatalogFetchError {
            exit_code: EXIT_LIVE_CONTRACT,
            endpoint: models_url.clone(),
            http_status: Some(status),
            finding: live_finding(
                "LIVE_CATALOG_SCHEMA_INVALID",
                format!("GET {models_url} response missing 'data' list."),
                "Verify upstream endpoint implements OpenAI /v1/models schema.".into(),
                BTreeMap::new(),
            ),
        }));
    };

    let mut catalog: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    for item in data_arr {
        if let Some(obj) = item.as_object() {
            let id = get_str(obj, "id");
            if !id.is_empty() {
                catalog.insert(id.to_string(), obj.clone());
            }
        }
    }
    let catalog_ids: Vec<&String> = catalog.keys().collect();
    let hash_payload = serde_json::to_string(&catalog_ids).unwrap_or_default();
    let catalog_sha256 = sha256_hex(hash_payload.as_bytes());

    Ok(FetchedCatalog {
        endpoint: models_url,
        http_status: status,
        catalog,
        catalog_sha256,
    })
}

fn collect_probe_models(
    cfg: &Map<String, Value>,
    active_provider: &str,
    default_model: &str,
) -> Vec<String> {
    let mut models = vec![default_model.to_string()];
    if let Some(aux_cfg) = cfg.get("auxiliary").and_then(Value::as_object) {
        for role_val in aux_cfg.values() {
            let Some(role_cfg) = role_val.as_object() else {
                continue;
            };
            let aux_model = get_str(role_cfg, "model");
            let aux_provider = {
                let p = get_str(role_cfg, "provider");
                if p.is_empty() { "auto" } else { p }
            };
            if !aux_model.is_empty()
                && (aux_provider == "auto" || aux_provider == active_provider)
                && !models.iter().any(|m| m == aux_model)
            {
                models.push(aux_model.to_string());
            }
        }
    }
    models
}

fn live_finding(
    rule: &str,
    message: String,
    remediation: String,
    details: BTreeMap<String, Value>,
) -> Finding {
    Finding {
        rule: rule.to_string(),
        severity: "error".to_string(),
        layer: "live".to_string(),
        message,
        remediation,
        details,
    }
}

pub fn verify_live(
    cfg_val: &Value,
    policy: &RuntimePolicy,
    env_path: Option<&Path>,
    probe: bool,
    timeout_override: Option<f64>,
) -> (i32, Vec<Finding>, Map<String, Value>) {
    let mut findings = Vec::new();
    let mut meta = Map::new();
    meta.insert("checked_at".into(), json!(Utc::now().to_rfc3339()));
    meta.insert("endpoint".into(), Value::Null);
    meta.insert("catalog_count".into(), json!(0));
    meta.insert("probe_enabled".into(), json!(probe));

    let empty_map = Map::new();
    let cfg = cfg_val.as_object().unwrap_or(&empty_map);
    let model_cfg = cfg
        .get("model")
        .and_then(Value::as_object)
        .unwrap_or(&empty_map);
    let active_provider = get_str(model_cfg, "provider");
    let default_model = get_str(model_cfg, "default");
    let provider_block = resolve_provider_block(cfg, active_provider);

    let base_url_raw = {
        let m = get_str(model_cfg, "base_url");
        if !m.is_empty() {
            m
        } else {
            provider_block.map(|b| get_str(b, "base_url")).unwrap_or("")
        }
    };
    let base_url = norm_url(base_url_raw);
    let api_key = resolve_api_key(model_cfg, provider_block, env_path);

    if base_url.is_empty() {
        findings.push(live_finding(
            "LIVE_BASE_URL_MISSING",
            "Cannot run live contract check: no base_url configured.".into(),
            "Configure model.base_url or providers.<active>.base_url.".into(),
            BTreeMap::new(),
        ));
        return (EXIT_LIVE_CONTRACT, findings, meta);
    }

    let timeout_secs = timeout_override.unwrap_or(policy.live_contract.timeout_seconds);
    let fetched = match fetch_models_catalog(&base_url, &api_key, timeout_secs) {
        Ok(f) => f,
        Err(err) => {
            meta.insert("endpoint".into(), json!(err.endpoint));
            if let Some(st) = err.http_status {
                meta.insert("http_status".into(), json!(st));
            }
            findings.push(err.finding);
            return (err.exit_code, findings, meta);
        }
    };

    let models_url = fetched.endpoint;
    meta.insert("endpoint".into(), json!(models_url));
    meta.insert("http_status".into(), json!(fetched.http_status));
    let catalog = fetched.catalog;
    meta.insert("catalog_count".into(), json!(catalog.len()));
    meta.insert("catalog_sha256".into(), json!(fetched.catalog_sha256));
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs_f64(timeout_secs.max(0.5)))
        .build();

    let provider_models = resolve_provider_models(provider_block);

    // 1. Default model in catalog
    if !default_model.is_empty() && !catalog.contains_key(default_model) {
        let mut details = BTreeMap::new();
        details.insert("model".into(), json!(default_model));
        findings.push(live_finding(
            "LIVE_DEFAULT_MODEL_NOT_IN_CATALOG",
            format!("model.default='{default_model}' is not advertised by {models_url}."),
            "Update model.default to a model present in /v1/models.".into(),
            details,
        ));
    }

    // 2. Auxiliary models in catalog
    if let Some(aux_cfg) = cfg.get("auxiliary").and_then(Value::as_object) {
        for (role, role_val) in aux_cfg {
            let Some(role_cfg) = role_val.as_object() else {
                continue;
            };
            let aux_model = get_str(role_cfg, "model");
            let aux_provider = {
                let p = get_str(role_cfg, "provider");
                if p.is_empty() { "auto" } else { p }
            };
            if !aux_model.is_empty()
                && (aux_provider == "auto" || aux_provider == active_provider)
                && !catalog.contains_key(aux_model)
            {
                let mut details = BTreeMap::new();
                details.insert("role".into(), json!(role));
                details.insert("model".into(), json!(aux_model));
                findings.push(live_finding(
                    "LIVE_AUX_MODEL_NOT_IN_CATALOG",
                    format!(
                        "auxiliary.{role}.model='{aux_model}' is not served by {models_url} (causes 404 fallback stalls)."
                    ),
                    format!(
                        "Run `hermes config set auxiliary.{role}.model ''` or choose a model from /v1/models."
                    ),
                    details,
                ));
            }
        }
    }

    // 3. Context length coverage
    if policy.live_contract.require_catalog_context_length_coverage {
        for (mid, mobj) in &catalog {
            let Some(adv) = advertised_context_length(mobj) else {
                continue;
            };
            match extract_context_length(&provider_models, mid) {
                None => {
                    let mut details = BTreeMap::new();
                    details.insert("model".into(), json!(mid));
                    details.insert("advertised_context_length".into(), json!(adv));
                    findings.push(live_finding(
                        "LIVE_MODEL_CONTEXT_UNDECLARED",
                        format!(
                            "Provider model '{mid}' advertises context_length={adv}, but is missing from providers.{active_provider}.models (switching to it triggers 256k probe-down & skill pruning)."
                        ),
                        format!(
                            "Run `hermes config set providers.{active_provider}.models.{mid}.context_length {adv}`."
                        ),
                        details,
                    ));
                }
                Some(configured) if configured > adv => {
                    let mut details = BTreeMap::new();
                    details.insert("model".into(), json!(mid));
                    details.insert("configured_context_length".into(), json!(configured));
                    details.insert("advertised_context_length".into(), json!(adv));
                    findings.push(live_finding(
                        "LIVE_CONTEXT_EXCEEDS_ADVERTISED",
                        format!(
                            "providers.{active_provider}.models.{mid}.context_length={configured} exceeds advertised limit {adv}."
                        ),
                        format!(
                            "Run `hermes config set providers.{active_provider}.models.{mid}.context_length {adv}`."
                        ),
                        details,
                    ));
                }
                _ => {}
            }
        }
    }

    // 4. Optional Tier B micro-probe
    if probe && !default_model.is_empty() {
        let comp_url = format!("{base_url}/chat/completions");
        let probe_models = collect_probe_models(cfg, active_provider, default_model);
        meta.insert("probed_models".into(), json!(probe_models));
        for pm in &probe_models {
            let mut preq = agent
                .post(&comp_url)
                .set("Content-Type", "application/json");
            if !api_key.is_empty() {
                preq = preq.set("Authorization", &format!("Bearer {api_key}"));
            }
            let payload = json!({
                "model": pm,
                "max_tokens": 1,
                "temperature": 0,
                "messages": [{"role": "user", "content": "ping"}],
            });
            match preq.send_json(payload) {
                Ok(resp) => {
                    let txt = resp.into_string().unwrap_or_default();
                    match serde_json::from_str::<Value>(&txt) {
                        Ok(Value::Object(obj)) if !obj.contains_key("error") => {}
                        Ok(_) => {
                            let mut details = BTreeMap::new();
                            details.insert("model".into(), json!(pm));
                            findings.push(live_finding(
                                "LIVE_PROBE_CONTRACT_ERROR",
                                format!("Micro-probe for '{pm}' returned HTTP 200 with invalid/error JSON body."),
                                "Inspect upstream gateway response for chat/completions.".into(),
                                details,
                            ));
                        }
                        Err(err) => {
                            let mut details = BTreeMap::new();
                            details.insert("model".into(), json!(pm));
                            findings.push(live_finding(
                                "LIVE_PROBE_INVALID_JSON",
                                format!("Micro-probe for '{pm}' returned HTTP 200 non-JSON payload: {err}"),
                                "Verify upstream endpoint is an OpenAI-compatible API, not a proxy error page.".into(),
                                details,
                            ));
                        }
                    }
                }
                Err(ureq::Error::Status(code, _)) if is_transient_http(code) => {
                    let mut details = BTreeMap::new();
                    details.insert("model".into(), json!(pm));
                    details.insert("status_code".into(), json!(code));
                    findings.push(live_finding(
                        "LIVE_PROBE_TRANSIENT",
                        format!("Micro-probe for '{pm}' returned transient HTTP {code}."),
                        "Retry later; upstream rate-limited or transiently unavailable.".into(),
                        details,
                    ));
                }
                Err(ureq::Error::Status(code, _)) => {
                    let mut details = BTreeMap::new();
                    details.insert("model".into(), json!(pm));
                    details.insert("status_code".into(), json!(code));
                    findings.push(live_finding(
                        "LIVE_PROBE_CONTRACT_ERROR",
                        format!("Micro-probe for '{pm}' failed with HTTP {code}."),
                        "Verify model routing on upstream gateway.".into(),
                        details,
                    ));
                }
                Err(ureq::Error::Transport(err)) => {
                    findings.push(live_finding(
                        "LIVE_NETWORK_UNAVAILABLE",
                        format!("HTTP transport error probing {comp_url}: {err}"),
                        "Check network connectivity and upstream gateway availability.".into(),
                        BTreeMap::new(),
                    ));
                    return (EXIT_LIVE_TRANSIENT, findings, meta);
                }
            }
        }
    }

    let has_contract = findings
        .iter()
        .any(|f| f.severity == "error" && f.rule.starts_with("LIVE_") && !f.rule.contains("TRANSIENT"));
    let has_transient = findings
        .iter()
        .any(|f| f.severity == "error" && f.rule.contains("TRANSIENT"));
    let exit_code = if has_contract {
        EXIT_LIVE_CONTRACT
    } else if has_transient {
        EXIT_LIVE_TRANSIENT
    } else {
        EXIT_PASS
    };
    (exit_code, findings, meta)
}
