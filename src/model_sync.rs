//! Native provider `/models` catalog synchronization for Hermes Agent `config.yaml`.
//!
//! Layer 3 (`engines`): compares a provider's live `/models` catalog against
//! `providers.<name>.models` (or `custom_providers[]`) in `~/.hermes/config.yaml`,
//! supporting read-only `--check` and atomic fail-closed `--apply` with verified 0600
//! backups and automatic rollback on `verify_live` failure. Never restarts the gateway.

use crate::config_utils::{
    extract_context_length, get_str, load_yaml_mapping, norm_url, resolve_api_key,
    resolve_provider_block, resolve_provider_models, sha256_hex,
};
use crate::constants::{EXIT_LIVE_CONTRACT, EXIT_PASS, EXIT_TOOL_ERROR};
use crate::live::{advertised_context_length, fetch_models_catalog, verify_live};
use crate::models::{Finding, RuntimePolicy};
use chrono::Utc;
use serde::Serialize;
use serde_json::{json, Map, Value};
use serde_yaml::{Mapping as YamlMapping, Number as YamlNumber, Value as YamlValue};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tempfile::Builder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelSyncMode { Check, Apply }

impl ModelSyncMode {
    pub fn as_str(self) -> &'static str {
        match self { Self::Check => "check", Self::Apply => "apply" }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ModelContextUpdate {
    pub model: String,
    pub previous_context_length: Option<u64>,
    pub context_length: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelSyncReport {
    pub command: String,
    pub mode: String,
    pub status: String,
    pub exit_code: i32,
    pub provider: String,
    pub endpoint: Option<String>,
    pub models: BTreeMap<String, u64>,
    pub catalog_sha256: Option<String>,
    pub full_sha256: Option<String>,
    pub added: BTreeMap<String, u64>,
    pub updated: Vec<ModelContextUpdate>,
    pub removed: Vec<String>,
    pub protected_skipped: Vec<String>,
    pub backup_path: Option<String>,
    pub birkin_live_exit: Option<i32>,
    pub findings: Vec<Finding>,
}

fn sync_finding(rule: &str, message: String, remediation: String, details: BTreeMap<String, Value>) -> Finding {
    Finding { rule: rule.to_string(), severity: "error".to_string(), layer: "model_sync".to_string(), message, remediation, details }
}

fn base_report(mode: ModelSyncMode, provider: &str) -> ModelSyncReport {
    ModelSyncReport {
        command: "sync-models".to_string(), mode: mode.as_str().to_string(),
        status: "FAIL".to_string(), exit_code: EXIT_LIVE_CONTRACT,
        provider: provider.to_string(), endpoint: None, models: BTreeMap::new(),
        catalog_sha256: None, full_sha256: None, added: BTreeMap::new(),
        updated: Vec::new(), removed: Vec::new(), protected_skipped: Vec::new(),
        backup_path: None, birkin_live_exit: None, findings: Vec::new(),
    }
}

fn abort_with(mut report: ModelSyncReport, status: &str, exit_code: i32, rule: &str, msg: String, rem: String) -> ModelSyncReport {
    report.status = status.to_string();
    report.exit_code = exit_code;
    report.findings.push(sync_finding(rule, msg, rem, BTreeMap::new()));
    report
}

fn collect_referenced_models(cfg: &Map<String, Value>, target_provider: &str) -> BTreeSet<String> {
    let mut protected = BTreeSet::new();
    let empty_map = Map::new();
    let model_cfg = cfg.get("model").and_then(Value::as_object).unwrap_or(&empty_map);
    let active_provider = get_str(model_cfg, "provider");
    let default_model = get_str(model_cfg, "default");
    if !default_model.is_empty() && (active_provider.is_empty() || active_provider == target_provider) {
        protected.insert(default_model.to_string());
    }

    let prefix = format!("{target_provider}/");
    if let Some(Value::Array(fb_list)) = cfg.get("fallback_providers") {
        for item in fb_list {
            let (fb_prov, fb_model) = match item {
                Value::Object(m) => (get_str(m, "provider"), get_str(m, "model")),
                Value::String(s) => ("", s.trim()),
                _ => continue,
            };
            if !fb_model.is_empty()
                && (fb_prov.is_empty() || fb_prov == "auto" || fb_prov == target_provider)
            {
                protected.insert(fb_model.to_string());
                if let Some(stripped) = fb_model.strip_prefix(&prefix) {
                    protected.insert(stripped.to_string());
                }
            }
        }
    }

    if let Some(Value::Object(aux_map)) = cfg.get("auxiliary") {
        for role_val in aux_map.values() {
            let Some(role_cfg) = role_val.as_object() else { continue };
            let aux_model = get_str(role_cfg, "model");
            if aux_model.is_empty() { continue; }
            let aux_provider = match get_str(role_cfg, "provider") {
                "" => "auto",
                p => p,
            };
            if aux_provider == "auto" || aux_provider == target_provider {
                protected.insert(aux_model.to_string());
            }
        }
    }
    protected
}

fn yaml_get_str<'a>(map: &'a YamlMapping, key: &str) -> &'a str {
    map.get(YamlValue::String(key.to_string()))
        .and_then(YamlValue::as_str)
        .unwrap_or("")
        .trim()
}

fn locate_provider_block_mut<'a>(
    root: &'a mut YamlMapping,
    provider: &str,
) -> Option<&'a mut YamlMapping> {
    let provs_key = YamlValue::String("providers".to_string());
    let prov_key = YamlValue::String(provider.to_string());
    let in_providers = root
        .get(&provs_key)
        .and_then(YamlValue::as_mapping)
        .and_then(|p| p.get(&prov_key))
        .and_then(YamlValue::as_mapping)
        .is_some();
    if in_providers {
        return root
            .get_mut(&provs_key)
            .and_then(YamlValue::as_mapping_mut)
            .and_then(|p| p.get_mut(&prov_key))
            .and_then(YamlValue::as_mapping_mut);
    }

    let cp_key = YamlValue::String("custom_providers".to_string());
    if let Some(YamlValue::Sequence(list)) = root.get_mut(&cp_key) {
        for entry in list.iter_mut() {
            if let YamlValue::Mapping(map) = entry {
                let slug = match yaml_get_str(map, "slug") {
                    "" => yaml_get_str(map, "name"),
                    s => s,
                };
                if slug == provider {
                    return Some(map);
                }
            }
        }
    }
    None
}

fn normalize_models_yaml_mapping(existing: Option<YamlValue>) -> Result<YamlMapping, String> {
    match existing {
        None | Some(YamlValue::Null) => Ok(YamlMapping::new()),
        Some(YamlValue::Mapping(m)) => Ok(m),
        Some(YamlValue::Sequence(seq)) => {
            let mut out = YamlMapping::new();
            for item in seq {
                match item {
                    YamlValue::String(s) if !s.trim().is_empty() => {
                        out.insert(YamlValue::String(s.trim().to_string()), YamlValue::Mapping(YamlMapping::new()));
                    }
                    YamlValue::Mapping(m) => {
                        let id = ["id", "model", "name"].iter().map(|k| yaml_get_str(&m, k)).find(|s| !s.is_empty()).unwrap_or("").to_string();
                        if !id.is_empty() {
                            out.insert(YamlValue::String(id), YamlValue::Mapping(m));
                        }
                    }
                    _ => {}
                }
            }
            Ok(out)
        }
        Some(_) => Err("Provider 'models' field must be a YAML mapping or sequence.".to_string()),
    }
}

fn apply_diff_to_yaml(
    yaml_doc: &mut YamlValue,
    provider: &str,
    added: &BTreeMap<String, u64>,
    updated: &[ModelContextUpdate],
    removed: &[String],
) -> Result<String, String> {
    let root = yaml_doc.as_mapping_mut().ok_or_else(|| "Top-level config YAML is not a mapping.".to_string())?;
    let block = locate_provider_block_mut(root, provider)
        .ok_or_else(|| format!("Provider block '{provider}' not found in config YAML."))?;

    let models_key = YamlValue::String("models".to_string());
    let mut models_map = normalize_models_yaml_mapping(block.remove(&models_key))?;
    let ctx_key = YamlValue::String("context_length".to_string());

    for (mid, &ctx) in added {
        let mut entry = YamlMapping::new();
        entry.insert(ctx_key.clone(), YamlValue::Number(YamlNumber::from(ctx)));
        models_map.insert(YamlValue::String(mid.clone()), YamlValue::Mapping(entry));
    }
    for upd in updated {
        let key = YamlValue::String(upd.model.clone());
        let val = YamlValue::Number(YamlNumber::from(upd.context_length));
        if let Some(YamlValue::Mapping(entry)) = models_map.get_mut(&key) {
            entry.insert(ctx_key.clone(), val);
        } else {
            let mut entry = YamlMapping::new();
            entry.insert(ctx_key.clone(), val);
            models_map.insert(key, YamlValue::Mapping(entry));
        }
    }
    for rem in removed {
        models_map.remove(YamlValue::String(rem.clone()));
    }
    block.insert(models_key, YamlValue::Mapping(models_map));

    let mut rendered = serde_yaml::to_string(yaml_doc)
        .map_err(|e| format!("Failed serializing updated YAML: {e}"))?;
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    let reparsed: YamlValue = serde_yaml::from_str(&rendered)
        .map_err(|e| format!("Rendered YAML failed round-trip parse: {e}"))?;
    if !reparsed.is_mapping() {
        return Err("Rendered YAML did not round-trip to a mapping.".to_string());
    }
    Ok(rendered)
}

#[cfg(unix)]
fn enforce_mode_0600_file(file: &fs::File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed setting 0600 permissions: {e}"))
}
#[cfg(not(unix))]
fn enforce_mode_0600_file(_file: &fs::File) -> Result<(), String> { Ok(()) }

#[cfg(unix)]
fn verify_mode_0600_path(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|e| format!("Failed reading metadata for {}: {e}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err(format!("Backup {} has mode {:04o}; expected 0600.", path.display(), mode));
    }
    Ok(())
}
#[cfg(not(unix))]
fn verify_mode_0600_path(_path: &Path) -> Result<(), String> { Ok(()) }

fn create_verified_backup(cfg_path: &Path, orig_bytes: &[u8]) -> Result<PathBuf, String> {
    let parent = cfg_path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let fname = cfg_path.file_name().and_then(|s| s.to_str()).unwrap_or("config.yaml");
    let ts = Utc::now().format("%Y%m%dT%H%M%S%.3fZ").to_string();
    let orig_sha = sha256_hex(orig_bytes);

    for attempt in 0..100u32 {
        let candidate = if attempt == 0 {
            parent.join(format!("{fname}.bak.{ts}"))
        } else {
            parent.join(format!("{fname}.bak.{ts}.{attempt}"))
        };
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = match opts.open(&candidate) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("Failed creating backup {}: {e}", candidate.display())),
        };
        let write_res = enforce_mode_0600_file(&file)
            .and_then(|_| file.write_all(orig_bytes).map_err(|e| format!("Failed writing backup: {e}")))
            .and_then(|_| file.sync_all().map_err(|e| format!("Failed syncing backup: {e}")));
        drop(file);
        if let Err(err) = write_res {
            let _ = fs::remove_file(&candidate);
            return Err(err);
        }
        let verify_res = verify_mode_0600_path(&candidate).and_then(|_| {
            let read_back = fs::read(&candidate).map_err(|e| format!("Failed verifying backup: {e}"))?;
            if sha256_hex(&read_back) != orig_sha {
                return Err(format!("Backup {} failed SHA-256 verification.", candidate.display()));
            }
            Ok(())
        });
        if let Err(err) = verify_res {
            let _ = fs::remove_file(&candidate);
            return Err(err);
        }
        return Ok(candidate);
    }
    Err("Exhausted backup filename attempts.".to_string())
}

fn write_file_atomic_0600(target_path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = target_path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let mut tmp = Builder::new()
        .prefix(".birkin-model-sync-")
        .tempfile_in(parent)
        .map_err(|e| format!("Failed creating temp file in {}: {e}", parent.display()))?;
    enforce_mode_0600_file(tmp.as_file())?;
    tmp.write_all(bytes)
        .and_then(|_| tmp.as_file().sync_all())
        .map_err(|e| format!("Failed writing temp config file: {e}"))?;
    tmp.persist(target_path)
        .map_err(|e| format!("Failed atomically replacing {}: {}", target_path.display(), e.error))?;
    Ok(())
}

fn record_drift_findings(report: &mut ModelSyncReport, provider: &str) {
    for (mid, &ctx) in &report.added {
        let mut details = BTreeMap::new();
        details.insert("model".into(), json!(mid));
        details.insert("advertised_context_length".into(), json!(ctx));
        report.findings.push(sync_finding(
            "SYNC_MODEL_MISSING",
            format!("Provider '{provider}' model '{mid}' (context_length={ctx}) is missing from config."),
            format!("Run `birkin hermes sync-models --provider {provider} --apply`."),
            details,
        ));
    }
    for upd in &report.updated {
        let mut details = BTreeMap::new();
        details.insert("model".into(), json!(upd.model));
        details.insert("previous_context_length".into(), json!(upd.previous_context_length));
        details.insert("advertised_context_length".into(), json!(upd.context_length));
        report.findings.push(sync_finding(
            "SYNC_CONTEXT_LENGTH_DRIFT",
            format!(
                "Provider '{provider}' model '{}' context_length={:?} differs from advertised {}.",
                upd.model, upd.previous_context_length, upd.context_length
            ),
            format!("Run `birkin hermes sync-models --provider {provider} --apply`."),
            details,
        ));
    }
    for rem in &report.removed {
        let mut details = BTreeMap::new();
        details.insert("model".into(), json!(rem));
        report.findings.push(sync_finding(
            "SYNC_STALE_MODEL_PRUNABLE",
            format!("Provider '{provider}' model '{rem}' is absent from upstream /models and eligible for --prune."),
            format!("Run `birkin hermes sync-models --provider {provider} --apply --prune`."),
            details,
        ));
    }
}

/// Synchronize or check a Hermes provider's `models` map against live `/models`.
pub fn sync_provider_models(
    cfg_path: &Path,
    env_path: Option<&Path>,
    policy: &RuntimePolicy,
    provider_opt: Option<&str>,
    mode: ModelSyncMode,
    prune: bool,
    timeout_override: Option<f64>,
) -> ModelSyncReport {
    let mut report = base_report(mode, provider_opt.unwrap_or("").trim());

    let orig_bytes = match fs::read(cfg_path) {
        Ok(b) => b,
        Err(e) => return abort_with(report, "ERROR", EXIT_TOOL_ERROR, "SYNC_CONFIG_READ_ERROR", format!("Failed reading {}: {e}", cfg_path.display()), "Verify --config / --home points to a readable Hermes config.yaml.".into()),
    };
    let orig_text = match String::from_utf8(orig_bytes.clone()) {
        Ok(s) => s,
        Err(e) => return abort_with(report, "ERROR", EXIT_TOOL_ERROR, "SYNC_CONFIG_UTF8_ERROR", format!("Config {} is not valid UTF-8: {e}", cfg_path.display()), "Fix invalid UTF-8 bytes in config.yaml.".into()),
    };
    let mut yaml_doc: YamlValue = match serde_yaml::from_str::<YamlValue>(&orig_text) {
        Ok(v) if v.is_mapping() => v,
        Ok(_) => return abort_with(report, "ERROR", EXIT_TOOL_ERROR, "SYNC_CONFIG_SCHEMA_ERROR", format!("{} did not parse to a YAML mapping.", cfg_path.display()), "Ensure Hermes config.yaml has a top-level YAML mapping.".into()),
        Err(e) => return abort_with(report, "ERROR", EXIT_TOOL_ERROR, "SYNC_CONFIG_PARSE_ERROR", format!("Invalid YAML in {}: {e}", cfg_path.display()), "Fix YAML syntax errors in config.yaml.".into()),
    };
    let cfg_val: Value = match serde_json::to_value(&yaml_doc) {
        Ok(v) => v,
        Err(e) => return abort_with(report, "ERROR", EXIT_TOOL_ERROR, "SYNC_CONFIG_CONVERT_ERROR", format!("Failed converting YAML in {}: {e}", cfg_path.display()), "Ensure config.yaml uses standard YAML mapping keys.".into()),
    };

    let empty_map = Map::new();
    let cfg = cfg_val.as_object().unwrap_or(&empty_map);
    let model_cfg = cfg.get("model").and_then(Value::as_object).unwrap_or(&empty_map);
    let active_provider = get_str(model_cfg, "provider");
    let target_provider = provider_opt.map(str::trim).filter(|s| !s.is_empty()).unwrap_or(active_provider);
    report.provider = target_provider.to_string();

    if target_provider.is_empty() {
        return abort_with(report, "FAIL", EXIT_LIVE_CONTRACT, "SYNC_PROVIDER_MISSING", "Cannot sync models: no provider specified and model.provider is empty.".into(), "Pass --provider <name> or configure model.provider in config.yaml.".into());
    }
    let Some(provider_block) = resolve_provider_block(cfg, target_provider) else {
        return abort_with(report, "FAIL", EXIT_LIVE_CONTRACT, "SYNC_PROVIDER_NOT_FOUND", format!("Provider '{target_provider}' was not found under providers or custom_providers."), format!("Configure providers.{target_provider} in config.yaml or check --provider."));
    };

    let eff_model_cfg = if target_provider == active_provider { model_cfg } else { &empty_map };
    let base_url_raw = match get_str(eff_model_cfg, "base_url") {
        "" => get_str(provider_block, "base_url"),
        m => m,
    };
    let base_url = norm_url(base_url_raw);
    if base_url.is_empty() {
        return abort_with(report, "FAIL", EXIT_LIVE_CONTRACT, "LIVE_BASE_URL_MISSING", format!("Cannot sync provider '{target_provider}': no base_url configured."), format!("Configure providers.{target_provider}.base_url in config.yaml."));
    }

    let api_key = resolve_api_key(eff_model_cfg, Some(provider_block), env_path);
    let timeout_secs = timeout_override.unwrap_or(policy.live_contract.timeout_seconds);
    let fetched = match fetch_models_catalog(&base_url, &api_key, timeout_secs) {
        Ok(f) => f,
        Err(err) => {
            report.endpoint = Some(err.endpoint);
            report.exit_code = err.exit_code;
            report.status = "FAIL".to_string();
            report.findings.push(err.finding);
            return report;
        }
    };

    report.endpoint = Some(fetched.endpoint.clone());
    report.catalog_sha256 = Some(fetched.catalog_sha256.clone());
    if fetched.catalog.is_empty() {
        return abort_with(report, "FAIL", EXIT_LIVE_CONTRACT, "SYNC_CATALOG_EMPTY", format!("GET {} returned an empty model catalog.", fetched.endpoint), "Verify upstream /models endpoint before syncing.".into());
    }

    let mut advertised_models = BTreeMap::new();
    let mut full_map: BTreeMap<&String, Option<u64>> = BTreeMap::new();
    for (mid, mobj) in &fetched.catalog {
        let adv = advertised_context_length(mobj);
        full_map.insert(mid, adv);
        if let Some(ctx) = adv {
            advertised_models.insert(mid.clone(), ctx);
        }
    }
    report.full_sha256 = Some(sha256_hex(serde_json::to_string(&full_map).unwrap_or_default().as_bytes()));
    report.models = advertised_models.clone();

    let configured_models = resolve_provider_models(Some(provider_block));
    for (mid, &adv) in &advertised_models {
        if !configured_models.contains_key(mid) {
            report.added.insert(mid.clone(), adv);
        } else {
            let prev = extract_context_length(&configured_models, mid);
            if prev != Some(adv) {
                report.updated.push(ModelContextUpdate { model: mid.clone(), previous_context_length: prev, context_length: adv });
            }
        }
    }

    if prune {
        let referenced = collect_referenced_models(cfg, target_provider);
        for mid in configured_models.keys() {
            if !fetched.catalog.contains_key(mid) {
                if referenced.contains(mid) {
                    report.protected_skipped.push(mid.clone());
                } else {
                    report.removed.push(mid.clone());
                }
            }
        }
    }

    let has_drift = !report.added.is_empty() || !report.updated.is_empty() || !report.removed.is_empty();
    if mode == ModelSyncMode::Check {
        if has_drift {
            report.status = "DRIFT".to_string();
            report.exit_code = EXIT_LIVE_CONTRACT;
            record_drift_findings(&mut report, target_provider);
        } else {
            report.status = "PASS".to_string();
            report.exit_code = EXIT_PASS;
        }
        return report;
    }

    if !has_drift {
        report.status = "PASS".to_string();
        report.exit_code = EXIT_PASS;
        return report;
    }

    let rendered = match apply_diff_to_yaml(&mut yaml_doc, target_provider, &report.added, &report.updated, &report.removed) {
        Ok(s) => s,
        Err(e) => return abort_with(report, "ERROR", EXIT_TOOL_ERROR, "SYNC_YAML_MUTATION_ERROR", e, "Inspect config.yaml provider structure before retrying.".into()),
    };
    let backup = match create_verified_backup(cfg_path, &orig_bytes) {
        Ok(p) => p,
        Err(e) => return abort_with(report, "ERROR", EXIT_TOOL_ERROR, "SYNC_BACKUP_FAILED", e, "Verify directory permissions for creating a 0600 backup before applying.".into()),
    };
    report.backup_path = Some(backup.to_string_lossy().into_owned());

    if let Err(e) = write_file_atomic_0600(cfg_path, rendered.as_bytes()) {
        return abort_with(report, "ERROR", EXIT_TOOL_ERROR, "SYNC_ATOMIC_WRITE_FAILED", e, "Verify write permissions on config.yaml parent directory.".into());
    }
    let reloaded = match load_yaml_mapping(cfg_path) {
        Ok(v) => v,
        Err(e) => {
            let rb = write_file_atomic_0600(cfg_path, &orig_bytes);
            return abort_with(report, "ERROR", EXIT_TOOL_ERROR, "SYNC_RELOAD_FAILED", format!("Post-write reload failed ({e}); rollback={rb:?}."), "Inspect backup_path and config.yaml.".into());
        }
    };

    let (live_exit, live_findings, _) = verify_live(&reloaded, policy, env_path, false, timeout_override);
    report.birkin_live_exit = Some(live_exit);
    if live_exit == EXIT_PASS {
        report.status = "PASS".to_string();
        report.exit_code = EXIT_PASS;
        return report;
    }

    report.findings.extend(live_findings);
    match write_file_atomic_0600(cfg_path, &orig_bytes) {
        Ok(()) => {
            report.status = "FAIL".to_string();
            report.exit_code = live_exit;
            let mut details = BTreeMap::new();
            details.insert("backup_path".into(), json!(report.backup_path));
            details.insert("birkin_live_exit".into(), json!(live_exit));
            report.findings.push(sync_finding(
                "SYNC_APPLY_ROLLED_BACK",
                format!("Post-apply verify_live failed with exit code {live_exit}; restored original config.yaml from backup."),
                "Resolve the live verification findings above before re-running --apply.".into(),
                details,
            ));
        }
        Err(err) => {
            return abort_with(report, "ERROR", EXIT_TOOL_ERROR, "SYNC_ROLLBACK_FAILED", format!("Post-apply verify_live failed (exit {live_exit}) and rollback failed: {err}"), format!("Manually restore config.yaml from backup: {}", backup.display()));
        }
    }
    report
}

pub fn format_model_sync_human(report: &ModelSyncReport) -> String {
    let mut lines = vec![format!(
        "birkin sync-models --{} (provider={}): status={} exit_code={} models={} added={} updated={} removed={}",
        report.mode,
        if report.provider.is_empty() { "<unset>" } else { &report.provider },
        report.status,
        report.exit_code,
        report.models.len(),
        report.added.len(),
        report.updated.len(),
        report.removed.len(),
    )];
    if let Some(ref ep) = report.endpoint { lines.push(format!("  endpoint: {ep}")); }
    if let Some(ref sha) = report.catalog_sha256 { lines.push(format!("  catalog_sha256: {sha}")); }
    if let Some(ref sha) = report.full_sha256 { lines.push(format!("  full_sha256: {sha}")); }
    for (mid, ctx) in &report.added {
        lines.push(format!("  + {mid} (context_length={ctx})"));
    }
    for upd in &report.updated {
        let prev = upd.previous_context_length.map(|v| v.to_string()).unwrap_or_else(|| "unset".into());
        lines.push(format!("  ~ {} (context_length: {prev} -> {})", upd.model, upd.context_length));
    }
    for rem in &report.removed { lines.push(format!("  - {rem}")); }
    for prot in &report.protected_skipped { lines.push(format!("  ! protected (not pruned): {prot}")); }
    if let Some(ref bak) = report.backup_path { lines.push(format!("  backup_path: {bak}")); }
    if let Some(code) = report.birkin_live_exit { lines.push(format!("  birkin_live_exit: {code}")); }
    for f in &report.findings {
        lines.push(format!("  - {} ({}): {}", f.rule, f.severity, f.message));
        lines.push(format!("    remediation: {}", f.remediation));
    }
    lines.join("\n")
}
