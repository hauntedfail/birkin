//! Experience & decision observability: distill ledger receipts into steering signals.

use crate::ledger::{read_receipts, resolve_ledger_path, verify_chain};
use crate::project_models::ProjectSpec;
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

fn parse_ts(raw: Option<&Value>) -> Option<DateTime<Utc>> {
    let s = raw?.as_str()?;
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[derive(Debug, Clone)]
struct SpecBucket {
    spec_sha256: String,
    first_seen: Option<String>,
    runs: usize,
    passes: usize,
    total_findings: usize,
}

pub fn analyze_telemetry(repo_root: &Path, spec: &ProjectSpec) -> Value {
    let ledger_path = resolve_ledger_path(repo_root, spec);
    let raw_entries = read_receipts(&ledger_path);
    let (chain_ok, chain_errors) = verify_chain(&raw_entries);
    let entries: Vec<_> = raw_entries
        .into_iter()
        .filter(|e| !e.get("_corrupt").and_then(Value::as_bool).unwrap_or(false))
        .collect();

    let total_runs = entries.len();
    let pass_runs = entries
        .iter()
        .filter(|e| {
            e.get("exit_code").and_then(Value::as_i64) == Some(0)
                && e.get("outcome").and_then(Value::as_str) == Some("PASS")
        })
        .count();
    let fail_runs = total_runs.saturating_sub(pass_runs);

    let mut rule_hits: HashMap<String, usize> = HashMap::new();
    let mut file_hits: HashMap<String, usize> = HashMap::new();
    let mut surface_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut rule_events_by_file: BTreeMap<(String, String), Vec<DateTime<Utc>>> = BTreeMap::new();

    let mut open_fail_files: HashSet<String> = HashSet::new();
    let mut fail_episodes = 0usize;
    let mut resolved_episodes = 0usize;

    let mut spec_order: Vec<String> = Vec::new();
    let mut spec_stats: HashMap<String, SpecBucket> = HashMap::new();

    for entry in &entries {
        let surface = entry
            .get("surface")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        *surface_counts.entry(surface).or_insert(0) += 1;

        let ts = parse_ts(entry.get("recorded_at"));
        let ssha = entry
            .get("spec_sha256")
            .or_else(|| entry.get("harness_sha256"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();

        if !spec_stats.contains_key(&ssha) {
            spec_order.push(ssha.clone());
            spec_stats.insert(
                ssha.clone(),
                SpecBucket {
                    spec_sha256: ssha.chars().take(12).collect(),
                    first_seen: entry
                        .get("recorded_at")
                        .and_then(Value::as_str)
                        .map(ToString::to_string),
                    runs: 0,
                    passes: 0,
                    total_findings: 0,
                },
            );
        }
        if let Some(bucket) = spec_stats.get_mut(&ssha) {
            bucket.runs += 1;
            if entry.get("exit_code").and_then(Value::as_i64) == Some(0)
                && entry.get("outcome").and_then(Value::as_str) == Some("PASS")
            {
                bucket.passes += 1;
            }
            bucket.total_findings += entry
                .get("finding_count")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
        }

        let affected: Vec<String> = entry
            .get("affected_files")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let checked: Vec<String> = entry
            .get("files_checked")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default();

        if let Some(rc) = entry.get("rule_counts").and_then(Value::as_object) {
            for (rule, count_val) in rc {
                let c = count_val.as_u64().unwrap_or(0) as usize;
                *rule_hits.entry(rule.clone()).or_insert(0) += c;
                if let Some(t) = ts {
                    if affected.is_empty() {
                        rule_events_by_file
                            .entry((rule.clone(), "<repo>".to_string()))
                            .or_default()
                            .push(t);
                    } else {
                        for f in &affected {
                            rule_events_by_file
                                .entry((rule.clone(), f.clone()))
                                .or_default()
                                .push(t);
                        }
                    }
                }
            }
        }

        for f in &affected {
            *file_hits.entry(f.clone()).or_insert(0) += 1;
            if open_fail_files.insert(f.clone()) {
                fail_episodes += 1;
            }
        }
        let affected_set: HashSet<&str> = affected.iter().map(String::as_str).collect();
        for f in &checked {
            if open_fail_files.contains(f) && !affected_set.contains(f.as_str()) {
                open_fail_files.remove(f);
                resolved_episodes += 1;
            }
        }
    }

    let thrash_window = Duration::minutes(spec.telemetry.thrash_window_minutes);
    let mut thrash_alerts = Vec::new();
    for ((rule, fpath), mut times) in rule_events_by_file {
        times.sort();
        let mut max_in_window = 0usize;
        let mut left = 0usize;
        for (right, &t_r) in times.iter().enumerate() {
            while t_r - times[left] > thrash_window {
                left += 1;
            }
            max_in_window = max_in_window.max(right - left + 1);
        }
        if max_in_window >= spec.telemetry.thrash_threshold {
            thrash_alerts.push(json!({
                "rule": rule,
                "file": fpath,
                "hits_in_window": max_in_window,
                "window_minutes": spec.telemetry.thrash_window_minutes,
            }));
        }
    }

    let mut declared_rules = Vec::new();
    for r in &spec.invariants.custom_regex_rules {
        declared_rules.push(format!("CUSTOM_REGEX:{}", r.id));
    }
    for r in &spec.semantic.rules {
        declared_rules.push(format!("SEMANTIC:{}", r.id));
    }
    for r in &spec.architecture.forbidden_imports {
        declared_rules.push(format!("ARCH_FORBIDDEN_IMPORT:{}", r.id));
    }
    let mut stale_candidates = Vec::new();
    if total_runs >= spec.telemetry.stale_rule_min_runs {
        for rule_name in declared_rules {
            if *rule_hits.get(&rule_name).unwrap_or(&0) == 0 {
                stale_candidates.push(rule_name);
            }
        }
    }

    let mut rule_pairs: Vec<(String, usize)> = rule_hits.into_iter().collect();
    rule_pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let hotspots: Vec<Value> = rule_pairs
        .into_iter()
        .take(10)
        .map(|(r, c)| json!({"rule": r, "hits": c}))
        .collect();

    let mut file_pairs: Vec<(String, usize)> = file_hits.into_iter().collect();
    file_pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let file_hotspots: Vec<Value> = file_pairs
        .into_iter()
        .take(10)
        .map(|(f, c)| json!({"file": f, "hits": c}))
        .collect();

    let mut evolution = Vec::new();
    for ssha in spec_order {
        if let Some(ss) = spec_stats.get(&ssha) {
            let pass_rate = if ss.runs > 0 {
                ((ss.passes as f64 / ss.runs as f64) * 1000.0).round() / 1000.0
            } else {
                0.0
            };
            let avg_findings = if ss.runs > 0 {
                ((ss.total_findings as f64 / ss.runs as f64) * 100.0).round() / 100.0
            } else {
                0.0
            };
            evolution.push(json!({
                "spec_sha256": ss.spec_sha256,
                "first_seen": ss.first_seen,
                "runs": ss.runs,
                "passes": ss.passes,
                "total_findings": ss.total_findings,
                "pass_rate": pass_rate,
                "avg_findings": avg_findings,
            }));
        }
    }

    let mut recommendations = Vec::new();
    for alert in &thrash_alerts {
        recommendations.push(format!(
            "Agent thrashing detected on '{}' for rule '{}' ({}x in {}m): clarify the rule's remediation text or promote this constraint into AGENTS.md feedforward guidance.",
            alert["file"].as_str().unwrap_or(""),
            alert["rule"].as_str().unwrap_or(""),
            alert["hits_in_window"].as_u64().unwrap_or(0),
            alert["window_minutes"].as_i64().unwrap_or(0),
        ));
    }
    for item in hotspots.iter().take(3) {
        let hits = item["hits"].as_u64().unwrap_or(0);
        if hits >= 3 {
            recommendations.push(format!(
                "Recurring violation '{}' ({hits} hits): add a short feedforward example to AGENTS.md so agents avoid it on the first attempt.",
                item["rule"].as_str().unwrap_or(""),
            ));
        }
    }
    for stale in &stale_candidates {
        recommendations.push(format!(
            "Rule '{stale}' never fired across {total_runs} runs: verify with `birkin eval-rules` and prune it if the underlying assumption is obsolete."
        ));
    }
    if !chain_ok {
        recommendations.push(
            "Receipt ledger hash chain is broken; inspect tampering or corruption immediately."
                .to_string(),
        );
    }

    let pass_rate_opt = if total_runs > 0 {
        Some(((pass_runs as f64 / total_runs as f64) * 1000.0).round() / 1000.0)
    } else {
        None
    };
    let corr_rate_opt = if fail_episodes > 0 {
        Some(((resolved_episodes as f64 / fail_episodes as f64) * 1000.0).round() / 1000.0)
    } else {
        None
    };

    json!({
        "project": spec.project.name,
        "ledger_path": ledger_path.to_string_lossy(),
        "chain_ok": chain_ok,
        "chain_errors": chain_errors,
        "total_runs": total_runs,
        "pass_runs": pass_runs,
        "fail_runs": fail_runs,
        "pass_rate": pass_rate_opt,
        "surfaces": surface_counts,
        "hotspots": hotspots,
        "file_hotspots": file_hotspots,
        "thrash_alerts": thrash_alerts,
        "self_correction": {
            "fail_episodes": fail_episodes,
            "resolved_episodes": resolved_episodes,
            "rate": corr_rate_opt,
        },
        "stale_rule_candidates": stale_candidates,
        "spec_evolution": evolution,
        "recommendations": recommendations,
    })
}
