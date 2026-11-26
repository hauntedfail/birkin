//! Vendor-agnostic inferential (semantic) sensor engine and rule self-calibration.

use crate::constants::{EXIT_LIVE_CONTRACT, EXIT_LIVE_TRANSIENT, EXIT_PASS};
use crate::glob::matches_any;
use crate::project_models::{ProjectFinding, ProjectSpec, SemanticRule};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const SEMANTIC_SYSTEM_PROMPT: &str = concat!(
    "You are a strict, narrow code-review predicate evaluator. ",
    "Evaluate ONLY the single rule predicate against the provided code/diff. ",
    "Return ONLY valid JSON with exact keys: ",
    "{\"violated\": bool, \"probability\": float (0..1), \"confidence\": float (0..1), ",
    "\"line\": int or null, \"evidence\": string (short quote/reason), \"suggestion\": string}. ",
    "Do not wrap in markdown fences or add commentary."
);

fn resolve_api_key(spec: &ProjectSpec) -> Option<String> {
    if !spec.semantic.api_key_env.is_empty() {
        if let Ok(val) = env::var(&spec.semantic.api_key_env) {
            let t = val.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    let url = spec.semantic.base_url.to_lowercase();
    if url.contains("127.0.0.1") || url.contains("localhost") || url.contains("[::1]") {
        return Some("magpie".to_string());
    }
    None
}

pub fn collect_review_scope(
    repo_root: &Path,
    staged: bool,
    diff_ref: Option<&str>,
    files: Option<&[PathBuf]>,
    max_chars: usize,
) -> Vec<(String, String)> {
    let resolved_root = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let mut items = Vec::new();

    if let Some(explicit) = files {
        for f in explicit {
            let p = if f.is_absolute() {
                f.clone()
            } else {
                resolved_root.join(f)
            };
            let Ok(canon) = fs::canonicalize(&p) else {
                continue;
            };
            if !canon.is_file() {
                continue;
            }
            let Ok(rel) = canon.strip_prefix(&resolved_root) else {
                continue;
            };
            let rel_posix = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            if let Ok(text) = fs::read_to_string(&canon) {
                let truncated: String = text.chars().take(max_chars).collect();
                items.push((rel_posix, truncated));
            }
        }
        return items;
    }

    let mut args = vec![
        "-C".to_string(),
        resolved_root.to_string_lossy().into_owned(),
        "diff".to_string(),
        "--unified=3".to_string(),
    ];
    if staged {
        args.push("--cached".to_string());
    } else if let Some(dref) = diff_ref {
        args.push(dref.to_string());
    }

    let Ok(out) = Command::new("git").args(&args).output() else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    if stdout.trim().is_empty() {
        return Vec::new();
    }

    let mut current_file: Option<String> = None;
    let mut buf: Vec<String> = Vec::new();
    for line in stdout.lines() {
        if line.starts_with("diff --git ") {
            if let Some(cf) = current_file.take() {
                if !buf.is_empty() {
                    let joined: String = buf.join("\n").chars().take(max_chars).collect();
                    items.push((cf, joined));
                }
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            current_file = parts
                .get(3)
                .and_then(|p| p.strip_prefix("b/"))
                .map(ToString::to_string);
            buf = vec![line.to_string()];
        } else if current_file.is_some() {
            buf.push(line.to_string());
        }
    }
    if let Some(cf) = current_file {
        if !buf.is_empty() {
            let joined: String = buf.join("\n").chars().take(max_chars).collect();
            items.push((cf, joined));
        }
    }
    items
}

#[derive(Debug, Clone)]
struct Verdict {
    violated: bool,
    probability: f64,
    confidence: f64,
    line: Option<usize>,
    evidence: String,
    suggestion: String,
}

fn parse_verdict_json(raw_text: &str) -> Result<Verdict, String> {
    let mut cleaned = raw_text.trim().to_string();
    if cleaned.starts_with("```") {
        let lines: Vec<&str> = cleaned.lines().collect();
        if lines.len() >= 2 {
            let end = if lines.last().map(|l| l.trim().starts_with("```")).unwrap_or(false) {
                lines.len() - 1
            } else {
                lines.len()
            };
            cleaned = lines[1..end].join("\n").trim().to_string();
        }
    }
    let val: Value = serde_json::from_str(&cleaned).map_err(|e| format!("Invalid JSON: {e}"))?;
    let obj = val
        .as_object()
        .ok_or_else(|| "Verdict JSON must be an object".to_string())?;
    let violated = obj
        .get("violated")
        .and_then(Value::as_bool)
        .ok_or_else(|| "Missing boolean 'violated'".to_string())?;
    let probability = obj
        .get("probability")
        .and_then(Value::as_f64)
        .filter(|&p| (0.0..=1.0).contains(&p))
        .ok_or_else(|| "probability must be a float in [0, 1]".to_string())?;
    let confidence = obj
        .get("confidence")
        .and_then(Value::as_f64)
        .filter(|&c| (0.0..=1.0).contains(&c))
        .ok_or_else(|| "confidence must be a float in [0, 1]".to_string())?;
    let line = obj
        .get("line")
        .and_then(Value::as_u64)
        .map(|v| v as usize);
    let evidence = obj
        .get("evidence")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let suggestion = obj
        .get("suggestion")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    Ok(Verdict {
        violated,
        probability,
        confidence,
        line,
        evidence,
        suggestion,
    })
}

fn query_semantic_predicate(
    agent: &ureq::Agent,
    spec: &ProjectSpec,
    rule: &SemanticRule,
    target_label: &str,
    snippet: &str,
) -> (i32, Option<Verdict>, Option<String>) {
    let url = format!("{}/chat/completions", spec.semantic.base_url.trim_end_matches('/'));
    let truncated: String = snippet.chars().take(spec.semantic.max_diff_chars).collect();
    let user_prompt = format!(
        "Rule ID: {}\nDescription: {}\nPredicate (answer true if violated): {}\nTarget: {target_label}\n\nCode/Diff:\n{truncated}\n",
        rule.id, rule.description, rule.predicate
    );
    let body = json!({
        "model": spec.semantic.model,
        "temperature": 0.0,
        "max_tokens": 256,
        "messages": [
            {"role": "system", "content": SEMANTIC_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]
    });

    let mut req = agent.post(&url).set("Content-Type", "application/json");
    if let Some(key) = resolve_api_key(spec) {
        req = req.set("Authorization", &format!("Bearer {key}"));
    }

    let (status, txt) = match req.send_json(body) {
        Ok(resp) => (resp.status(), resp.into_string().unwrap_or_default()),
        Err(ureq::Error::Status(code, resp)) => (code, resp.into_string().unwrap_or_default()),
        Err(ureq::Error::Transport(err)) => {
            return (
                EXIT_LIVE_TRANSIENT,
                None,
                Some(format!("Semantic endpoint transport error: {err}")),
            );
        }
    };

    if matches!(status, 429 | 500 | 502 | 503 | 504) {
        return (
            EXIT_LIVE_TRANSIENT,
            None,
            Some(format!("Semantic endpoint transient HTTP {status}")),
        );
    }
    if status != 200 {
        let preview: String = txt.chars().take(200).collect();
        return (
            EXIT_LIVE_CONTRACT,
            None,
            Some(format!("Semantic endpoint contract HTTP {status}: {preview}")),
        );
    }

    let parsed: Result<Verdict, String> = (|| {
        let payload: Value = serde_json::from_str(&txt).map_err(|e| e.to_string())?;
        let choices = payload
            .get("choices")
            .and_then(Value::as_array)
            .filter(|c| !c.is_empty())
            .ok_or_else(|| "missing choices array".to_string())?;
        let content = choices[0]
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| "empty message content".to_string())?;
        parse_verdict_json(content)
    })();

    match parsed {
        Ok(v) => (EXIT_PASS, Some(v), None),
        Err(err) => (
            EXIT_LIVE_CONTRACT,
            None,
            Some(format!("Invalid semantic response payload: {err}")),
        ),
    }
}

pub fn run_semantic_review(
    repo_root: &Path,
    spec: &ProjectSpec,
    staged: bool,
    diff_ref: Option<&str>,
    files: Option<&[PathBuf]>,
) -> (i32, Vec<ProjectFinding>, Map<String, Value>) {
    let mut meta = Map::new();
    if spec.semantic.rules.is_empty() {
        meta.insert("evaluated".into(), json!(0));
        meta.insert("skipped_reason".into(), json!("no_semantic_rules"));
        return (EXIT_PASS, Vec::new(), meta);
    }

    let scope = collect_review_scope(repo_root, staged, diff_ref, files, spec.semantic.max_diff_chars);
    if scope.is_empty() {
        meta.insert("evaluated".into(), json!(0));
        meta.insert("skipped_reason".into(), json!("empty_scope"));
        return (EXIT_PASS, Vec::new(), meta);
    }

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs_f64(spec.semantic.timeout_seconds.max(1.0)))
        .build();

    let mut findings = Vec::new();
    let mut worst_code = EXIT_PASS;
    let mut evaluated = 0usize;
    let mut advisories = 0usize;
    let mut fix_now = 0usize;
    let scope_files: Vec<String> = scope.iter().map(|(f, _)| f.clone()).collect();

    for (rel, snippet) in &scope {
        for rule in &spec.semantic.rules {
            if !matches_any(rel, &rule.globs) {
                continue;
            }
            evaluated += 1;
            let (code, verdict_opt, err_opt) =
                query_semantic_predicate(&agent, spec, rule, rel, snippet);
            if code != EXIT_PASS || verdict_opt.is_none() {
                if code == EXIT_LIVE_CONTRACT || worst_code == EXIT_PASS {
                    worst_code = code;
                }
                findings.push(ProjectFinding {
                    rule: format!("SEMANTIC_PROVIDER_ERROR:{}", rule.id),
                    category: "semantic".into(),
                    severity: "error".into(),
                    file: Some(rel.clone()),
                    line: None,
                    message: err_opt.unwrap_or_else(|| "Semantic evaluation failed".into()),
                    remediation: "Check semantic.base_url / semantic.model / API key; errors are never treated as approval.".into(),
                    details: BTreeMap::new(),
                });
                continue;
            }
            let verdict = verdict_opt.unwrap();
            if verdict.violated && verdict.probability >= rule.threshold {
                let is_fix_now = rule.action == "fix_now";
                if is_fix_now {
                    fix_now += 1;
                    if worst_code == EXIT_PASS {
                        worst_code = crate::constants::EXIT_STATIC;
                    }
                } else {
                    advisories += 1;
                }
                let mut details = BTreeMap::new();
                details.insert("probability".into(), json!(verdict.probability));
                details.insert("confidence".into(), json!(verdict.confidence));
                details.insert("threshold".into(), json!(rule.threshold));
                details.insert("action".into(), json!(rule.action));
                if !verdict.evidence.is_empty() {
                    details.insert("evidence".into(), json!(verdict.evidence));
                }
                findings.push(ProjectFinding {
                    rule: format!("SEMANTIC:{}", rule.id),
                    category: "semantic".into(),
                    severity: if is_fix_now { "error" } else { "warning" }.into(),
                    file: Some(rel.clone()),
                    line: verdict.line,
                    message: format!(
                        "{} (p={:.2}, conf={:.2}): {}",
                        rule.description, verdict.probability, verdict.confidence, verdict.evidence
                    ),
                    remediation: if verdict.suggestion.is_empty() {
                        rule.remediation.clone()
                    } else {
                        verdict.suggestion
                    },
                    details,
                });
            }
        }
    }

    meta.insert("evaluated".into(), json!(evaluated));
    meta.insert("fix_now".into(), json!(fix_now));
    meta.insert("advisories".into(), json!(advisories));
    meta.insert("model".into(), json!(spec.semantic.model));
    meta.insert("files".into(), json!(scope_files));
    (worst_code, findings, meta)
}

pub fn evaluate_semantic_rules(spec: &ProjectSpec, live: bool) -> Value {
    let mut rows = Vec::new();
    let mut all_ok = true;
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs_f64(spec.semantic.timeout_seconds.max(1.0)))
        .build();

    for rule in &spec.semantic.rules {
        let missing_fixtures = rule.examples_pass.is_empty() || rule.examples_fail.is_empty();
        let mut fps = 0usize;
        let mut fns = 0usize;
        let mut live_errors = 0usize;

        if live && !missing_fixtures {
            for (idx, ex) in rule.examples_pass.iter().enumerate() {
                let (code, v, _) = query_semantic_predicate(
                    &agent,
                    spec,
                    rule,
                    &format!("fixture:pass:{idx}"),
                    ex,
                );
                if code != EXIT_PASS {
                    live_errors += 1;
                } else if let Some(ver) = v {
                    if ver.violated && ver.probability >= rule.threshold {
                        fps += 1;
                    }
                }
            }
            for (idx, ex) in rule.examples_fail.iter().enumerate() {
                let (code, v, _) = query_semantic_predicate(
                    &agent,
                    spec,
                    rule,
                    &format!("fixture:fail:{idx}"),
                    ex,
                );
                if code != EXIT_PASS {
                    live_errors += 1;
                } else if let Some(ver) = v {
                    if !(ver.violated && ver.probability >= rule.threshold) {
                        fns += 1;
                    }
                }
            }
        }

        let passed = !missing_fixtures && fps == 0 && fns == 0 && live_errors == 0;
        if !passed {
            all_ok = false;
        }
        rows.push(json!({
            "id": rule.id,
            "kind": "semantic",
            "mode": if live { "live" } else { "structural" },
            "status": if passed { "PASS" } else { "FAIL" },
            "examples_pass": rule.examples_pass.len(),
            "examples_fail": rule.examples_fail.len(),
            "false_positives": fps,
            "false_negatives": fns,
            "live_errors": live_errors,
            "missing_fixtures": missing_fixtures,
        }));
    }

    json!({
        "status": if all_ok { "PASS" } else { "FAIL" },
        "rules": rows,
    })
}
