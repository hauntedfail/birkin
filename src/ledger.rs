//! Append-only, hash-chained receipt ledger bound to git revision and spec digest.

use crate::config_utils::{canonicalize_json, sha256_hex};
use crate::constants::home_dir;
use crate::project_models::ProjectSpec;
use chrono::Utc;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn default_ledger_dir() -> PathBuf {
    if let Ok(val) = env::var("BIRKIN_LEDGER_DIR") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    home_dir().join(".birkin").join("ledger")
}

pub fn repo_slug(repo_root: &Path) -> String {
    let resolved = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let resolved_str = resolved.to_string_lossy();
    let short_hash = &sha256_hex(resolved_str.as_bytes())[..10];
    let raw_name = resolved
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("repo");
    let re = Regex::new(r"[^A-Za-z0-9._-]+").unwrap();
    let safe = re.replace_all(raw_name, "-");
    let safe_trimmed = safe.trim_matches('-');
    let name = if safe_trimmed.is_empty() {
        "repo"
    } else {
        safe_trimmed
    };
    format!("{name}-{short_hash}")
}

pub fn resolve_ledger_path(repo_root: &Path, spec: &ProjectSpec) -> PathBuf {
    if let Some(custom) = &spec.telemetry.ledger_path {
        let expanded = if let Some(rest) = custom.strip_prefix("~/") {
            home_dir().join(rest)
        } else {
            PathBuf::from(custom)
        };
        return if expanded.is_absolute() {
            expanded
        } else {
            repo_root.join(expanded)
        };
    }
    default_ledger_dir().join(format!("{}.jsonl", repo_slug(repo_root)))
}

pub fn canonical_spec_sha256(spec: &ProjectSpec) -> String {
    let val = serde_json::to_value(spec).unwrap_or(Value::Null);
    let canon = canonicalize_json(&val, false);
    let payload = serde_json::to_string(&canon).unwrap_or_default();
    sha256_hex(payload.as_bytes())
}

#[derive(Debug, Clone)]
pub struct GitRevisionState {
    pub is_git: bool,
    pub git_head: Option<String>,
    pub git_dirty: bool,
    pub tree_digest: Option<String>,
}

pub fn git_revision_state(repo_root: &Path, ignore_rel: Option<&str>) -> GitRevisionState {
    snapshot(repo_root, ignore_rel).unwrap_or(GitRevisionState {
        is_git: false, git_head: None, git_dirty: true, tree_digest: None,
    })
}

fn git_bytes(root: &Path, args: &[&str], ignore: Option<&str>) -> io::Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.current_dir(root).args(args);
    if let Some(rel) = ignore {
        cmd.args(["--", ".", &format!(":(top,exclude,literal){rel}")]);
    }
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(io::Error::other(String::from_utf8_lossy(&out.stderr).into_owned()));
    }
    Ok(out.stdout)
}

#[cfg(unix)]
fn git_path(bytes: &[u8]) -> io::Result<&Path> {
    use std::os::unix::ffi::OsStrExt;
    Ok(Path::new(std::ffi::OsStr::from_bytes(bytes)))
}

#[cfg(not(unix))]
fn git_path(bytes: &[u8]) -> io::Result<&Path> {
    std::str::from_utf8(bytes).map(Path::new).map_err(io::Error::other)
}

fn snapshot(root: &Path, ignore: Option<&str>) -> io::Result<GitRevisionState> {
    let status = git_bytes(root, &["status", "--porcelain=v1", "-z", "--no-renames", "-uall"], ignore)?;
    let head = Command::new("git").current_dir(root).args(["rev-parse", "--verify", "--quiet", "HEAD"]).output()?;
    let revision = match head.status.code() {
        Some(0) => Some(String::from_utf8(head.stdout).map_err(io::Error::other)?.trim().to_owned()),
        Some(1) => None,
        _ => return Err(io::Error::other("cannot resolve HEAD")),
    };
    let mut hash = Sha256::new();
    hash.update(revision.as_deref().unwrap_or_default());
    hash.update(b"\n---\n");
    hash.update(&status);
    hash.update(b"\n---\n");
    if !status.is_empty() {
        for args in [vec!["diff", "--cached", "--binary", "--no-ext-diff", "--no-textconv"],
                     vec!["diff", "--binary", "--no-ext-diff", "--no-textconv"]] {
            let diff = git_bytes(root, &args, ignore)?;
            hash.update((diff.len() as u64).to_be_bytes());
            hash.update(diff);
        }
        for path in status.split(|&b| b == 0).filter_map(|row| row.strip_prefix(b"?? ")) {
            let file = root.join(git_path(path)?);
            let kind = fs::symlink_metadata(&file)?.file_type();
            hash.update((path.len() as u64).to_be_bytes());
            hash.update(path);
            if kind.is_symlink() {
                hash.update(b"L");
                hash.update(Sha256::digest(fs::read_link(file)?.as_os_str().as_encoded_bytes()));
            } else if kind.is_file() {
                hash.update(b"F");
                let mut contents = Sha256::new();
                io::copy(&mut fs::File::open(file)?, &mut contents)?;
                hash.update(contents.finalize());
            } else {
                return Err(io::Error::other(format!("unsupported untracked path {}", file.display())));
            }
        }
    }
    Ok(GitRevisionState { is_git: true, git_head: revision, git_dirty: !status.is_empty(),
        tree_digest: Some(format!("{:x}", hash.finalize())) })
}

fn relative_ignore(repo_root: &Path, ledger_path: &Path) -> Option<String> {
    let root = fs::canonicalize(repo_root).ok()?;
    let lp = fs::canonicalize(ledger_path).unwrap_or_else(|_| ledger_path.to_path_buf());
    let rel = lp.strip_prefix(&root).ok()?;
    Some(
        rel.components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/"),
    )
}

pub fn receipt_hash(entry: &Map<String, Value>) -> String {
    let mut copy = Map::new();
    for (k, v) in entry {
        if k != "receipt_sha256" {
            copy.insert(k.clone(), v.clone());
        }
    }
    let canon = canonicalize_json(&Value::Object(copy), false);
    let payload = serde_json::to_string(&canon).unwrap_or_default();
    sha256_hex(payload.as_bytes())
}

pub fn read_receipts(ledger_path: &Path) -> Vec<Map<String, Value>> {
    let read = || -> io::Result<_> {
        let mut file = fs::File::open(ledger_path)?;
        file.lock_shared()?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        Ok(parse_receipts(&text))
    };
    match read() {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(_) => vec![Map::from_iter([("_corrupt".into(), Value::Bool(true))])],
    }
}

fn parse_receipts(text: &str) -> Vec<Map<String, Value>> {
    let mut entries = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(Value::Object(map)) => entries.push(map),
            _ => {
                let mut m = Map::new();
                m.insert("_corrupt".into(), Value::Bool(true));
                m.insert("raw".into(), Value::String(line.to_string()));
                entries.push(m);
            }
        }
    }
    entries
}

pub fn verify_chain(entries: &[Map<String, Value>]) -> (bool, Vec<String>) {
    let mut errors = Vec::new();
    let mut prev_hash = String::from("GENESIS");
    for (idx, entry) in entries.iter().enumerate() {
        if entry.get("_corrupt").and_then(Value::as_bool).unwrap_or(false) {
            errors.push(format!("Line {}: corrupt JSON entry", idx + 1));
            continue;
        }
        let got_prev = entry
            .get("prev_receipt_sha256")
            .and_then(Value::as_str)
            .unwrap_or("");
        if got_prev != prev_hash {
            let exp_short: String = prev_hash.chars().take(12).collect();
            let got_short: String = got_prev.chars().take(12).collect();
            errors.push(format!(
                "Line {}: prev_receipt_sha256 mismatch (expected {}, got {})",
                idx + 1,
                exp_short,
                got_short
            ));
        }
        let expected_hash = receipt_hash(entry);
        let actual_hash = entry
            .get("receipt_sha256")
            .and_then(Value::as_str)
            .unwrap_or("");
        if actual_hash != expected_hash {
            errors.push(format!("Line {}: receipt_sha256 tampered or invalid", idx + 1));
        }
        prev_hash = actual_hash.to_string();
    }
    (errors.is_empty(), errors)
}

#[allow(clippy::too_many_arguments)]
pub fn append_receipt(
    repo_root: &Path,
    spec: &ProjectSpec,
    command: &str,
    surface: &str,
    outcome: &str,
    exit_code: i32,
    duration_ms: u128,
    findings: &[Value],
    files: &[String],
    meta: Map<String, Value>,
) -> Result<Map<String, Value>, String> {
    let ledger_path = resolve_ledger_path(repo_root, spec);
    if let Some(parent) = ledger_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed creating ledger dir {}: {e}", parent.display()))?;
    }

    let mut fh = OpenOptions::new().create(true).read(true).append(true).open(&ledger_path)
        .map_err(|e| format!("Failed opening ledger {}: {e}", ledger_path.display()))?;
    fh.lock().map_err(|e| format!("Failed locking ledger: {e}"))?;
    let mut text = String::new();
    fh.read_to_string(&mut text).map_err(|e| format!("Failed reading ledger: {e}"))?;
    let existing = parse_receipts(&text);
    let prev_hash = match existing.last() {
        Some(entry) => entry.get("receipt_sha256").and_then(Value::as_str).ok_or("Invalid receipt at end of ledger")?,
        None => "GENESIS",
    };
    let ignore_rel = relative_ignore(repo_root, &ledger_path);
    let rev = snapshot(repo_root, ignore_rel.as_deref()).map_err(|e| format!("Cannot snapshot working tree: {e}"))?;

    let mut rule_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut affected_files: Vec<String> = Vec::new();
    let mut error_count = 0usize;
    for item in findings {
        let rule = item
            .get("rule")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN")
            .to_string();
        *rule_counts.entry(rule).or_insert(0) += 1;
        if item.get("severity").and_then(Value::as_str) == Some("error") {
            error_count += 1;
        }
        if let Some(f) = item.get("file").and_then(Value::as_str) {
            if !affected_files.iter().any(|x| x == f) {
                affected_files.push(f.to_string());
            }
        }
    }

    let resolved_repo = fs::canonicalize(repo_root)
        .unwrap_or_else(|_| repo_root.to_path_buf())
        .to_string_lossy()
        .into_owned();

    let mut entry = Map::new();
    entry.insert("schema_version".into(), json!(1));
    entry.insert("recorded_at".into(), json!(Utc::now().to_rfc3339()));
    entry.insert("repo".into(), json!(resolved_repo));
    entry.insert("project".into(), json!(spec.project.name));
    entry.insert("command".into(), json!(command));
    entry.insert("surface".into(), json!(surface));
    entry.insert("outcome".into(), json!(outcome));
    entry.insert("exit_code".into(), json!(exit_code));
    entry.insert("duration_ms".into(), json!(duration_ms as u64));
    entry.insert("git_head".into(), json!(rev.git_head));
    entry.insert("git_dirty".into(), json!(rev.git_dirty));
    entry.insert("tree_digest".into(), json!(rev.tree_digest));
    entry.insert("spec_sha256".into(), json!(canonical_spec_sha256(spec)));
    entry.insert("finding_count".into(), json!(findings.len()));
    entry.insert("error_count".into(), json!(error_count));
    entry.insert("rule_counts".into(), json!(rule_counts));
    entry.insert("files_checked".into(), json!(files));
    entry.insert("affected_files".into(), json!(affected_files));
    entry.insert("meta".into(), Value::Object(meta));
    entry.insert("prev_receipt_sha256".into(), json!(prev_hash));

    let hash = receipt_hash(&entry);
    entry.insert("receipt_sha256".into(), json!(hash));

    let canon_entry = canonicalize_json(&Value::Object(entry.clone()), false);
    let serialized = serde_json::to_string(&canon_entry)
        .map_err(|e| format!("Failed serializing receipt: {e}"))?;

    if !text.is_empty() && !text.ends_with('\n') {
        fh.write_all(b"\n").map_err(|e| format!("Failed terminating receipt: {e}"))?;
    }
    writeln!(fh, "{serialized}")
        .map_err(|e| format!("Failed writing ledger {}: {e}", ledger_path.display()))?;

    Ok(entry)
}

pub fn verify_receipts_for_current_state(
    repo_root: &Path,
    spec: &ProjectSpec,
    required_commands: &[String],
    require_clean: bool,
) -> Value {
    let ledger_path = resolve_ledger_path(repo_root, spec);
    let entries = read_receipts(&ledger_path);
    let (chain_ok, chain_errors) = verify_chain(&entries);
    let ignore_rel = relative_ignore(repo_root, &ledger_path);
    let rev = git_revision_state(repo_root, ignore_rel.as_deref());
    let spec_sha = canonical_spec_sha256(spec);

    if rev.tree_digest.is_none() || (require_clean && rev.git_dirty) {
        return json!({
            "status": "FAIL",
            "reason": if rev.tree_digest.is_none() { "Cannot snapshot working tree" } else { "Working tree is dirty while --require-clean is set" },
            "chain_ok": chain_ok,
            "chain_errors": chain_errors,
            "ledger_path": ledger_path.to_string_lossy(),
            "git_head": rev.git_head,
            "git_dirty": rev.git_dirty,
            "tree_digest": rev.tree_digest,
            "spec_sha256": spec_sha,
            "matched": {},
            "missing": required_commands,
        });
    }

    let mut matched = Map::new();
    let mut missing = Vec::new();

    for req in required_commands {
        let mut found: Option<Value> = None;
        for entry in entries.iter().rev() {
            if entry.get("_corrupt").and_then(Value::as_bool).unwrap_or(false) {
                continue;
            }
            if entry.get("command").and_then(Value::as_str) != Some(req.as_str()) {
                continue;
            }
            if entry.get("exit_code").and_then(Value::as_i64) != Some(0)
                || entry.get("outcome").and_then(Value::as_str) != Some("PASS")
            {
                continue;
            }
            if entry.get("spec_sha256").and_then(Value::as_str) != Some(spec_sha.as_str()) {
                continue;
            }
            if let Some(ref td) = rev.tree_digest {
                if entry.get("tree_digest").and_then(Value::as_str) != Some(td.as_str()) {
                    continue;
                }
            }
            if let Some(ref gh) = rev.git_head {
                if entry.get("git_head").and_then(Value::as_str) != Some(gh.as_str()) {
                    continue;
                }
            }
            found = Some(json!({
                "recorded_at": entry.get("recorded_at"),
                "surface": entry.get("surface"),
                "receipt_sha256": entry.get("receipt_sha256"),
                "duration_ms": entry.get("duration_ms"),
            }));
            break;
        }
        match found {
            Some(v) => {
                matched.insert(req.clone(), v);
            }
            None => missing.push(req.clone()),
        }
    }

    let ok = chain_ok && missing.is_empty() && !required_commands.is_empty();
    json!({
        "status": if ok { "PASS" } else { "FAIL" },
        "chain_ok": chain_ok,
        "chain_errors": chain_errors,
        "ledger_path": ledger_path.to_string_lossy(),
        "git_head": rev.git_head,
        "git_dirty": rev.git_dirty,
        "tree_digest": rev.tree_digest,
        "spec_sha256": spec_sha,
        "matched": matched,
        "missing": missing,
    })
}
