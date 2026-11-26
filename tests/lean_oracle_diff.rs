//! Differential tests verifying that Rust runtime logic matches the formally verified
//! Lean 4 reference oracle (`birkin-oracle`) across exhaustive input matrices.

use birkin::constants::combine_exit_codes;
use birkin::ledger::{
    append_receipt, canonical_spec_sha256, git_revision_state, read_receipts, receipt_hash,
    resolve_ledger_path, verify_chain, verify_receipts_for_current_state,
};
use birkin::models::{FallbackEntry, RuntimePolicy};
use birkin::project_models::{load_project_spec, ProjectSpec};
use birkin::sensors::find_layer_dag_cycles;
use birkin::static_check::verify_static;
use serde_json::{json, Map, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn oracle_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("lean")
        .join(".lake")
        .join("build")
        .join("bin")
        .join("birkin-oracle")
}

fn query_lean_oracle(queries: &[String]) -> Vec<String> {
    let bin = oracle_path();
    assert!(
        bin.is_file(),
        "Lean oracle binary missing at {} — run `lake --dir lean build` first.",
        bin.display()
    );
    let mut child = Command::new(&bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn birkin-oracle");
    {
        let stdin = child.stdin.as_mut().expect("oracle stdin");
        for q in queries {
            writeln!(stdin, "{q}").expect("write oracle query");
        }
    }
    let out = child.wait_with_output().expect("wait birkin-oracle");
    assert!(
        out.status.success(),
        "birkin-oracle failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[test]
fn diff_exit_code_lattice_exhaustive_pairs_and_triples() {
    let mut queries = Vec::new();
    let mut expected_rust = Vec::new();

    for a in 0..=5 {
        for b in 0..=5 {
            queries.push(format!("combine {a} {b}"));
            expected_rust.push(combine_exit_codes(&[a, b]).to_string());
        }
    }
    for a in 0..=5 {
        for b in 0..=5 {
            for c in 0..=5 {
                queries.push(format!("combine {a} {b} {c}"));
                expected_rust.push(combine_exit_codes(&[a, b, c]).to_string());
            }
        }
    }

    let lean_out = query_lean_oracle(&queries);
    assert_eq!(lean_out.len(), expected_rust.len());
    for ((q, r), l) in queries.iter().zip(expected_rust.iter()).zip(lean_out.iter()) {
        assert_eq!(r, l, "Rust vs Lean mismatch on `{q}`: rust={r} lean={l}");
    }
}

#[test]
fn diff_six_layer_dag_matches_birkin_config_and_lean() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let (spec, _) = load_project_spec(&repo_root, None).expect("load .birkin/config.yaml");
    assert!(
        find_layer_dag_cycles(&spec.architecture.layers).is_empty(),
        "Birkin's own 6-layer DAG must be acyclic"
    );

    let names = ["core", "models", "utils", "engines", "orchestration", "cli"];
    let mut queries = Vec::new();
    let mut rust_results = Vec::new();

    for &src in &names {
        let layer = spec
            .architecture
            .layers
            .iter()
            .find(|l| l.name == src)
            .expect("layer present in .birkin/config.yaml");
        for &dst in &names {
            queries.push(format!("layer_edge {src} {dst}"));
            let allowed = src == dst || layer.allowed_dependencies.iter().any(|d| d == dst);
            rust_results.push(allowed.to_string());
        }
    }

    let lean_out = query_lean_oracle(&queries);
    assert_eq!(lean_out, rust_results);
}

#[test]
fn diff_fallback_denylist_dominance_against_lean() {
    let mut policy = RuntimePolicy::default();
    policy.fallback_providers.forbidden_patterns = vec!["*opus*".into()];
    policy.fallback_providers.allowed = vec![
        FallbackEntry {
            provider: "custom".into(),
            model: "opus-secret".into(),
        },
        FallbackEntry {
            provider: "custom".into(),
            model: "allowed-model".into(),
        },
    ];

    let cases = [
        // (model, is_forbidden, in_allowlist)
        ("opus-secret", true, true),
        ("opus-unlisted", true, false),
        ("allowed-model", false, true),
        ("other-model", false, false),
    ];

    let queries: Vec<String> = cases
        .iter()
        .map(|(_, f, a)| format!("fallback {} {}", if *f { 1 } else { 0 }, if *a { 1 } else { 0 }))
        .collect();
    let lean_out = query_lean_oracle(&queries);

    for ((model, _, _), lean_allowed) in cases.iter().zip(lean_out.iter()) {
        let cfg = json!({
            "model": { "provider": "custom", "default": "group/lvmh" },
            "providers": {
                "custom": {
                    "base_url": "http://127.0.0.1:3425/v1",
                    "api_key": "k",
                    "models": { "group/lvmh": { "context_length": 128000 } }
                }
            },
            "fallback_providers": [
                { "provider": "custom", "model": model }
            ]
        });
        let (code, findings) = verify_static(&cfg, &policy, None, None);
        let rust_allowed = (code == 0 && findings.is_empty()).to_string();
        assert_eq!(
            &rust_allowed, lean_allowed,
            "Fallback decision mismatch for {model}: rust={rust_allowed} lean={lean_allowed} findings={findings:?}"
        );
    }
}

#[test]
fn diff_compression_bounds_against_lean() {
    let policy = RuntimePolicy::default();
    // default bounds: threshold_min = 0.10 (1000 bp), threshold_max = 0.95 (9500 bp), require_target_lt = true
    let cases = [
        (8000u32, 5000u32), // valid: 0.80, 0.50
        (500u32, 200u32),   // invalid: threshold below min
        (9800u32, 5000u32), // invalid: threshold above max
        (5000u32, 5000u32), // invalid: target == threshold
        (5000u32, 6000u32), // invalid: target > threshold
        (5000u32, 0u32),    // invalid: target == 0
    ];

    let queries: Vec<String> = cases
        .iter()
        .map(|(th, tr)| format!("compression 1000 9500 1 {th} {tr}"))
        .collect();
    let lean_out = query_lean_oracle(&queries);

    for ((th, tr), lean_ok) in cases.iter().zip(lean_out.iter()) {
        let cfg = json!({
            "model": { "provider": "custom", "default": "group/lvmh" },
            "providers": {
                "custom": {
                    "base_url": "http://127.0.0.1:3425/v1",
                    "api_key": "k",
                    "models": { "group/lvmh": { "context_length": 128000 } }
                }
            },
            "fallback_providers": [],
            "compression": {
                "enabled": true,
                "threshold": (*th as f64) / 10000.0,
                "target_ratio": (*tr as f64) / 10000.0
            }
        });
        let (code, findings) = verify_static(&cfg, &policy, None, None);
        let rust_ok = (code == 0 && findings.is_empty()).to_string();
        assert_eq!(
            &rust_ok, lean_ok,
            "Compression bounds mismatch for th={th} tr={tr}: rust={rust_ok} lean={lean_ok} findings={findings:?}"
        );
    }
}

fn encode_receipt_for_oracle(entry: &Map<String, Value>) -> String {
    let corrupt = entry
        .get("_corrupt")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let cmd = entry
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let outcome_pass = entry.get("outcome").and_then(Value::as_str) == Some("PASS");
    let exit_code = entry.get("exit_code").and_then(Value::as_i64).unwrap_or(1).max(0);
    let git_head = entry
        .get("git_head")
        .and_then(Value::as_str)
        .unwrap_or("-");
    let tree_digest = entry
        .get("tree_digest")
        .and_then(Value::as_str)
        .unwrap_or("-");
    let spec_sha = entry
        .get("spec_sha256")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let prev_hash = entry
        .get("prev_receipt_sha256")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let actual_hash = entry
        .get("receipt_sha256")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let computed_hash = if corrupt {
        "corrupt".to_string()
    } else {
        receipt_hash(entry)
    };
    format!(
        "{},{},{},{},{},{},{},{},{},{}",
        if corrupt { 1 } else { 0 },
        cmd,
        if outcome_pass { 1 } else { 0 },
        exit_code,
        git_head,
        tree_digest,
        spec_sha,
        prev_hash,
        actual_hash,
        computed_hash,
    )
}

fn git_cmd(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Birkin Diff")
        .env("GIT_AUTHOR_EMAIL", "diff@example.com")
        .env("GIT_COMMITTER_NAME", "Birkin Diff")
        .env("GIT_COMMITTER_EMAIL", "diff@example.com")
        .output()
        .expect("run git");
    assert!(out.status.success(), "git {:?} failed", args);
}

#[test]
fn diff_receipt_chain_and_admission_against_lean() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    git_cmd(root, &["init", "-q"]);
    fs::write(root.join("main.rs"), "fn main() {}\n").unwrap();
    git_cmd(root, &["add", "."]);
    git_cmd(root, &["commit", "-q", "-m", "init"]);

    let ledger_file = tmp.path().join(".ledger.jsonl");
    let mut spec = ProjectSpec::default();
    spec.project.name = "diff-ledger".into();
    spec.telemetry.ledger_path = Some(ledger_file.to_string_lossy().into_owned());

    // Record clean `check` and `verify` receipts
    append_receipt(root, &spec, "check", "cli", "PASS", 0, 5, &[], &[], Map::new()).unwrap();
    append_receipt(root, &spec, "verify", "cli", "PASS", 0, 8, &[], &[], Map::new()).unwrap();

    let mut queries = Vec::new();
    let mut rust_results = Vec::new();

    let check_case = |entries: &[Map<String, Value>],
                      reqs: &[String],
                      require_clean: bool,
                      spec_for_check: &ProjectSpec,
                      queries: &mut Vec<String>,
                      rust_results: &mut Vec<String>| {
        let rev = git_revision_state(root, Some(".ledger.jsonl"));
        let spec_sha = canonical_spec_sha256(spec_for_check);
        let encoded: Vec<String> = entries.iter().map(encode_receipt_for_oracle).collect();

        // 1. Chain verification comparison
        let chain_query = if encoded.is_empty() {
            "receipt_chain".to_string()
        } else {
            format!("receipt_chain {}", encoded.join(" "))
        };
        let (rust_chain_ok, _) = verify_chain(entries);
        queries.push(chain_query);
        rust_results.push(rust_chain_ok.to_string());

        // 2. Admission verification comparison
        let req_csv = if reqs.is_empty() {
            "-".to_string()
        } else {
            reqs.join(",")
        };
        let head_s = rev.git_head.as_deref().unwrap_or("-");
        let tree_s = rev.tree_digest.as_deref().unwrap_or("-");
        let adm_query = if encoded.is_empty() {
            format!(
                "receipt_admission {req_csv} {head_s} {tree_s} {spec_sha} {} {}",
                if require_clean { 1 } else { 0 },
                if rev.git_dirty { 1 } else { 0 }
            )
        } else {
            format!(
                "receipt_admission {req_csv} {head_s} {tree_s} {spec_sha} {} {} {}",
                if require_clean { 1 } else { 0 },
                if rev.git_dirty { 1 } else { 0 },
                encoded.join(" ")
            )
        };
        let rust_adm = verify_receipts_for_current_state(root, spec_for_check, reqs, require_clean);
        let rust_adm_ok = rust_adm["status"] == "PASS";
        queries.push(adm_query);
        rust_results.push(rust_adm_ok.to_string());
    };

    let ledger_path = resolve_ledger_path(root, &spec);
    let clean_entries = read_receipts(&ledger_path);

    // Case 1: Clean repo, both check & verify present -> true
    check_case(&clean_entries, &["check".into(), "verify".into()], true, &spec, &mut queries, &mut rust_results);
    // Case 2: Empty required commands -> fail closed (false)
    check_case(&clean_entries, &[], true, &spec, &mut queries, &mut rust_results);
    // Case 3: Missing required command (`review`) -> false
    check_case(&clean_entries, &["check".into(), "review".into()], true, &spec, &mut queries, &mut rust_results);
    // Case 4: Spec digest changed -> false
    let mut changed_spec = spec.clone();
    changed_spec.project.name = "mutated-spec".into();
    check_case(&clean_entries, &["check".into()], true, &changed_spec, &mut queries, &mut rust_results);

    // Case 5: Dirty working tree (require_clean=true and require_clean=false) -> both false
    fs::write(root.join("main.rs"), "fn main() { let _ = 1; }\n").unwrap();
    check_case(&clean_entries, &["check".into()], true, &spec, &mut queries, &mut rust_results);
    check_case(&clean_entries, &["check".into()], false, &spec, &mut queries, &mut rust_results);

    // Restore clean working tree, tamper ledger entry -> chain false, admission false
    fs::write(root.join("main.rs"), "fn main() {}\n").unwrap();
    let orig_text = fs::read_to_string(&ledger_path).unwrap();
    fs::write(&ledger_path, orig_text.replace("\"PASS\"", "\"FAIL\"")).unwrap();
    let tampered_entries = read_receipts(&ledger_path);
    check_case(&tampered_entries, &["check".into()], true, &spec, &mut queries, &mut rust_results);

    // Append corrupt JSON line -> chain false, admission false
    fs::write(&ledger_path, format!("{orig_text}{{not-valid-json\n")).unwrap();
    let corrupt_entries = read_receipts(&ledger_path);
    check_case(&corrupt_entries, &["check".into()], true, &spec, &mut queries, &mut rust_results);

    let lean_out = query_lean_oracle(&queries);
    assert_eq!(lean_out.len(), rust_results.len());
    for ((q, r), l) in queries.iter().zip(rust_results.iter()).zip(lean_out.iter()) {
        assert_eq!(r, l, "Rust vs Lean receipt mismatch on `{q}`: rust={r} lean={l}");
    }
}
