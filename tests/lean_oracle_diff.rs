//! Differential tests verifying that Rust runtime logic matches the formally verified
//! Lean 4 reference oracle (`birkin-oracle`) across exhaustive input matrices.

use birkin::constants::combine_exit_codes;
use birkin::models::{FallbackEntry, RuntimePolicy};
use birkin::project_models::load_project_spec;
use birkin::sensors::find_layer_dag_cycles;
use birkin::static_check::verify_static;
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
