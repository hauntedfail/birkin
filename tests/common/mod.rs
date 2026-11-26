//! Shared helpers for workflow-contract integration tests.
#![allow(dead_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub fn oracle_path() -> PathBuf {
    let bin_name = if cfg!(windows) {
        "birkin-oracle.exe"
    } else {
        "birkin-oracle"
    };
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("lean")
        .join(".lake")
        .join("build")
        .join("bin")
        .join(bin_name)
}

/// Send line-oriented queries to the Lean 4 reference oracle and return one verdict per query.
/// Fails the calling test when the oracle is missing or answers a different number of lines.
pub fn query_lean_oracle(queries: &[String]) -> Vec<String> {
    let bin = oracle_path();
    assert!(
        bin.is_file(),
        "Lean oracle binary missing at {} (run `cd lean && lake build` first).",
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
    let verdicts: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(
        verdicts.len(),
        queries.len(),
        "oracle answered {} line(s) for {} query(ies)",
        verdicts.len(),
        queries.len()
    );
    verdicts
}

/// Assert that every Rust verdict equals the Lean verdict for the same query.
pub fn assert_matches_oracle(queries: &[String], rust: &[bool]) {
    assert_eq!(queries.len(), rust.len());
    assert!(!queries.is_empty(), "differential test produced no cases");
    let lean = query_lean_oracle(queries);
    for ((q, r), l) in queries.iter().zip(rust).zip(&lean) {
        assert_eq!(&r.to_string(), l, "Rust vs Lean mismatch on `{q}`");
    }
}

pub fn bit(v: bool) -> &'static str {
    if v {
        "1"
    } else {
        "0"
    }
}

/// Encode a list for the oracle, using `-` for the empty list.
pub fn joined(items: &[String], sep: &str) -> String {
    if items.is_empty() {
        "-".into()
    } else {
        items.join(sep)
    }
}
