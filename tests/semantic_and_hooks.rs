//! Semantic sensor mock-HTTP tests (PASS, fix_now, advisory, fail-closed contract & transient,
//! live rule calibration) and Claude Code PostToolUse hook end-to-end tests.

use birkin::constants::{EXIT_LIVE_CONTRACT, EXIT_LIVE_TRANSIENT, EXIT_PASS, EXIT_STATIC};
use birkin::project_models::{ProjectSpec, SemanticRule};
use birkin::semantic::{evaluate_semantic_rules, run_semantic_review};
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread;
use tempfile::TempDir;

fn read_http_request(stream: &mut std::net::TcpStream) {
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut header_end: Option<usize> = None;
    let mut content_len: usize = 0;
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                data.extend_from_slice(&chunk[..n]);
                if header_end.is_none() {
                    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                        let end = pos + 4;
                        header_end = Some(end);
                        let hdrs = String::from_utf8_lossy(&data[..pos]).to_lowercase();
                        for line in hdrs.lines() {
                            if let Some(val) = line.strip_prefix("content-length:") {
                                content_len = val.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                }
                if let Some(end) = header_end {
                    if data.len() >= end + content_len {
                        break;
                    }
                }
            }
        }
    }
}

fn spawn_mock_chat_server(responses: Vec<(&'static str, String)>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock semantic http");
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        for (status_line, body) in responses {
            if let Ok((mut stream, _)) = listener.accept() {
                read_http_request(&mut stream);
                let resp = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
                let _ = stream.shutdown(std::net::Shutdown::Write);
            }
        }
    });
    (format!("http://{addr}/v1"), handle)
}

fn chat_verdict_body(verdict_json: &str) -> String {
    json!({
        "choices": [
            { "message": { "content": verdict_json } }
        ]
    })
    .to_string()
}

fn make_semantic_spec(base_url: &str, action: &str) -> ProjectSpec {
    let mut spec = ProjectSpec::default();
    spec.project.name = "sem-test".into();
    spec.semantic.enabled = true;
    spec.semantic.base_url = base_url.to_string();
    spec.semantic.model = "mock-model".into();
    spec.semantic.timeout_seconds = 3.0;
    spec.semantic.rules = vec![SemanticRule {
        id: "no-silent-error".into(),
        description: "Never swallow errors as PASS".into(),
        predicate: "Does the code return PASS on error?".into(),
        globs: vec!["src/**/*.rs".into()],
        threshold: 0.75,
        action: action.into(),
        remediation: "Return an error exit code.".into(),
        examples_pass: vec!["Err(e) => return EXIT_LIVE_TRANSIENT".into()],
        examples_fail: vec!["Err(_) => return EXIT_PASS".into()],
    }];
    spec
}

#[test]
fn semantic_review_handles_pass_fix_now_advisory_and_fail_closed_errors() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join("src")).unwrap();
    let target = root.join("src/live.rs");
    fs::write(&target, "pub fn check() -> i32 { 0 }\n").unwrap();

    // 1. Clean PASS verdict
    let (url_pass, h_pass) = spawn_mock_chat_server(vec![(
        "200 OK",
        chat_verdict_body(
            r#"{"violated":false,"probability":0.05,"confidence":0.95,"line":null,"evidence":"clean","suggestion":""}"#,
        ),
    )]);
    let spec_pass = make_semantic_spec(&url_pass, "fix_now");
    let (code_pass, f_pass, _) =
        run_semantic_review(root, &spec_pass, false, None, Some(std::slice::from_ref(&target)));
    h_pass.join().unwrap();
    assert_eq!(code_pass, EXIT_PASS);
    assert!(f_pass.is_empty());

    // 2. Violated fix_now above threshold -> EXIT_STATIC with error finding
    let (url_fix, h_fix) = spawn_mock_chat_server(vec![(
        "200 OK",
        chat_verdict_body(
            r#"{"violated":true,"probability":0.92,"confidence":0.90,"line":1,"evidence":"returns 0","suggestion":"return error"}"#,
        ),
    )]);
    let spec_fix = make_semantic_spec(&url_fix, "fix_now");
    let (code_fix, f_fix, _) =
        run_semantic_review(root, &spec_fix, false, None, Some(std::slice::from_ref(&target)));
    h_fix.join().unwrap();
    assert_eq!(code_fix, EXIT_STATIC);
    assert_eq!(f_fix.len(), 1);
    assert_eq!(f_fix[0].severity, "error");
    assert_eq!(f_fix[0].rule, "SEMANTIC:no-silent-error");

    // 3. Violated advisory above threshold -> EXIT_PASS with warning finding
    let (url_adv, h_adv) = spawn_mock_chat_server(vec![(
        "200 OK",
        chat_verdict_body(
            r#"{"violated":true,"probability":0.85,"confidence":0.80,"line":1,"evidence":"advisory","suggestion":"consider fixing"}"#,
        ),
    )]);
    let spec_adv = make_semantic_spec(&url_adv, "advisory");
    let (code_adv, f_adv, _) =
        run_semantic_review(root, &spec_adv, false, None, Some(std::slice::from_ref(&target)));
    h_adv.join().unwrap();
    assert_eq!(code_adv, EXIT_PASS);
    assert_eq!(f_adv.len(), 1);
    assert_eq!(f_adv[0].severity, "warning");

    // 4. Malformed JSON from provider -> fail-closed EXIT_LIVE_CONTRACT
    let (url_bad, h_bad) = spawn_mock_chat_server(vec![(
        "200 OK",
        chat_verdict_body("not-json-at-all"),
    )]);
    let spec_bad = make_semantic_spec(&url_bad, "fix_now");
    let (code_bad, f_bad, _) =
        run_semantic_review(root, &spec_bad, false, None, Some(std::slice::from_ref(&target)));
    h_bad.join().unwrap();
    assert_eq!(code_bad, EXIT_LIVE_CONTRACT);
    assert!(f_bad.iter().any(|f| f.rule.starts_with("SEMANTIC_PROVIDER_ERROR:")));

    // 5. HTTP 500 -> fail-closed EXIT_LIVE_TRANSIENT
    let (url_500, h_500) = spawn_mock_chat_server(vec![(
        "500 Internal Server Error",
        r#"{"error":"upstream failed"}"#.to_string(),
    )]);
    let spec_500 = make_semantic_spec(&url_500, "fix_now");
    let (code_500, f_500, _) =
        run_semantic_review(root, &spec_500, false, None, Some(std::slice::from_ref(&target)));
    h_500.join().unwrap();
    assert_eq!(code_500, EXIT_LIVE_TRANSIENT);
    assert!(f_500.iter().any(|f| f.rule.starts_with("SEMANTIC_PROVIDER_ERROR:")));
}

#[test]
fn semantic_live_calibration_verifies_pass_and_detects_false_negatives() {
    // 1. Live PASS calibration (pass fixture -> violated=false, fail fixture -> violated=true)
    let (url_ok, h_ok) = spawn_mock_chat_server(vec![
        (
            "200 OK",
            chat_verdict_body(
                r#"{"violated":false,"probability":0.10,"confidence":0.9,"line":null,"evidence":"ok","suggestion":""}"#,
            ),
        ),
        (
            "200 OK",
            chat_verdict_body(
                r#"{"violated":true,"probability":0.95,"confidence":0.9,"line":1,"evidence":"caught","suggestion":"fix"}"#,
            ),
        ),
    ]);
    let spec_ok = make_semantic_spec(&url_ok, "fix_now");
    let report_ok = evaluate_semantic_rules(&spec_ok, true);
    h_ok.join().unwrap();
    assert_eq!(report_ok["status"], "PASS", "got {report_ok}");

    // 2. Live FAIL calibration (fail fixture missed -> false_negatives == 1)
    let (url_fn, h_fn) = spawn_mock_chat_server(vec![
        (
            "200 OK",
            chat_verdict_body(
                r#"{"violated":false,"probability":0.10,"confidence":0.9,"line":null,"evidence":"ok","suggestion":""}"#,
            ),
        ),
        (
            "200 OK",
            chat_verdict_body(
                r#"{"violated":false,"probability":0.20,"confidence":0.8,"line":null,"evidence":"missed","suggestion":""}"#,
            ),
        ),
    ]);
    let spec_fn = make_semantic_spec(&url_fn, "fix_now");
    let report_fn = evaluate_semantic_rules(&spec_fn, true);
    h_fn.join().unwrap();
    assert_eq!(report_fn["status"], "FAIL", "got {report_fn}");
    assert_eq!(report_fn["rules"][0]["false_negatives"], 1);
}

#[test]
fn claude_stdin_hook_emits_additional_context_on_violation_and_is_silent_when_clean() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join(".birkin")).unwrap();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join(".birkin/config.yaml"),
        r#"version: 1
project:
  name: hook-demo
  languages: [rust]
invariants:
  forbid_secrets: true
  english_prose_only: true
  forbid_debug_leftovers: true
telemetry:
  enabled: false
"#,
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_birkin");
    let file_path = root.join("src/demo.rs");

    // 1. Clean file -> silent stdout, exit 0
    fs::write(&file_path, "pub fn ok() -> u32 { 1 }\n").unwrap();
    let payload = json!({
        "tool_name": "Write",
        "tool_input": { "file_path": file_path.to_string_lossy() }
    })
    .to_string();

    let mut clean_child = Command::new(bin)
        .args(["hook", "post-edit", "--claude-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    clean_child.stdin.as_mut().unwrap().write_all(payload.as_bytes()).unwrap();
    let clean_out = clean_child.wait_with_output().unwrap();
    assert_eq!(clean_out.status.code(), Some(EXIT_PASS));
    assert!(String::from_utf8_lossy(&clean_out.stdout).trim().is_empty());

    // 2. Violating file -> JSON hookSpecificOutput.additionalContext with remediation
    fs::write(
        &file_path,
        concat!("pub fn bad() { ", "db", "g!(1); }\n"),
    )
    .unwrap();
    let mut bad_child = Command::new(bin)
        .args(["hook", "post-edit", "--claude-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    bad_child.stdin.as_mut().unwrap().write_all(payload.as_bytes()).unwrap();
    let bad_out = bad_child.wait_with_output().unwrap();
    assert_eq!(bad_out.status.code(), Some(EXIT_PASS));
    let parsed: Value = serde_json::from_slice(&bad_out.stdout)
        .expect("expected JSON hookSpecificOutput on stdout");
    let ctx = parsed["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or("");
    assert!(
        ctx.contains("INVARIANT_DEBUG_LEFTOVER:RUST_DBG_MACRO"),
        "missing remediation in additionalContext: {ctx}"
    );
}
