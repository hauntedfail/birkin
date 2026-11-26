//! Canonical verification command runner with process-group timeout enforcement.

use crate::project_models::{ProjectFinding, ProjectSpec};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

fn tail_chars(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        s.to_string()
    } else {
        s.chars().skip(count - max_chars).collect()
    }
}

enum CmdOutcome {
    Finished {
        code: i32,
        ok: bool,
        combined: String,
    },
    TimedOut {
        combined: String,
    },
    SpawnError(String),
}

fn execute_with_timeout(repo_root: &Path, cmd: &str, timeout_secs: u64) -> CmdOutcome {
    #[cfg(windows)]
    let mut command = {
        let mut c = Command::new("cmd");
        c.args(["/C", cmd]);
        c
    };
    #[cfg(not(windows))]
    let mut command = {
        let mut c = Command::new("sh");
        c.args(["-c", cmd]);
        c
    };
    command
        .current_dir(repo_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Place the shell and its descendants into their own process group on Unix so
    // a timeout terminates the entire subtree and closes inherited stdio pipes.
    #[cfg(unix)]
    command.process_group(0);

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(err) => return CmdOutcome::SpawnError(err.to_string()),
    };

    let stdout_handle = child.stdout.take().map(|mut pipe| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });
    let stderr_handle = child.stderr.take().map(|mut pipe| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });

    let limit = Duration::from_secs(timeout_secs.max(1));
    let started = Instant::now();
    let mut timed_out = false;
    let mut exit_code = 1;
    let mut ok = false;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code().unwrap_or(1);
                ok = status.success();
                break;
            }
            Ok(None) => {
                if started.elapsed() >= limit {
                    timed_out = true;
                    #[cfg(unix)]
                    unsafe {
                        libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
                    }
                    #[cfg(windows)]
                    {
                        let _ = Command::new("taskkill")
                            .args(["/F", "/T", "/PID", &child.id().to_string()])
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .status();
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                thread::sleep(Duration::from_millis(15));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }
    }

    let stdout_bytes = stdout_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let stderr_bytes = stderr_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&stdout_bytes),
        String::from_utf8_lossy(&stderr_bytes)
    );

    if timed_out {
        CmdOutcome::TimedOut { combined }
    } else {
        CmdOutcome::Finished {
            code: exit_code,
            ok,
            combined,
        }
    }
}

pub fn run_verify_commands(
    repo_root: &Path,
    spec: &ProjectSpec,
) -> (Vec<ProjectFinding>, Vec<Value>) {
    let mut findings = Vec::new();
    let mut results = Vec::new();

    for vc in &spec.verify.commands {
        let t0 = Instant::now();
        let outcome = execute_with_timeout(repo_root, &vc.cmd, vc.timeout_seconds);
        let dur_ms = t0.elapsed().as_millis() as u64;

        match outcome {
            CmdOutcome::Finished { code, ok, combined } => {
                let tail = tail_chars(combined.trim(), 1500);
                results.push(json!({
                    "name": vc.name, "cmd": vc.cmd, "kind": vc.kind,
                    "exit_code": code, "duration_ms": dur_ms,
                    "status": if ok { "PASS" } else { "FAIL" }, "output_tail": tail,
                }));
                if !ok {
                    let mut details = BTreeMap::new();
                    details.insert("exit_code".into(), json!(code));
                    details.insert("output_tail".into(), json!(tail_chars(&tail, 600)));
                    findings.push(ProjectFinding {
                        rule: format!("ADMISSION_VERIFY_FAILED:{}", vc.name),
                        category: "admission".into(),
                        severity: "error".into(),
                        file: None,
                        line: None,
                        message: format!(
                            "Canonical verify command '{}' (`{}`) failed with exit {code}.",
                            vc.name, vc.cmd
                        ),
                        remediation: format!(
                            "Run `{}` locally, fix the reported failures, and re-run `birkin check --run-verify`.",
                            vc.cmd
                        ),
                        details,
                    });
                }
            }
            CmdOutcome::TimedOut { combined } => {
                let tail = tail_chars(combined.trim(), 1500);
                results.push(json!({
                    "name": vc.name, "cmd": vc.cmd, "kind": vc.kind,
                    "exit_code": 124, "duration_ms": dur_ms,
                    "timeout_seconds": vc.timeout_seconds,
                    "status": "TIMEOUT", "output_tail": tail,
                }));
                let mut details = BTreeMap::new();
                details.insert("exit_code".into(), json!(124));
                details.insert("timed_out".into(), json!(true));
                details.insert("timeout_seconds".into(), json!(vc.timeout_seconds));
                details.insert("output_tail".into(), json!(tail_chars(&tail, 600)));
                findings.push(ProjectFinding {
                    rule: format!("ADMISSION_VERIFY_TIMEOUT:{}", vc.name),
                    category: "admission".into(),
                    severity: "error".into(),
                    file: None,
                    line: None,
                    message: format!(
                        "Canonical verify command '{}' (`{}`) timed out after {}s.",
                        vc.name, vc.cmd, vc.timeout_seconds
                    ),
                    remediation: format!(
                        "Investigate why `{}` hung or increase timeout_seconds in .birkin/config.yaml.",
                        vc.cmd
                    ),
                    details,
                });
            }
            CmdOutcome::SpawnError(err) => {
                results.push(json!({
                    "name": vc.name, "cmd": vc.cmd, "kind": vc.kind,
                    "exit_code": 127, "duration_ms": dur_ms,
                    "status": "ERROR", "output_tail": err,
                }));
                findings.push(ProjectFinding {
                    rule: format!("ADMISSION_VERIFY_FAILED:{}", vc.name),
                    category: "admission".into(),
                    severity: "error".into(),
                    file: None,
                    line: None,
                    message: format!("Failed spawning verify command '{}': {err}", vc.name),
                    remediation: format!("Ensure `{}` is executable in PATH.", vc.cmd),
                    details: BTreeMap::new(),
                });
            }
        }
    }

    (findings, results)
}
