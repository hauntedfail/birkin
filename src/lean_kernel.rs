//! Fail-closed client for the compiled Lean 4 decision kernel (`birkin-kernel`).
//!
//! All five workflow contracts (`plan`, `scope`, `authority`, `stage`, `review_closure`)
//! delegate their admission verdicts to the native executable compiled directly from
//! `lean/BirkinSpec/`. Missing or malformed kernel responses fail closed with an error;
//! there is no unproved Rust decision fallback.

use crate::constants::home_dir;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, OnceLock};

pub const KERNEL_CONTRACT_VERSION: u64 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelPlanTask {
    pub id: String,
    pub status: String,
    pub depends_on: Vec<String>,
    pub has_completion_evidence: bool,
    pub allowed_paths_nonempty: bool,
    pub verification_nonempty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelBlockingQuestion {
    pub id: String,
    pub blocks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelPlanRequest {
    pub tasks: Vec<KernelPlanTask>,
    pub questions: Vec<KernelBlockingQuestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelPlanDispatchRequest {
    pub intent: String,
    pub task_id: String,
    pub tasks: Vec<KernelPlanTask>,
    pub questions: Vec<KernelBlockingQuestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelPathDecision {
    pub inside_root: bool,
    pub matched_allowed: bool,
    pub matched_forbidden: bool,
    pub matched_verify_output: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelScopeRequest {
    pub authority: String,
    pub decisions: Vec<KernelPathDecision>,
    pub my_writes: Vec<String>,
    pub other_active_writes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelAuthorityRequest {
    pub role: String,
    pub requested_tier: String,
    pub explicit_f_auth: bool,
    pub is_refusal_retry: bool,
    pub prev_tier: String,
    pub retries_after_first: u32,
    pub forbidden_model: bool,
    pub same_impl_runtime: bool,
    pub same_impl_model: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelStageRequest {
    pub stage: String,
    pub discovered_tests: usize,
    pub executed_tests: usize,
    pub toolchain_matched: bool,
    pub receipt_chain_ok: bool,
    pub tree_bound_ok: bool,
    pub review_passed: bool,
    pub sawyer_staged_exact: bool,
    pub sawyer_excluded_clean: bool,
    pub gpg_sign_required: bool,
    pub gpg_sig_valid: bool,
    pub remote_head_matches: bool,
    pub ci_passed: bool,
    pub release_authorized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelReviewItem {
    pub item_key: String,
    pub classification: String,
    pub replied: bool,
    pub resolved: bool,
    pub fix_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelReviewClosureRequest {
    pub request_re_review: bool,
    pub items: Vec<KernelReviewItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelVerdict {
    pub admitted: bool,
    pub reasons: Vec<String>,
    pub kernel_bin: String,
    pub kernel_version: String,
    pub contract_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanKernelVerdict {
    pub verdict: KernelVerdict,
    pub ready_tasks: Vec<String>,
    pub blocked_tasks: Vec<String>,
    pub done_tasks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeKernelVerdict {
    pub verdict: KernelVerdict,
    pub path_admitted: Vec<bool>,
    pub overlapping_writes: Vec<String>,
}

fn kernel_bin_name() -> &'static str {
    if cfg!(windows) {
        "birkin-kernel.exe"
    } else {
        "birkin-kernel"
    }
}

fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

/// Locate the compiled Lean 4 `birkin-kernel` binary.
///
/// Resolution order:
/// 1. `BIRKIN_KERNEL_BIN` (if set, fails closed if missing rather than falling back)
/// 2. Sibling binary next to canonicalized `current_exe()` (and raw `current_exe()`)
/// 3. Compile-time workspace `lean/.lake/build/bin/birkin-kernel`
/// 4. Ancestor `lean/.lake/build/bin/birkin-kernel` from current working directory
/// 5. `PATH` lookup
/// 6. `~/.local/bin/birkin-kernel` and `~/.hermes/scripts/birkin-kernel`
pub fn resolve_kernel_bin() -> Result<PathBuf, String> {
    if let Ok(explicit) = env::var("BIRKIN_KERNEL_BIN") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            if is_executable_file(&path) {
                return Ok(path);
            }
            return Err(format!(
                "BIRKIN_KERNEL_BIN points to missing Lean kernel binary: {}",
                path.display()
            ));
        }
    }

    let name = kernel_bin_name();
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(name));
        }
        if let Ok(canon) = std::fs::canonicalize(&exe) {
            if let Some(dir) = canon.parent() {
                candidates.push(dir.join(name));
                // Check repo lean/.lake/build/bin relative to target/{debug,release}/birkin
                if let Some(repo_dir) = dir.parent().and_then(Path::parent) {
                    candidates.push(
                        repo_dir
                            .join("lean")
                            .join(".lake")
                            .join("build")
                            .join("bin")
                            .join(name),
                    );
                }
            }
        }
    }

    candidates.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("lean")
            .join(".lake")
            .join("build")
            .join("bin")
            .join(name),
    );

    if let Ok(cwd) = env::current_dir() {
        for ancestor in cwd.ancestors() {
            candidates.push(
                ancestor
                    .join("lean")
                    .join(".lake")
                    .join("build")
                    .join("bin")
                    .join(name),
            );
        }
    }

    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            candidates.push(dir.join(name));
        }
    }

    let home = home_dir();
    candidates.push(home.join(".local").join("bin").join(name));
    candidates.push(home.join(".hermes").join("scripts").join(name));

    for cand in candidates {
        if is_executable_file(&cand) {
            return Ok(cand);
        }
    }

    Err(
        "Lean 4 decision kernel binary `birkin-kernel` not found. Build it with `cd lean && lake build` or set BIRKIN_KERNEL_BIN."
            .into(),
    )
}

struct KernelSession {
    bin: PathBuf,
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

fn kernel_session_slot() -> &'static Mutex<Option<KernelSession>> {
    static SLOT: OnceLock<Mutex<Option<KernelSession>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

fn spawn_kernel_session(bin: &Path) -> Result<KernelSession, String> {
    let mut child = Command::new(bin)
        .arg("--serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed spawning Lean kernel {}: {e}", bin.display()))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| format!("Failed opening stdin for Lean kernel {}", bin.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("Failed opening stdout for Lean kernel {}", bin.display()))?;
    Ok(KernelSession {
        bin: bin.to_path_buf(),
        _child: child,
        stdin,
        stdout: BufReader::new(stdout),
    })
}

fn exchange_line(session: &mut KernelSession, encoded: &str) -> Result<String, String> {
    session
        .stdin
        .write_all(encoded.as_bytes())
        .and_then(|_| session.stdin.write_all(b"\n"))
        .and_then(|_| session.stdin.flush())
        .map_err(|e| format!("Failed writing to Lean kernel stdin: {e}"))?;
    let mut line = String::new();
    let n = session
        .stdout
        .read_line(&mut line)
        .map_err(|e| format!("Failed reading from Lean kernel stdout: {e}"))?;
    if n == 0 {
        return Err(format!(
            "Lean kernel {} closed stdout unexpectedly",
            session.bin.display()
        ));
    }
    Ok(line.trim().to_string())
}

fn invoke_kernel_raw(payload: &Value) -> Result<(PathBuf, Value), String> {
    let bin = resolve_kernel_bin()?;
    let encoded = serde_json::to_string(payload)
        .map_err(|e| format!("Failed encoding kernel request JSON: {e}"))?;

    let mut guard = kernel_session_slot()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let needs_spawn = match guard.as_ref() {
        Some(sess) => sess.bin != bin,
        None => true,
    };
    if needs_spawn {
        *guard = Some(spawn_kernel_session(&bin)?);
    }

    let stdout = match exchange_line(guard.as_mut().unwrap(), &encoded) {
        Ok(line) => line,
        Err(_) => {
            *guard = Some(spawn_kernel_session(&bin)?);
            exchange_line(guard.as_mut().unwrap(), &encoded)?
        }
    };
    drop(guard);

    let parsed: Value = serde_json::from_str(&stdout).map_err(|e| {
        format!(
            "Invalid JSON from Lean kernel {}: {e} (raw: {stdout})",
            bin.display()
        )
    })?;
    if parsed.get("ok").and_then(Value::as_bool) != Some(true) {
        let err_msg = parsed
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("unknown kernel error");
        return Err(format!("Lean kernel rejected request: {err_msg}"));
    }
    let version = parsed
        .get("contract_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| "Lean kernel response missing contract_version".to_string())?;
    if version != KERNEL_CONTRACT_VERSION {
        return Err(format!(
            "Lean kernel contract_version mismatch: expected {KERNEL_CONTRACT_VERSION}, got {version}"
        ));
    }
    Ok((bin, parsed))
}

fn parse_str_array(val: &Value, key: &str) -> Result<Vec<String>, String> {
    let arr = val
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("Lean kernel response missing array field '{key}'"))?;
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("Lean kernel field '{key}' contains non-string element"))
        })
        .collect()
}

fn parse_bool_array(val: &Value, key: &str) -> Result<Vec<bool>, String> {
    let arr = val
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("Lean kernel response missing array field '{key}'"))?;
    arr.iter()
        .map(|v| {
            v.as_bool()
                .ok_or_else(|| format!("Lean kernel field '{key}' contains non-boolean element"))
        })
        .collect()
}

fn parse_verdict(bin: &Path, resp: &Value) -> Result<KernelVerdict, String> {
    let admitted = resp
        .get("admitted")
        .and_then(Value::as_bool)
        .ok_or_else(|| "Lean kernel response missing boolean 'admitted'".to_string())?;
    let reasons = parse_str_array(resp, "reasons")?;
    let kernel_version = resp
        .get("kernel_version")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let contract_version = resp
        .get("contract_version")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    Ok(KernelVerdict {
        admitted,
        reasons,
        kernel_bin: bin.to_string_lossy().into_owned(),
        kernel_version,
        contract_version,
    })
}

pub fn eval_plan(req: &KernelPlanRequest) -> Result<PlanKernelVerdict, String> {
    let payload = json!({
        "op": "plan_valid",
        "tasks": req.tasks,
        "questions": req.questions,
    });
    let (bin, resp) = invoke_kernel_raw(&payload)?;
    let verdict = parse_verdict(&bin, &resp)?;
    let ready_tasks = parse_str_array(&resp, "ready_tasks")?;
    let blocked_tasks = parse_str_array(&resp, "blocked_tasks")?;
    let done_tasks = parse_str_array(&resp, "done_tasks")?;
    Ok(PlanKernelVerdict {
        verdict,
        ready_tasks,
        blocked_tasks,
        done_tasks,
    })
}

pub fn eval_plan_dispatch(req: &KernelPlanDispatchRequest) -> Result<KernelVerdict, String> {
    let payload = json!({
        "op": "plan_dispatch",
        "intent": req.intent,
        "task_id": req.task_id,
        "tasks": req.tasks,
        "questions": req.questions,
    });
    let (bin, resp) = invoke_kernel_raw(&payload)?;
    parse_verdict(&bin, &resp)
}

pub fn eval_scope(req: &KernelScopeRequest) -> Result<ScopeKernelVerdict, String> {
    let payload = json!({
        "op": "scope_admit",
        "authority": req.authority,
        "decisions": req.decisions,
        "my_writes": req.my_writes,
        "other_active_writes": req.other_active_writes,
    });
    let (bin, resp) = invoke_kernel_raw(&payload)?;
    let verdict = parse_verdict(&bin, &resp)?;
    let path_admitted = parse_bool_array(&resp, "path_admitted")?;
    let overlapping_writes = parse_str_array(&resp, "overlapping_writes")?;
    Ok(ScopeKernelVerdict {
        verdict,
        path_admitted,
        overlapping_writes,
    })
}

pub fn eval_authority(req: &KernelAuthorityRequest) -> Result<KernelVerdict, String> {
    let payload = json!({
        "op": "authority_admit",
        "role": req.role,
        "requested_tier": req.requested_tier,
        "explicit_f_auth": req.explicit_f_auth,
        "is_refusal_retry": req.is_refusal_retry,
        "prev_tier": req.prev_tier,
        "retries_after_first": req.retries_after_first,
        "forbidden_model": req.forbidden_model,
        "same_impl_runtime": req.same_impl_runtime,
        "same_impl_model": req.same_impl_model,
    });
    let (bin, resp) = invoke_kernel_raw(&payload)?;
    parse_verdict(&bin, &resp)
}

pub fn eval_stage(req: &KernelStageRequest) -> Result<KernelVerdict, String> {
    let payload = json!({
        "op": "stage_admit",
        "stage": req.stage,
        "discovered_tests": req.discovered_tests,
        "executed_tests": req.executed_tests,
        "toolchain_matched": req.toolchain_matched,
        "receipt_chain_ok": req.receipt_chain_ok,
        "tree_bound_ok": req.tree_bound_ok,
        "review_passed": req.review_passed,
        "sawyer_staged_exact": req.sawyer_staged_exact,
        "sawyer_excluded_clean": req.sawyer_excluded_clean,
        "gpg_sign_required": req.gpg_sign_required,
        "gpg_sig_valid": req.gpg_sig_valid,
        "remote_head_matches": req.remote_head_matches,
        "ci_passed": req.ci_passed,
        "release_authorized": req.release_authorized,
    });
    let (bin, resp) = invoke_kernel_raw(&payload)?;
    parse_verdict(&bin, &resp)
}

pub fn eval_review_closure(req: &KernelReviewClosureRequest) -> Result<KernelVerdict, String> {
    let payload = json!({
        "op": "review_closure",
        "request_re_review": req.request_re_review,
        "items": req.items,
    });
    let (bin, resp) = invoke_kernel_raw(&payload)?;
    parse_verdict(&bin, &resp)
}
