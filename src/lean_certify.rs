//! Mode B Lean 4 kernel certificate generator and `#print axioms` auditor.
//!
//! For milestone gates (`--certify`), deterministically emits a self-contained `.lean`
//! certificate importing prebuilt `BirkinSpec` `.olean` libraries, invokes `lean` directly
//! with `LEAN_PATH`, audits `#print axioms certified` for zero `sorry`/`native_decide`/
//! custom axioms, and returns a content-addressed `proof_sha256` for ledger recording.

use crate::config_utils::sha256_hex;
use crate::constants::home_dir;
use crate::lean_kernel::{
    KernelAuthorityRequest, KernelBlockingQuestion, KernelPathDecision, KernelPlanDispatchRequest,
    KernelPlanRequest, KernelPlanTask, KernelReviewClosureRequest, KernelReviewItem,
    KernelScopeRequest, KernelStageRequest,
};
use crate::project_models::ProjectFinding;
use crate::prove_audit::{audit_axioms, parse_print_axioms};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum CertObligation {
    Plan(KernelPlanRequest),
    PlanDispatch(KernelPlanDispatchRequest),
    Scope(KernelScopeRequest),
    Authority(KernelAuthorityRequest),
    Stage(KernelStageRequest),
    ReviewClosure(KernelReviewClosureRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificationOutcome {
    pub certified: bool,
    pub contract: String,
    pub theorem: String,
    pub proof_sha256: String,
    pub kernel_axioms: Vec<String>,
    pub elapsed_ms: u64,
    pub proof_path: Option<String>,
    pub lean_lib_dir: String,
    pub detail: Option<String>,
}

fn lean_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn lean_bool(b: bool) -> &'static str {
    if b { "true" } else { "false" }
}

fn lean_str_list(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| lean_str(s)).collect();
    format!("[{}]", inner.join(", "))
}

fn lean_task_status(s: &str) -> Result<&'static str, String> {
    match s {
        "ready" => Ok(".ready"),
        "blocked" => Ok(".blocked"),
        "in_progress" => Ok(".inProgress"),
        "done" => Ok(".done"),
        "superseded" => Ok(".superseded"),
        other => Err(format!("Unsupported task status for certificate: {other}")),
    }
}

fn lean_plan_intent(s: &str) -> Result<&'static str, String> {
    match s {
        "plan-only" => Ok(".planOnly"),
        "implement" => Ok(".implement"),
        other => Err(format!("Unsupported plan intent for certificate: {other}")),
    }
}

fn lean_path_authority(s: &str) -> Result<&'static str, String> {
    match s {
        "source" | "source_edit" => Ok(".sourceEdit"),
        "verification_output" => Ok(".verificationOutput"),
        other => Err(format!("Unsupported path authority for certificate: {other}")),
    }
}

fn lean_role(s: &str) -> Result<&'static str, String> {
    match s {
        "scope" => Ok(".scope"),
        "review" => Ok(".review"),
        "research" => Ok(".research"),
        "docs" => Ok(".docs"),
        "investigate" => Ok(".investigate"),
        "implement" => Ok(".implement"),
        "finalize" => Ok(".finalize"),
        other => Err(format!("Unsupported agent role for certificate: {other}")),
    }
}

fn lean_tier(s: &str) -> Result<&'static str, String> {
    match s {
        "R" => Ok(".R"),
        "W" => Ok(".W"),
        "F" => Ok(".F"),
        other => Err(format!("Unsupported approval tier for certificate: {other}")),
    }
}

fn lean_stage(s: &str) -> Result<&'static str, String> {
    match s {
        "implemented" => Ok(".implemented"),
        "verified" => Ok(".verified"),
        "reviewed" => Ok(".reviewed"),
        "committed" => Ok(".committed"),
        "pushed" => Ok(".pushed"),
        "ci_passed" => Ok(".ciPassed"),
        "released" => Ok(".released"),
        other => Err(format!("Unsupported lifecycle stage for certificate: {other}")),
    }
}

fn lean_review_class(s: &str) -> Result<&'static str, String> {
    match s {
        "unclassified" => Ok(".unclassified"),
        "must_fix" => Ok(".mustFix"),
        "already_fixed" => Ok(".alreadyFixed"),
        "not_valid" => Ok(".notValid"),
        "out_of_scope" => Ok(".outOfScope"),
        "needs_clarification" => Ok(".needsClarification"),
        other => Err(format!(
            "Unsupported review classification for certificate: {other}"
        )),
    }
}

fn render_plan_tasks(tasks: &[KernelPlanTask]) -> Result<String, String> {
    let mut rows = Vec::with_capacity(tasks.len());
    for t in tasks {
        let st = lean_task_status(&t.status)?;
        rows.push(format!(
            "  {{ id := {}, status := {st}, dependsOn := {}, hasCompletionEvidence := {}, allowedPathsNonempty := {}, verificationNonempty := {} }}",
            lean_str(&t.id),
            lean_str_list(&t.depends_on),
            lean_bool(t.has_completion_evidence),
            lean_bool(t.allowed_paths_nonempty),
            lean_bool(t.verification_nonempty),
        ));
    }
    Ok(format!("[\n{}\n]", rows.join(",\n")))
}

fn render_questions(qs: &[KernelBlockingQuestion]) -> String {
    let rows: Vec<String> = qs
        .iter()
        .map(|q| {
            format!(
                "  {{ id := {}, blocks := {} }}",
                lean_str(&q.id),
                lean_str_list(&q.blocks)
            )
        })
        .collect();
    format!("[\n{}\n]", rows.join(",\n"))
}

fn render_decisions(ds: &[KernelPathDecision]) -> String {
    let rows: Vec<String> = ds
        .iter()
        .map(|d| {
            format!(
                "  {{ insideRoot := {}, matchedAllowed := {}, matchedForbidden := {}, matchedVerifyOutput := {} }}",
                lean_bool(d.inside_root),
                lean_bool(d.matched_allowed),
                lean_bool(d.matched_forbidden),
                lean_bool(d.matched_verify_output),
            )
        })
        .collect();
    format!("[\n{}\n]", rows.join(",\n"))
}

fn render_review_items(items: &[KernelReviewItem]) -> Result<String, String> {
    let mut rows = Vec::with_capacity(items.len());
    for it in items {
        let cls = lean_review_class(&it.classification)?;
        rows.push(format!(
            "  {{ itemKey := {}, classification := {cls}, replied := {}, resolved := {}, fixVerified := {} }}",
            lean_str(&it.item_key),
            lean_bool(it.replied),
            lean_bool(it.resolved),
            lean_bool(it.fix_verified),
        ));
    }
    Ok(format!("[\n{}\n]", rows.join(",\n")))
}

/// Deterministically render a self-contained Lean 4 proof certificate module.
pub fn render_certificate(obligation: &CertObligation) -> Result<(&'static str, String), String> {
    match obligation {
        CertObligation::Plan(req) => {
            let tasks = render_plan_tasks(&req.tasks)?;
            let qs = render_questions(&req.questions);
            Ok((
                "plan",
                format!(
                    "import BirkinSpec.PlanContract\n\nopen BirkinSpec\n\ndef certTasks : List PlanTask :=\n{tasks}\n\ndef certQuestions : List BlockingQuestion :=\n{qs}\n\ntheorem certified : planValid certTasks certQuestions = true := by decide\n#print axioms certified\n"
                ),
            ))
        }
        CertObligation::PlanDispatch(req) => {
            let intent = lean_plan_intent(&req.intent)?;
            let tasks = render_plan_tasks(&req.tasks)?;
            let qs = render_questions(&req.questions);
            Ok((
                "plan_dispatch",
                format!(
                    "import BirkinSpec.PlanContract\n\nopen BirkinSpec\n\ndef certTasks : List PlanTask :=\n{tasks}\n\ndef certQuestions : List BlockingQuestion :=\n{qs}\n\ntheorem certified : canDispatchMutating {intent} certTasks certQuestions {} = true := by decide\n#print axioms certified\n",
                    lean_str(&req.task_id)
                ),
            ))
        }
        CertObligation::Scope(req) => {
            let auth = lean_path_authority(&req.authority)?;
            let decs = render_decisions(&req.decisions);
            Ok((
                "scope",
                format!(
                    "import BirkinSpec.ScopeContract\n\nopen BirkinSpec\n\ndef certDecisions : List PathDecision :=\n{decs}\n\ndef certMyWrites : List String := {}\ndef certOtherWrites : List String := {}\n\ntheorem certified : scopeAdmitted {auth} certDecisions certMyWrites certOtherWrites = true := by decide\n#print axioms certified\n",
                    lean_str_list(&req.my_writes),
                    lean_str_list(&req.other_active_writes),
                ),
            ))
        }
        CertObligation::Authority(req) => {
            let role = lean_role(&req.role)?;
            let tier = lean_tier(&req.requested_tier)?;
            let prev = lean_tier(&req.prev_tier)?;
            Ok((
                "authority",
                format!(
                    "import BirkinSpec.AuthorityContract\n\nopen BirkinSpec\n\ndef certReq : DispatchRequest :=\n  {{ role := {role}\n  , requestedTier := {tier}\n  , explicitFAuth := {}\n  , isRefusalRetry := {}\n  , prevTier := {prev}\n  , retriesAfterFirst := {}\n  , forbiddenModel := {}\n  , sameImplRuntime := {}\n  , sameImplModel := {}\n  }}\n\ntheorem certified : dispatchAdmitted certReq = true := by decide\n#print axioms certified\n",
                    lean_bool(req.explicit_f_auth),
                    lean_bool(req.is_refusal_retry),
                    req.retries_after_first,
                    lean_bool(req.forbidden_model),
                    lean_bool(req.same_impl_runtime),
                    lean_bool(req.same_impl_model),
                ),
            ))
        }
        CertObligation::Stage(req) => {
            let stage = lean_stage(&req.stage)?;
            Ok((
                "stage",
                format!(
                    "import BirkinSpec.StageAdmission\n\nopen BirkinSpec\n\ndef certEv : StageEvidence :=\n  {{ discoveredTests := {}\n  , executedTests := {}\n  , toolchainMatched := {}\n  , receiptChainOk := {}\n  , treeBoundOk := {}\n  , reviewPassed := {}\n  , sawyerStagedExact := {}\n  , sawyerExcludedClean := {}\n  , gpgSignRequired := {}\n  , gpgSigValid := {}\n  , remoteHeadMatches := {}\n  , ciPassed := {}\n  , releaseAuthorized := {}\n  }}\n\ntheorem certified : stageAdmitted {stage} certEv = true := by decide\n#print axioms certified\n",
                    req.discovered_tests,
                    req.executed_tests,
                    lean_bool(req.toolchain_matched),
                    lean_bool(req.receipt_chain_ok),
                    lean_bool(req.tree_bound_ok),
                    lean_bool(req.review_passed),
                    lean_bool(req.sawyer_staged_exact),
                    lean_bool(req.sawyer_excluded_clean),
                    lean_bool(req.gpg_sign_required),
                    lean_bool(req.gpg_sig_valid),
                    lean_bool(req.remote_head_matches),
                    lean_bool(req.ci_passed),
                    lean_bool(req.release_authorized),
                ),
            ))
        }
        CertObligation::ReviewClosure(req) => {
            let items = render_review_items(&req.items)?;
            let pred = if req.request_re_review {
                "canRequestReReview"
            } else {
                "reviewClosureValid"
            };
            Ok((
                "review_closure",
                format!(
                    "import BirkinSpec.ReviewClosure\n\nopen BirkinSpec\n\ndef certItems : List CanonicalReviewItem :=\n{items}\n\ntheorem certified : {pred} certItems = true := by decide\n#print axioms certified\n"
                ),
            ))
        }
    }
}

fn has_birkin_spec_olean(dir: &Path) -> bool {
    dir.join("BirkinSpec.olean").is_file()
        || dir.join("BirkinSpec").join("PlanContract.olean").is_file()
}

/// Resolve the prebuilt `BirkinSpec` `.olean` library directory for Mode B certification.
pub fn resolve_lean_lib_dir() -> Result<PathBuf, String> {
    if let Ok(explicit) = env::var("BIRKIN_LEAN_LIB") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            if has_birkin_spec_olean(&path) {
                return Ok(path);
            }
            return Err(format!(
                "BIRKIN_LEAN_LIB does not contain compiled BirkinSpec .olean files: {}",
                path.display()
            ));
        }
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = env::current_exe() {
        if let Ok(canon) = fs::canonicalize(&exe) {
            if let Some(dir) = canon.parent() {
                candidates.push(dir.join("share").join("birkin").join("lean"));
                if let Some(repo_dir) = dir.parent().and_then(Path::parent) {
                    candidates.push(
                        repo_dir
                            .join("lean")
                            .join(".lake")
                            .join("build")
                            .join("lib")
                            .join("lean"),
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
            .join("lib")
            .join("lean"),
    );
    if let Ok(cwd) = env::current_dir() {
        for ancestor in cwd.ancestors() {
            candidates.push(
                ancestor
                    .join("lean")
                    .join(".lake")
                    .join("build")
                    .join("lib")
                    .join("lean"),
            );
        }
    }
    candidates.push(home_dir().join(".birkin").join("lean").join("lib"));

    for cand in candidates {
        if has_birkin_spec_olean(&cand) {
            return Ok(cand);
        }
    }

    Err(
        "Compiled BirkinSpec .olean library not found. Build it with `cd lean && lake build` or set BIRKIN_LEAN_LIB."
            .into(),
    )
}

fn resolve_lean_bin() -> Result<PathBuf, String> {
    if let Ok(explicit) = env::var("BIRKIN_LEAN_BIN") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            if path.is_file() {
                return Ok(path);
            }
            return Err(format!(
                "BIRKIN_LEAN_BIN points to missing lean executable: {}",
                path.display()
            ));
        }
    }
    let name = if cfg!(windows) { "lean.exe" } else { "lean" };
    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            let cand = dir.join(name);
            if cand.is_file() {
                return Ok(cand);
            }
        }
    }
    let elan_cand = home_dir().join(".elan").join("bin").join(name);
    if elan_cand.is_file() {
        return Ok(elan_cand);
    }
    Err("Lean 4 `lean` executable not found in PATH or ~/.elan/bin; required for --certify.".into())
}

fn run_and_audit_certificate(
    contract: String,
    theorem_label: String,
    expected: &[String],
    source: &str,
    emit_proof: Option<&Path>,
) -> Result<CertificationOutcome, String> {
    let start = Instant::now();
    let proof_sha256 = sha256_hex(source.as_bytes());
    let lib_dir = resolve_lean_lib_dir()?;
    let lean_bin = resolve_lean_bin()?;

    let mut temp_guard = None;
    let cert_path: PathBuf = if let Some(dest) = emit_proof {
        if let Some(parent) = dest.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    format!("Failed creating proof directory {}: {e}", parent.display())
                })?;
            }
        }
        fs::write(dest, source)
            .map_err(|e| format!("Failed writing Lean certificate {}: {e}", dest.display()))?;
        dest.to_path_buf()
    } else {
        let tmp = tempfile::Builder::new()
            .prefix("birkin-cert-")
            .suffix(".lean")
            .tempfile()
            .map_err(|e| format!("Failed creating temporary Lean certificate: {e}"))?;
        fs::write(tmp.path(), source)
            .map_err(|e| format!("Failed writing temporary Lean certificate: {e}"))?;
        let path = tmp.path().to_path_buf();
        temp_guard = Some(tmp);
        path
    };

    let mut lean_paths = vec![lib_dir.clone()];
    if let Some(existing) = env::var_os("LEAN_PATH") {
        lean_paths.extend(env::split_paths(&existing));
    }
    let joined_path = env::join_paths(lean_paths)
        .map_err(|e| format!("Failed constructing LEAN_PATH: {e}"))?;

    let output = Command::new(&lean_bin)
        .arg(&cert_path)
        .env("LEAN_PATH", joined_path)
        .output()
        .map_err(|e| format!("Failed spawning Lean kernel {}: {e}", lean_bin.display()))?;
    drop(temp_guard);

    let elapsed_ms = start.elapsed().as_millis() as u64;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let proof_path = emit_proof.map(|p| p.to_string_lossy().into_owned());

    if !output.status.success() {
        return Ok(CertificationOutcome {
            certified: false,
            contract,
            theorem: theorem_label,
            proof_sha256,
            kernel_axioms: Vec::new(),
            elapsed_ms,
            proof_path,
            lean_lib_dir: lib_dir.to_string_lossy().into_owned(),
            detail: Some(format!("{stdout}\n{stderr}").trim().to_string()),
        });
    }

    let observed = parse_print_axioms(&stdout);
    let mut findings: Vec<ProjectFinding> = Vec::new();
    audit_axioms(expected, &observed, true, &mut findings);
    if !findings.is_empty() {
        let detail = findings
            .iter()
            .map(|f| f.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("Lean kernel axiom audit failed: {detail}"));
    }

    let mut axioms = Vec::new();
    for thm in expected {
        if let Some(list) = observed.get(thm) {
            for ax in list {
                if !axioms.contains(ax) {
                    axioms.push(ax.clone());
                }
            }
        }
    }
    Ok(CertificationOutcome {
        certified: true,
        contract,
        theorem: theorem_label,
        proof_sha256,
        kernel_axioms: axioms,
        elapsed_ms,
        proof_path,
        lean_lib_dir: lib_dir.to_string_lossy().into_owned(),
        detail: None,
    })
}

/// Emit and type-check a Mode B Lean 4 proof certificate, auditing `#print axioms`.
pub fn certify_obligation(
    obligation: &CertObligation,
    emit_proof: Option<&Path>,
) -> Result<CertificationOutcome, String> {
    let (contract, source) = render_certificate(obligation)?;
    run_and_audit_certificate(
        contract.to_string(),
        "certified".into(),
        &["certified".to_string()],
        &source,
        emit_proof,
    )
}

/// Emit and type-check a combined certificate for multiple obligations (e.g. `unit admit`
/// checking both `PlanDispatch` and `Authority`) in a single Lean 4 kernel invocation.
pub fn certify_pair(
    first: &CertObligation,
    second: &CertObligation,
    emit_proof: Option<&Path>,
) -> Result<CertificationOutcome, String> {
    let (c1, s1) = render_certificate(first)?;
    let (c2, s2) = render_certificate(second)?;
    let mut imports = Vec::new();
    let mut split_body = |src: &str, thm: &str| {
        let mut body = Vec::new();
        for line in src.lines() {
            if line.starts_with("import ") {
                if !imports.contains(&line.to_string()) {
                    imports.push(line.to_string());
                }
            } else if line != "open BirkinSpec" && !line.starts_with("#print axioms ") {
                body.push(line.replace("theorem certified ", &format!("theorem {thm} ")));
            }
        }
        body.join("\n")
    };
    let b1 = split_body(&s1, "certified_1");
    let b2 = split_body(&s2, "certified_2");
    let source = format!(
        "{}\n\nopen BirkinSpec\n\nnamespace First\n{b1}\nend First\n\nnamespace Second\n{b2}\nend Second\n\n#print axioms First.certified_1\n#print axioms Second.certified_2\n",
        imports.join("\n"),
    );
    let expected = vec![
        "First.certified_1".to_string(),
        "Second.certified_2".to_string(),
    ];
    run_and_audit_certificate(
        format!("{c1}+{c2}"),
        "First.certified_1+Second.certified_2".into(),
        &expected,
        &source,
        emit_proof,
    )
}

/// Attach `verification_mode` (`lean_kernel` or `lean_certified`) and optional certification
/// metadata to both receipt ledger metadata and CLI JSON report payloads.
pub fn attach_attestation(
    meta: &mut Map<String, Value>,
    report: &mut Value,
    cert: Option<&CertificationOutcome>,
) {
    let mode = if cert.is_some() {
        "lean_certified"
    } else {
        "lean_kernel"
    };
    meta.insert("verification_mode".into(), json!(mode));
    if let Some(c) = cert {
        meta.insert("proof_sha256".into(), json!(c.proof_sha256));
        meta.insert("kernel_axioms".into(), json!(c.kernel_axioms));
        if let Some(ref p) = c.proof_path {
            meta.insert("proof_path".into(), json!(p));
        }
    }
    if let Some(obj) = report.as_object_mut() {
        obj.insert("verification_mode".into(), json!(mode));
        if let Some(c) = cert {
            obj.insert("proof_sha256".into(), json!(c.proof_sha256));
            obj.insert("kernel_axioms".into(), json!(c.kernel_axioms));
            obj.insert("certification".into(), json!(c));
        }
    }
}
