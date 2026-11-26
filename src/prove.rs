//! Formal proof orchestration engine for per-repository invariants (`birkin prove`).
//!
//! Extracts repository import-graph facts, compiles `.birkin/config.yaml` obligations to Lean 4
//! via `prove_lean`, verifies them with Lean's kernel, and audits custom Lean projects via `prove_audit`.

use crate::constants::{combine_exit_codes, EXIT_PASS, EXIT_STATIC, EXIT_TOOL_ERROR};
use crate::glob::{fnmatch, matches_any};
use crate::imports_parser::{detect_go_module, extract_imports_for_file};
use crate::project_models::{LayerSpec, ProjectFinding, ProjectSpec};
use crate::prove_audit::{
    audit_axioms, parse_print_axioms, run_lean_process, summarize_lean_errors, verify_lean_project,
    ProcResult,
};
use crate::prove_lean::{generate_lean_obligation, LayerEdgeFact, ScopedImportFact};
use crate::sensors::collect_target_files;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tempfile::Builder;

const CODE_EXTENSIONS: &[&str] = &[
    ".py", ".go", ".rs", ".lean", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
];

#[derive(Debug, Clone)]
pub struct ProveOutcome {
    pub exit_code: i32,
    pub findings: Vec<ProjectFinding>,
    pub theorems_proved: Vec<String>,
    pub axioms_audited: BTreeMap<String, Vec<String>>,
    pub emitted_path: Option<String>,
    pub architecture_dag_proved: bool,
    pub total_import_edges: usize,
    pub layer_edges_proved: usize,
    pub forbidden_imports_proved: usize,
    pub state_machine_ids: Vec<String>,
    pub policy_ids: Vec<String>,
    pub custom_projects: Vec<Value>,
    pub files_checked: Vec<String>,
    pub duration_ms: u128,
}

fn rel_posix(path: &Path, root: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    Some(
        rel.components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/"),
    )
}

fn layer_for_path<'a>(rel: &str, layers: &'a [LayerSpec]) -> Option<&'a LayerSpec> {
    layers.iter().find(|l| matches_any(rel, &l.paths))
}

/// Extract concrete import-graph facts plus actionable counterexample diagnostics.
pub fn extract_codebase_facts(
    repo_root: &Path,
    spec: &ProjectSpec,
) -> (
    Vec<LayerEdgeFact>,
    Vec<ScopedImportFact>,
    Vec<String>,
    usize,
    Vec<ProjectFinding>,
) {
    let resolved_root = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let targets = collect_target_files(&resolved_root, spec, None);
    let go_mod = detect_go_module(&resolved_root);

    let mut layer_edges = Vec::new();
    let mut scoped_imports = Vec::new();
    let mut checked = Vec::new();
    let mut counterexamples = Vec::new();
    let mut total_edges = 0usize;

    for path in targets {
        let Some(rel) = rel_posix(&path, &resolved_root) else {
            continue;
        };
        checked.push(rel.clone());
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| format!(".{}", s.to_lowercase()))
            .unwrap_or_default();
        if !CODE_EXTENSIONS.contains(&ext.as_str()) {
            continue;
        }
        let edges = extract_imports_for_file(&path, &resolved_root, go_mod.as_deref());
        total_edges += edges.len();
        let src_layer = layer_for_path(&rel, &spec.architecture.layers);

        for edge in edges {
            if let (Some(sl), Some(ref dst_rel)) = (src_layer, &edge.resolved_path) {
                if let Some(dl) = layer_for_path(dst_rel, &spec.architecture.layers) {
                    layer_edges.push(LayerEdgeFact {
                        src_layer: sl.name.clone(),
                        dst_layer: dl.name.clone(),
                    });
                    if dl.name != sl.name
                        && !sl.allowed_dependencies.iter().any(|a| a == &dl.name)
                    {
                        counterexamples.push(ProjectFinding {
                            rule: "PROOF_ARCH_LAYER_VIOLATION".into(),
                            category: "proof".into(),
                            severity: "error".into(),
                            file: Some(rel.clone()),
                            line: Some(edge.line),
                            message: format!(
                                "Layer '{}' ({rel}) imports layer '{}' ({dst_rel}) via `{}`.",
                                sl.name, dl.name, edge.raw
                            ),
                            remediation: if sl.remediation.is_empty() {
                                format!("Remove disallowed cross-layer import from '{}'.", sl.name)
                            } else {
                                sl.remediation.clone()
                            },
                            details: BTreeMap::new(),
                        });
                    }
                }
            }

            for frule in &spec.architecture.forbidden_imports {
                if !matches_any(&rel, &frule.from_globs) {
                    continue;
                }
                scoped_imports.push(ScopedImportFact {
                    rule_id: frule.id.clone(),
                    raw_import: edge.raw.clone(),
                    resolved_path: edge.resolved_path.clone(),
                });
                let hit = frule.forbid_patterns.iter().any(|pat| {
                    fnmatch(&edge.raw, pat)
                        || edge
                            .resolved_path
                            .as_deref()
                            .map(|rp| fnmatch(rp, pat))
                            .unwrap_or(false)
                });
                if hit {
                    counterexamples.push(ProjectFinding {
                        rule: format!("PROOF_FORBIDDEN_IMPORT:{}", frule.id),
                        category: "proof".into(),
                        severity: "error".into(),
                        file: Some(rel.clone()),
                        line: Some(edge.line),
                        message: format!("{} (found import `{}`)", frule.message, edge.raw),
                        remediation: frule.remediation.clone(),
                        details: BTreeMap::new(),
                    });
                }
            }
        }
    }

    (
        layer_edges,
        scoped_imports,
        checked,
        total_edges,
        counterexamples,
    )
}

fn write_obligation_file(
    resolved_root: &Path,
    spec: &ProjectSpec,
    emit_override: Option<&Path>,
    source: &str,
) -> Result<(PathBuf, Option<String>, Option<tempfile::NamedTempFile>), Box<ProjectFinding>> {
    let configured_emit: Option<PathBuf> = emit_override
        .map(Path::to_path_buf)
        .or_else(|| spec.proofs.emit_path.as_ref().map(|p| resolved_root.join(p)));

    if let Some(target) = configured_emit {
        if let Some(parent) = target.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&target, source).map_err(|err| {
            Box::new(ProjectFinding {
                rule: "PROOF_EMIT_IO_ERROR".into(),
                category: "proof".into(),
                severity: "error".into(),
                file: Some(target.to_string_lossy().into_owned()),
                line: None,
                message: format!("Failed writing generated Lean obligation: {err}"),
                remediation: "Check permissions for --emit or proofs.emit_path.".into(),
                details: BTreeMap::new(),
            })
        })?;
        let display = target.to_string_lossy().into_owned();
        return Ok((target, Some(display), None));
    }

    let mut tf = Builder::new()
        .prefix("birkin-proof-")
        .suffix(".lean")
        .tempfile()
        .map_err(|err| {
            Box::new(ProjectFinding {
                rule: "PROOF_EMIT_IO_ERROR".into(),
                category: "proof".into(),
                severity: "error".into(),
                file: None,
                line: None,
                message: format!("Failed creating temp Lean file: {err}"),
                remediation: "Check temporary directory permissions.".into(),
                details: BTreeMap::new(),
            })
        })?;
    tf.write_all(source.as_bytes()).map_err(|err| {
        Box::new(ProjectFinding {
            rule: "PROOF_EMIT_IO_ERROR".into(),
            category: "proof".into(),
            severity: "error".into(),
            file: None,
            line: None,
            message: format!("Failed writing temp Lean file: {err}"),
            remediation: "Check temporary directory permissions.".into(),
            details: BTreeMap::new(),
        })
    })?;
    let p = tf.path().to_path_buf();
    Ok((p, None, Some(tf)))
}

/// Run all configured Lean 4 proofs for `repo_root` fail-closed.
pub fn run_prove(
    repo_root: &Path,
    spec: &ProjectSpec,
    emit_override: Option<&Path>,
    skip_lean_projects: bool,
) -> ProveOutcome {
    let t0 = Instant::now();
    let resolved_root = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let (layer_edges, scoped_imports, files_checked, total_import_edges, counterexamples) =
        extract_codebase_facts(&resolved_root, spec);

    let has_generated = (spec.proofs.prove_architecture
        && (!spec.architecture.layers.is_empty()
            || !spec.architecture.forbidden_imports.is_empty()))
        || !spec.proofs.state_machines.is_empty()
        || !spec.proofs.policies.is_empty();
    let has_custom = !skip_lean_projects && !spec.proofs.lean_projects.is_empty();

    if !has_generated && !has_custom {
        return ProveOutcome {
            exit_code: EXIT_STATIC,
            findings: vec![ProjectFinding {
                rule: "PROOF_NO_OBLIGATIONS".into(),
                category: "proof".into(),
                severity: "error".into(),
                file: None,
                line: None,
                message: "No proof obligations declared in .birkin/config.yaml.".into(),
                remediation: "Declare architecture.layers, forbidden_imports, proofs.state_machines, proofs.policies, or proofs.lean_projects.".into(),
                details: BTreeMap::new(),
            }],
            theorems_proved: Vec::new(),
            axioms_audited: BTreeMap::new(),
            emitted_path: None,
            architecture_dag_proved: false,
            total_import_edges,
            layer_edges_proved: 0,
            forbidden_imports_proved: 0,
            state_machine_ids: Vec::new(),
            policy_ids: Vec::new(),
            custom_projects: Vec::new(),
            files_checked,
            duration_ms: t0.elapsed().as_millis(),
        };
    }

    let mut findings = counterexamples;
    let mut codes = Vec::new();
    let mut theorems_proved = Vec::new();
    let mut axioms_audited = BTreeMap::new();
    let mut emitted_path: Option<String> = None;
    let mut architecture_dag_proved = false;
    let mut layer_edges_proved = 0usize;
    let mut forbidden_imports_proved = 0usize;
    let mut state_machine_ids = Vec::new();
    let mut policy_ids = Vec::new();

    if has_generated {
        match generate_lean_obligation(spec, &layer_edges, &scoped_imports) {
            Err(dag_findings) => {
                findings.extend(dag_findings);
                codes.push(EXIT_STATIC);
            }
            Ok(ob) => {
                architecture_dag_proved = ob.architecture_dag_proved;
                layer_edges_proved = ob.layer_edges_proved;
                forbidden_imports_proved = ob.forbidden_imports_proved;
                state_machine_ids = ob.state_machine_ids.clone();
                policy_ids = ob.policy_ids.clone();

                match write_obligation_file(&resolved_root, spec, emit_override, &ob.source) {
                    Err(io_finding) => {
                        findings.push(*io_finding);
                        codes.push(EXIT_TOOL_ERROR);
                    }
                    Ok((lean_path, emitted, _tmp_guard)) => {
                        emitted_path = emitted;
                        let arg = lean_path.to_string_lossy().into_owned();
                        match run_lean_process(
                            "lean",
                            &[&arg],
                            &resolved_root,
                            None,
                            spec.proofs.timeout_seconds,
                        ) {
                            ProcResult::Finished {
                                ok: true, stdout, ..
                            } => {
                                let parsed = parse_print_axioms(&stdout);
                                audit_axioms(
                                    &ob.theorems,
                                    &parsed,
                                    spec.proofs.require_standard_axioms_only,
                                    &mut findings,
                                );
                                axioms_audited.extend(parsed);
                                theorems_proved.extend(ob.theorems);
                                codes.push(EXIT_PASS);
                            }
                            ProcResult::Finished {
                                code: ec,
                                stdout,
                                stderr,
                                ..
                            } => {
                                codes.push(EXIT_STATIC);
                                findings.push(ProjectFinding {
                                    rule: "PROOF_KERNEL_REJECTED".into(),
                                    category: "proof".into(),
                                    severity: "error".into(),
                                    file: emitted_path.clone(),
                                    line: None,
                                    message: format!(
                                        "Lean 4 kernel rejected proof obligation (exit {ec}): {}",
                                        summarize_lean_errors(&stdout, &stderr, 500)
                                    ),
                                    remediation: "Fix the violated architectural, state-machine, or policy invariant and re-run `birkin prove`.".into(),
                                    details: BTreeMap::new(),
                                });
                            }
                            ProcResult::TimedOut { .. } => {
                                codes.push(EXIT_STATIC);
                                findings.push(ProjectFinding {
                                    rule: "PROOF_LEAN_TIMEOUT".into(),
                                    category: "proof".into(),
                                    severity: "error".into(),
                                    file: emitted_path.clone(),
                                    line: None,
                                    message: format!(
                                        "Lean 4 kernel verification timed out after {}s.",
                                        spec.proofs.timeout_seconds
                                    ),
                                    remediation: "Raise proofs.timeout_seconds or simplify large rule sets.".into(),
                                    details: BTreeMap::new(),
                                });
                            }
                            ProcResult::NotFound(msg) | ProcResult::SpawnError(msg) => {
                                codes.push(EXIT_TOOL_ERROR);
                                findings.push(ProjectFinding {
                                    rule: "PROOF_LEAN_TOOLCHAIN_MISSING".into(),
                                    category: "proof".into(),
                                    severity: "error".into(),
                                    file: None,
                                    line: None,
                                    message: msg,
                                    remediation: "Install Lean 4 via `elan` so `lean` is available on PATH.".into(),
                                    details: BTreeMap::new(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    let mut custom_projects = Vec::new();
    if has_custom {
        for lp in &spec.proofs.lean_projects {
            let (c, pf, meta) = verify_lean_project(
                &resolved_root,
                lp,
                spec,
                &mut axioms_audited,
                &mut theorems_proved,
            );
            codes.push(c);
            findings.extend(pf);
            custom_projects.push(meta);
        }
    }

    if findings.iter().any(|f| f.severity == "error") {
        codes.push(EXIT_STATIC);
    }
    let exit_code = combine_exit_codes(&codes);

    ProveOutcome {
        exit_code,
        findings,
        theorems_proved,
        axioms_audited,
        emitted_path,
        architecture_dag_proved,
        total_import_edges,
        layer_edges_proved,
        forbidden_imports_proved,
        state_machine_ids,
        policy_ids,
        custom_projects,
        files_checked,
        duration_ms: t0.elapsed().as_millis(),
    }
}
