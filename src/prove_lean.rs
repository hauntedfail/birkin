//! Pure Lean 4 formal proof-obligation compiler for per-repository invariants.
//!
//! Compiles `.birkin/config.yaml` architecture layers, extracted import-graph facts,
//! declarative state machines, and boundary policies into a self-contained Lean 4 module
//! verified strictly by Lean's kernel (zero `sorry`, zero `native_decide`, zero custom axioms).

use crate::project_models::{LayerSpec, ProjectFinding, ProjectSpec};
use crate::proof_models::{PolicyProofSpec, StateMachineSpec};
use std::collections::{BTreeMap, BTreeSet};

const LEAN_PRELUDE: &str = include_str!("prove_prelude.lean");

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LayerEdgeFact {
    pub src_layer: String,
    pub dst_layer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScopedImportFact {
    pub rule_id: String,
    pub raw_import: String,
    pub resolved_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GeneratedObligation {
    pub source: String,
    pub theorems: Vec<String>,
    pub architecture_dag_proved: bool,
    pub layer_edges_proved: usize,
    pub forbidden_imports_proved: usize,
    pub state_machine_ids: Vec<String>,
    pub policy_ids: Vec<String>,
}

/// Compute a strict topological rank witness where every declared dependency `d` of `r`
/// satisfies `rank[d] < rank[r]`. Fails closed if any cycle exists.
pub fn compute_layer_ranks(layers: &[LayerSpec]) -> Result<BTreeMap<String, usize>, Vec<String>> {
    let mut nodes: BTreeSet<String> = BTreeSet::new();
    let mut edges: BTreeSet<(String, String)> = BTreeSet::new();

    for layer in layers {
        nodes.insert(layer.name.clone());
        for dep in &layer.allowed_dependencies {
            if dep == &layer.name {
                return Err(vec![format!("{} -> {}", layer.name, dep)]);
            }
            nodes.insert(dep.clone());
            edges.insert((dep.clone(), layer.name.clone()));
        }
    }

    let mut in_deg: BTreeMap<String, usize> = nodes.iter().map(|n| (n.clone(), 0)).collect();
    let mut adj: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (u, v) in &edges {
        *in_deg.entry(v.clone()).or_insert(0) += 1;
        adj.entry(u.clone()).or_default().push(v.clone());
    }

    let mut ready: BTreeSet<String> = in_deg
        .iter()
        .filter_map(|(k, &deg)| if deg == 0 { Some(k.clone()) } else { None })
        .collect();

    let mut ranks: BTreeMap<String, usize> = BTreeMap::new();
    let mut next_rank = 0usize;

    while let Some(u) = ready.pop_first() {
        ranks.insert(u.clone(), next_rank);
        next_rank += 1;
        if let Some(children) = adj.get(&u) {
            for v in children {
                if let Some(d) = in_deg.get_mut(v) {
                    *d -= 1;
                    if *d == 0 {
                        ready.insert(v.clone());
                    }
                }
            }
        }
    }

    if ranks.len() != nodes.len() {
        let cyclic: Vec<String> = nodes
            .into_iter()
            .filter(|n| !ranks.contains_key(n))
            .collect();
        return Err(cyclic);
    }

    Ok(ranks)
}

pub fn escape_lean_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn sanitize_lean_ident(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        out.insert(0, 'p');
    }
    out
}

fn lean_str_list(items: &[String]) -> String {
    if items.is_empty() {
        return "[]".into();
    }
    let inner: Vec<String> = items.iter().map(|s| escape_lean_str(s)).collect();
    format!("[{}]", inner.join(", "))
}

fn emit_state_machine(sm: &StateMachineSpec, out: &mut String, theorems: &mut Vec<String>) {
    let id = sanitize_lean_ident(&sm.id);
    let transitions: Vec<String> = sm
        .transitions
        .iter()
        .map(|t| {
            format!(
                "{{ src := {}, dst := {}, label := {} }}",
                escape_lean_str(&t.from),
                escape_lean_str(&t.to),
                escape_lean_str(&t.label)
            )
        })
        .collect();
    let forbidden: Vec<String> = sm
        .forbidden_transitions
        .iter()
        .map(|f| format!("({}, {})", escape_lean_str(&f.from), escape_lean_str(&f.to)))
        .collect();
    let reversible: Vec<String> = sm
        .reversible_pairs
        .iter()
        .map(|p| {
            format!(
                "({}, {})",
                escape_lean_str(&p.forward),
                escape_lean_str(&p.backward)
            )
        })
        .collect();

    out.push_str(&format!(
        "\ndef sm_{id} : StateMachine :=\n  {{ states := {}\n  , initial := {}\n  , terminal := {}\n  , transitions := [{}]\n  , forbidden := [{}]\n  , reversible := [{}]\n  }}\n",
        lean_str_list(&sm.states),
        escape_lean_str(&sm.initial),
        lean_str_list(&sm.terminal),
        transitions.join(", "),
        forbidden.join(", "),
        reversible.join(", "),
    ));

    let thm_wf = format!("sm_{id}_well_formed");
    out.push_str(&format!(
        "theorem {thm_wf} : smWellFormedBool sm_{id} = true := by decide\n"
    ));
    theorems.push(format!("BirkinProof.{thm_wf}"));

    if !sm.forbidden_transitions.is_empty() {
        let thm_forb = format!("sm_{id}_no_forbidden_transitions");
        out.push_str(&format!(
            "theorem {thm_forb} : ∀ t ∈ sm_{id}.transitions, (t.src, t.dst) ∉ sm_{id}.forbidden :=\n  smNoForbiddenBool_sound (by decide)\n"
        ));
        theorems.push(format!("BirkinProof.{thm_forb}"));
    }

    if sm.require_terminal_sink && !sm.terminal.is_empty() {
        let thm_sink = format!("sm_{id}_terminal_sink");
        out.push_str(&format!(
            "theorem {thm_sink} : ∀ s ∈ sm_{id}.terminal, ∀ t ∈ sm_{id}.transitions, t.src ≠ s :=\n  smTerminalSinkBool_sound (by decide)\n"
        ));
        theorems.push(format!("BirkinProof.{thm_sink}"));
    }

    if sm.require_all_states_reachable {
        let thm_reach = format!("sm_{id}_all_states_reachable");
        out.push_str(&format!(
            "theorem {thm_reach} : ∀ s ∈ sm_{id}.states, SmReachable sm_{id} sm_{id}.initial s :=\n  smAllReachableBool_sound (by decide)\n"
        ));
        theorems.push(format!("BirkinProof.{thm_reach}"));
    }

    if !sm.reversible_pairs.is_empty() {
        let thm_rev = format!("sm_{id}_reversible_pairs");
        out.push_str(&format!(
            "theorem {thm_rev} : ∀ pair ∈ sm_{id}.reversible, ∀ t ∈ sm_{id}.transitions, t.label = pair.1 →\n    (∃ r ∈ sm_{id}.transitions, r.label = pair.2 ∧ r.src = t.dst ∧ r.dst = t.src) ∧\n    (∀ r ∈ sm_{id}.transitions, r.label = pair.2 → r.src = t.dst → r.dst = t.src) :=\n  smReversibleBool_sound (by decide)\n"
        ));
        theorems.push(format!("BirkinProof.{thm_rev}"));
    }
}

fn emit_policy(pol: &PolicyProofSpec, out: &mut String, theorems: &mut Vec<String>) {
    let id = sanitize_lean_ident(&pol.id);
    out.push_str(&format!(
        "\ndef pol_{id}_deny : List String := {}\ndef pol_{id}_allow : List String := {}\n",
        lean_str_list(&pol.deny_patterns),
        lean_str_list(&pol.allow_patterns),
    ));

    if pol.require_deny_dominance {
        let thm_dom = format!("pol_{id}_deny_dominates");
        out.push_str(&format!(
            "theorem {thm_dom} (x : String) (h : matchesAnyGlob pol_{id}_deny x = true) :\n    policyAllowed pol_{id}_deny pol_{id}_allow x = false :=\n  policy_deny_dominates pol_{id}_deny pol_{id}_allow x h\n"
        ));
        theorems.push(format!("BirkinProof.{thm_dom}"));

        let thm_unl = format!("pol_{id}_unlisted_denied");
        out.push_str(&format!(
            "theorem {thm_unl} (x : String) (h : matchesAnyGlob pol_{id}_allow x = false) :\n    policyAllowed pol_{id}_deny pol_{id}_allow x = false :=\n  policy_unlisted_denied pol_{id}_deny pol_{id}_allow x h\n"
        ));
        theorems.push(format!("BirkinProof.{thm_unl}"));
    }

    if !pol.must_deny.is_empty() {
        let thm_md = format!("pol_{id}_must_deny");
        out.push_str(&format!(
            "def pol_{id}_mustDeny : List String := {}\ntheorem {thm_md} : ∀ x ∈ pol_{id}_mustDeny, policyAllowed pol_{id}_deny pol_{id}_allow x = false :=\n  list_all_policy_false (by decide)\n",
            lean_str_list(&pol.must_deny),
        ));
        theorems.push(format!("BirkinProof.{thm_md}"));
    }

    if !pol.must_allow.is_empty() {
        let thm_ma = format!("pol_{id}_must_allow");
        out.push_str(&format!(
            "def pol_{id}_mustAllow : List String := {}\ntheorem {thm_ma} : ∀ x ∈ pol_{id}_mustAllow, policyAllowed pol_{id}_deny pol_{id}_allow x = true :=\n  list_all_policy_true (by decide)\n",
            lean_str_list(&pol.must_allow),
        ));
        theorems.push(format!("BirkinProof.{thm_ma}"));
    }
}

/// Compile repository proof obligations into a self-contained Lean 4 source file.
pub fn generate_lean_obligation(
    spec: &ProjectSpec,
    layer_edges: &[LayerEdgeFact],
    scoped_imports: &[ScopedImportFact],
) -> Result<GeneratedObligation, Vec<ProjectFinding>> {
    let mut out = String::from(LEAN_PRELUDE);
    let mut theorems: Vec<String> = Vec::new();
    let mut architecture_dag_proved = false;
    let mut layer_edges_proved = 0usize;
    let mut forbidden_imports_proved = 0usize;

    if spec.proofs.prove_architecture && !spec.architecture.layers.is_empty() {
        let ranks = compute_layer_ranks(&spec.architecture.layers).map_err(|cyclic| {
            vec![ProjectFinding {
                rule: "PROOF_ARCH_DAG_CYCLE".into(),
                category: "proof".into(),
                severity: "error".into(),
                file: None,
                line: None,
                message: format!(
                    "Cannot prove architecture DAG acyclicity: cycle involving [{}].",
                    cyclic.join(", ")
                ),
                remediation: "Break cyclic allowed_dependencies entries in architecture.layers."
                    .into(),
                details: BTreeMap::new(),
            }]
        })?;

        let rules_lean: Vec<String> = spec
            .architecture
            .layers
            .iter()
            .map(|l| {
                format!(
                    "{{ name := {}, allowedDeps := {} }}",
                    escape_lean_str(&l.name),
                    lean_str_list(&l.allowed_dependencies)
                )
            })
            .collect();
        out.push_str(&format!(
            "\ndef repoLayers : List LayerRule := [{}]\n",
            rules_lean.join(", ")
        ));

        let fallback_rank = ranks.len();
        out.push_str("def repoLayerRank : String → Nat\n");
        for (name, rank) in &ranks {
            out.push_str(&format!("  | {} => {rank}\n", escape_lean_str(name)));
        }
        out.push_str(&format!("  | _ => {fallback_rank}\n"));

        out.push_str(
            "theorem repo_dag_acyclic : ∀ a : String, ¬ Reachable repoLayers a a :=\n  validRankOrder_acyclic (validRankOrderBool_sound repoLayerRank (by decide))\n",
        );
        theorems.push("BirkinProof.repo_dag_acyclic".into());
        architecture_dag_proved = true;

        let unique_edges: BTreeSet<&LayerEdgeFact> = layer_edges.iter().collect();
        layer_edges_proved = unique_edges.len();
        let edges_lean: Vec<String> = unique_edges
            .into_iter()
            .map(|e| {
                format!(
                    "{{ srcLayer := {}, dstLayer := {} }}",
                    escape_lean_str(&e.src_layer),
                    escape_lean_str(&e.dst_layer)
                )
            })
            .collect();
        out.push_str(&format!(
            "def repoLayerEdges : List LayerEdgeFact := [{}]\n",
            edges_lean.join(", ")
        ));
        out.push_str(
            "theorem repo_imports_respect_layers : ∀ e ∈ repoLayerEdges, edgeAllowed repoLayers e.srcLayer e.dstLayer = true :=\n  allEdgesRespectLayers_sound (by decide)\n",
        );
        theorems.push("BirkinProof.repo_imports_respect_layers".into());
    }

    if spec.proofs.prove_architecture && !spec.architecture.forbidden_imports.is_empty() {
        let frules: Vec<String> = spec
            .architecture
            .forbidden_imports
            .iter()
            .map(|r| {
                format!(
                    "{{ id := {}, forbidPatterns := {} }}",
                    escape_lean_str(&r.id),
                    lean_str_list(&r.forbid_patterns)
                )
            })
            .collect();
        let unique_imps: BTreeSet<&ScopedImportFact> = scoped_imports.iter().collect();
        forbidden_imports_proved = unique_imps.len();
        let imps_lean: Vec<String> = unique_imps
            .into_iter()
            .map(|imp| {
                let res = match &imp.resolved_path {
                    Some(p) => format!("some {}", escape_lean_str(p)),
                    None => "none".into(),
                };
                format!(
                    "{{ ruleId := {}, rawImport := {}, resolvedPath := {res} }}",
                    escape_lean_str(&imp.rule_id),
                    escape_lean_str(&imp.raw_import)
                )
            })
            .collect();
        out.push_str(&format!(
            "\ndef repoForbiddenRules : List ForbiddenRuleFact := [{}]\ndef repoScopedImports : List ScopedImportFact := [{}]\n",
            frules.join(", "),
            imps_lean.join(", "),
        ));
        out.push_str(
            "theorem repo_no_forbidden_imports : ∀ imp ∈ repoScopedImports, forbiddenHit repoForbiddenRules imp = false :=\n  noForbiddenImportsBool_sound (by decide)\n",
        );
        theorems.push("BirkinProof.repo_no_forbidden_imports".into());
    }

    let mut state_machine_ids = Vec::new();
    for sm in &spec.proofs.state_machines {
        emit_state_machine(sm, &mut out, &mut theorems);
        state_machine_ids.push(sm.id.clone());
    }

    let mut policy_ids = Vec::new();
    for pol in &spec.proofs.policies {
        emit_policy(pol, &mut out, &mut theorems);
        policy_ids.push(pol.id.clone());
    }

    out.push('\n');
    for thm in &theorems {
        let short = thm.strip_prefix("BirkinProof.").unwrap_or(thm);
        out.push_str(&format!("#print axioms {short}\n"));
    }
    out.push_str("\nend BirkinProof\n");

    Ok(GeneratedObligation {
        source: out,
        theorems,
        architecture_dag_proved,
        layer_edges_proved,
        forbidden_imports_proved,
        state_machine_ids,
        policy_ids,
    })
}
