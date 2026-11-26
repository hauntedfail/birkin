//! Strict fail-closed models for per-repository formal proof obligations (`proofs:` in `.birkin/config.yaml`).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

fn default_true() -> bool {
    true
}

fn default_proof_timeout() -> u64 {
    120
}

fn default_lean_dir() -> String {
    ".".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StateTransitionSpec {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenTransitionSpec {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReversiblePairSpec {
    pub forward: String,
    pub backward: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StateMachineSpec {
    pub id: String,
    pub states: Vec<String>,
    pub initial: String,
    #[serde(default)]
    pub terminal: Vec<String>,
    #[serde(default)]
    pub transitions: Vec<StateTransitionSpec>,
    #[serde(default)]
    pub forbidden_transitions: Vec<ForbiddenTransitionSpec>,
    #[serde(default)]
    pub reversible_pairs: Vec<ReversiblePairSpec>,
    #[serde(default = "default_true")]
    pub require_terminal_sink: bool,
    #[serde(default = "default_true")]
    pub require_all_states_reachable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyProofSpec {
    pub id: String,
    #[serde(default)]
    pub deny_patterns: Vec<String>,
    #[serde(default)]
    pub allow_patterns: Vec<String>,
    #[serde(default)]
    pub must_deny: Vec<String>,
    #[serde(default)]
    pub must_allow: Vec<String>,
    #[serde(default = "default_true")]
    pub require_deny_dominance: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LeanProjectSpec {
    pub name: String,
    #[serde(default = "default_lean_dir")]
    pub dir: String,
    #[serde(default)]
    pub modules: Vec<String>,
    #[serde(default)]
    pub theorems: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProofsSpec {
    #[serde(default)]
    pub emit_path: Option<String>,
    #[serde(default = "default_proof_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_true")]
    pub require_zero_sorry: bool,
    #[serde(default = "default_true")]
    pub require_standard_axioms_only: bool,
    #[serde(default = "default_true")]
    pub prove_architecture: bool,
    #[serde(default)]
    pub state_machines: Vec<StateMachineSpec>,
    #[serde(default)]
    pub policies: Vec<PolicyProofSpec>,
    #[serde(default)]
    pub lean_projects: Vec<LeanProjectSpec>,
}

impl Default for ProofsSpec {
    fn default() -> Self {
        Self {
            emit_path: None,
            timeout_seconds: default_proof_timeout(),
            require_zero_sorry: true,
            require_standard_axioms_only: true,
            prove_architecture: true,
            state_machines: Vec::new(),
            policies: Vec::new(),
            lean_projects: Vec::new(),
        }
    }
}

impl ProofsSpec {
    /// Fail-closed validation of declarative proof obligations.
    pub fn validate(&self) -> Result<(), String> {
        if self.timeout_seconds == 0 {
            return Err("proofs.timeout_seconds must be a positive integer".into());
        }

        let mut sm_ids: HashSet<&str> = HashSet::new();
        for sm in &self.state_machines {
            let id = sm.id.trim();
            if id.is_empty() {
                return Err("proofs.state_machines[].id must be non-empty".into());
            }
            if !sm_ids.insert(id) {
                return Err(format!("Duplicate proofs.state_machines id '{id}'"));
            }
            if sm.states.is_empty() {
                return Err(format!("State machine '{id}' must declare at least one state"));
            }
            let mut seen_states: HashSet<&str> = HashSet::new();
            for st in &sm.states {
                if st.trim().is_empty() {
                    return Err(format!("State machine '{id}' contains an empty state name"));
                }
                if !seen_states.insert(st.as_str()) {
                    return Err(format!("State machine '{id}' declares duplicate state '{st}'"));
                }
            }
            if sm.initial.trim().is_empty() {
                return Err(format!("State machine '{id}' must declare a non-empty initial state"));
            }
            for pair in &sm.reversible_pairs {
                if pair.forward.trim().is_empty() || pair.backward.trim().is_empty() {
                    return Err(format!(
                        "State machine '{id}' reversible_pairs require non-empty forward and backward labels"
                    ));
                }
            }
        }

        let mut pol_ids: HashSet<&str> = HashSet::new();
        for pol in &self.policies {
            let id = pol.id.trim();
            if id.is_empty() {
                return Err("proofs.policies[].id must be non-empty".into());
            }
            if !pol_ids.insert(id) {
                return Err(format!("Duplicate proofs.policies id '{id}'"));
            }
        }

        let mut lp_names: HashSet<&str> = HashSet::new();
        for lp in &self.lean_projects {
            let name = lp.name.trim();
            if name.is_empty() {
                return Err("proofs.lean_projects[].name must be non-empty".into());
            }
            if !lp_names.insert(name) {
                return Err(format!("Duplicate proofs.lean_projects name '{name}'"));
            }
            if lp.dir.trim().is_empty() {
                return Err(format!("Lean project '{name}' must declare a non-empty dir"));
            }
        }

        Ok(())
    }
}
