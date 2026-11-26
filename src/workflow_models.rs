//! Strict fail-closed models for per-repository workflow contracts (`workflow:` in `.birkin/config.yaml`)
//! and structured contract inputs/outputs for plan, scope, authority, stage/Sawyer, and review closure.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const VALID_CONTRACTS: &[&str] = &[
    "plan",
    "scope",
    "authority",
    "stage",
    "sawyer",
    "review_closure",
];

pub const VALID_TEST_PARSERS: &[&str] = &[
    "cargo_test",
    "go_test",
    "pytest",
    "vitest",
    "playwright",
    "lake",
    "generic",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TestRunnerSpec {
    pub name: String,
    pub parser: String,
    #[serde(default)]
    pub require_nonzero: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSpec {
    #[serde(default)]
    pub enabled_contracts: Vec<String>,
    #[serde(default)]
    pub require_plan_receipt: bool,
    #[serde(default)]
    pub toolchain_pin_files: Vec<String>,
    #[serde(default)]
    pub exclude_whitelist_path: Option<String>,
    #[serde(default)]
    pub test_runners: Vec<TestRunnerSpec>,
    #[serde(default)]
    pub service_build_guards: Vec<String>,
}

impl WorkflowSpec {
    pub fn validate(&self) -> Result<(), String> {
        let mut seen = HashSet::new();
        for c in &self.enabled_contracts {
            if !VALID_CONTRACTS.contains(&c.as_str()) {
                return Err(format!(
                    "Unsupported workflow contract '{c}' (expected one of: {})",
                    VALID_CONTRACTS.join(", ")
                ));
            }
            if !seen.insert(c.as_str()) {
                return Err(format!("Duplicate workflow contract '{c}'"));
            }
        }
        let mut runner_names = HashSet::new();
        for r in &self.test_runners {
            if r.name.trim().is_empty() {
                return Err("workflow.test_runners[].name must be non-empty".into());
            }
            if !runner_names.insert(r.name.as_str()) {
                return Err(format!("Duplicate workflow.test_runners name '{}'", r.name));
            }
            if !VALID_TEST_PARSERS.contains(&r.parser.as_str()) {
                return Err(format!(
                    "Unsupported test parser '{}' on runner '{}'",
                    r.parser, r.name
                ));
            }
        }
        if let Some(ref wl) = self.exclude_whitelist_path {
            if wl.trim().is_empty() {
                return Err("workflow.exclude_whitelist_path must be non-empty when set".into());
            }
        }
        Ok(())
    }

    pub fn contract_enabled(&self, name: &str) -> bool {
        self.enabled_contracts.iter().any(|c| c == name)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApprovalTier {
    R,
    W,
    F,
}

impl ApprovalTier {
    pub fn rank(self) -> u8 {
        match self {
            Self::R => 0,
            Self::W => 1,
            Self::F => 2,
        }
    }

    pub fn parse_str(s: &str) -> Result<Self, String> {
        match s.trim() {
            "R" => Ok(Self::R),
            "W" => Ok(Self::W),
            "F" => Ok(Self::F),
            other => Err(format!(
                "Invalid approval tier '{other}' (expected R, W, or F)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::R => "R",
            Self::W => "W",
            Self::F => "F",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    Scope,
    Review,
    Research,
    Docs,
    Investigate,
    Implement,
    Finalize,
}

impl AgentRole {
    pub fn max_default_tier(self) -> ApprovalTier {
        match self {
            Self::Scope | Self::Review | Self::Research | Self::Docs | Self::Investigate => {
                ApprovalTier::R
            }
            Self::Implement | Self::Finalize => ApprovalTier::W,
        }
    }

    pub fn parse_str(s: &str) -> Result<Self, String> {
        match s.trim() {
            "scope" => Ok(Self::Scope),
            "review" => Ok(Self::Review),
            "research" => Ok(Self::Research),
            "docs" => Ok(Self::Docs),
            "investigate" => Ok(Self::Investigate),
            "implement" => Ok(Self::Implement),
            "finalize" => Ok(Self::Finalize),
            other => Err(format!("Invalid agent role '{other}'")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scope => "scope",
            Self::Review => "review",
            Self::Research => "research",
            Self::Docs => "docs",
            Self::Investigate => "investigate",
            Self::Implement => "implement",
            Self::Finalize => "finalize",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStage {
    Implemented,
    Verified,
    Reviewed,
    Committed,
    Pushed,
    CiPassed,
    Released,
}

impl LifecycleStage {
    pub fn parse_str(s: &str) -> Result<Self, String> {
        match s.trim() {
            "implemented" => Ok(Self::Implemented),
            "verified" => Ok(Self::Verified),
            "reviewed" => Ok(Self::Reviewed),
            "committed" => Ok(Self::Committed),
            "pushed" => Ok(Self::Pushed),
            "ci_passed" | "ci" => Ok(Self::CiPassed),
            "released" => Ok(Self::Released),
            other => Err(format!("Invalid lifecycle stage '{other}'")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Implemented => "implemented",
            Self::Verified => "verified",
            Self::Reviewed => "reviewed",
            Self::Committed => "committed",
            Self::Pushed => "pushed",
            Self::CiPassed => "ci_passed",
            Self::Released => "released",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewClassification {
    Unclassified,
    MustFix,
    AlreadyFixed,
    NotValid,
    OutOfScope,
    NeedsClarification,
}

impl ReviewClassification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unclassified => "unclassified",
            Self::MustFix => "must_fix",
            Self::AlreadyFixed => "already_fixed",
            Self::NotValid => "not_valid",
            Self::OutOfScope => "out_of_scope",
            Self::NeedsClarification => "needs_clarification",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlanVerificationSpec {
    pub method: String,
    pub expected: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlanTaskSpec {
    pub id: String,
    pub title: String,
    pub context: String,
    pub expected_behavior: String,
    pub status: String,
    pub depends_on: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub forbidden_paths: Vec<String>,
    #[serde(default)]
    pub verification_output_paths: Vec<String>,
    #[serde(default)]
    pub checkout_root: Option<String>,
    pub acceptance: Vec<String>,
    pub verification: Vec<PlanVerificationSpec>,
    pub stop_conditions: Vec<String>,
    pub owner: String,
    pub completion_evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlanQuestionSpec {
    pub id: String,
    pub question: String,
    pub blocks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlanDocument {
    pub version: u32,
    pub intent: String,
    pub outcome: String,
    pub non_goals: Vec<String>,
    pub constraints: Vec<String>,
    pub evidence: Vec<String>,
    pub questions: Vec<PlanQuestionSpec>,
    pub tasks: Vec<PlanTaskSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActiveUnitRecord {
    pub task_id: String,
    pub checkout_root: String,
    #[serde(default)]
    pub write_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DispatchManifest {
    pub role: AgentRole,
    pub requested_tier: ApprovalTier,
    #[serde(default)]
    pub explicit_f_auth: bool,
    #[serde(default)]
    pub is_refusal_retry: bool,
    #[serde(default = "default_tier_r")]
    pub prev_tier: ApprovalTier,
    #[serde(default)]
    pub retries_after_first: u32,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default)]
    pub implementer_model: Option<String>,
    #[serde(default)]
    pub implementer_runtime: Option<String>,
    #[serde(default)]
    pub forbidden_model_patterns: Vec<String>,
}

fn default_tier_r() -> ApprovalTier {
    ApprovalTier::R
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StageEvidenceInput {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SawyerContextPack {
    pub repo_root: String,
    pub target_branch: String,
    #[serde(default)]
    pub remote: Option<String>,
    #[serde(default)]
    pub target_ref: Option<String>,
    pub approved_files: Vec<String>,
    #[serde(default)]
    pub excluded_files: Vec<String>,
    #[serde(default)]
    pub expected_commit_sha: Option<String>,
    #[serde(default)]
    pub require_signed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanonicalReviewItemSpec {
    #[serde(alias = "itemKey")]
    pub item_key: String,
    pub classification: ReviewClassification,
    #[serde(default)]
    pub replied: bool,
    #[serde(default)]
    pub reply_url: Option<String>,
    #[serde(default)]
    pub resolved: bool,
    #[serde(default)]
    pub fix_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReviewStateDocument {
    #[serde(alias = "canonicalReviewItems")]
    pub canonical_review_items: Vec<CanonicalReviewItemSpec>,
    #[serde(default)]
    pub request_re_review: bool,
}
