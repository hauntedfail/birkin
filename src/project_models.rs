//! Strict fail-closed models for per-repository Birkin specifications (.birkin/config.yaml).

use crate::proof_models::ProofsSpec;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

pub const SPEC_REL_PATHS: [&str; 3] = [".birkin/config.yaml", ".birkin/config.yml", "birkin.yaml"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProjectFinding {
    pub rule: String,
    pub category: String,
    #[serde(default = "default_error")]
    pub severity: String,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub line: Option<usize>,
    pub message: String,
    pub remediation: String,
    #[serde(default)]
    pub details: BTreeMap<String, Value>,
}

fn default_error() -> String { "error".into() }
fn default_true() -> bool { true }
fn default_version() -> u32 { 1 }
fn default_entry_docs() -> Vec<String> { vec!["AGENTS.md".into()] }
fn default_max_entry_doc_lines() -> usize { 180 }
fn default_max_review_age_days() -> u64 { 90 }
fn default_max_file_lines() -> usize { 600 }
fn default_verify_kind() -> String { "test".into() }
fn default_verify_timeout() -> u64 { 300 }
fn default_all_globs() -> Vec<String> { vec!["**/*".into()] }
fn default_secret_exempt() -> Vec<String> { vec!["tests/**".into(), "**/*_test.*".into(), "**/*.test.*".into()] }
fn default_threshold() -> f64 { 0.75 }
fn default_advisory() -> String { "advisory".into() }
fn default_semantic_url() -> String { "http://127.0.0.1:3425/v1".into() }
fn default_semantic_key_env() -> String { "BIRKIN_SEMANTIC_API_KEY".into() }
fn default_semantic_model() -> String { "auto/gemini-3.8-flash".into() }
fn default_semantic_timeout() -> f64 { 15.0 }
fn default_max_diff_chars() -> usize { 24000 }
fn default_rules_dir() -> String { ".birkin/rules".into() }
fn default_thrash_threshold() -> usize { 3 }
fn default_thrash_window_minutes() -> i64 { 30 }
fn default_stale_min_runs() -> usize { 20 }

fn default_exclude_globs() -> Vec<String> {
    [
        ".git/**", "**/.git/**", "**/.venv/**", "**/venv/**", "**/node_modules/**",
        "**/target/**", "**/.lake/**", "**/dist/**", "**/build/**", "**/__pycache__/**",
        "**/*.pyc", "**/.pytest_cache/**", "**/.ruff_cache/**", "**/*.egg-info/**",
        "**/.birkin/ledger/**",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProjectIdentity {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default = "default_exclude_globs")]
    pub exclude_globs: Vec<String>,
}

impl Default for ProjectIdentity {
    fn default() -> Self {
        Self {
            name: String::new(),
            languages: Vec::new(),
            exclude_globs: default_exclude_globs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OrientationSpec {
    #[serde(default = "default_entry_docs")]
    pub entry_docs: Vec<String>,
    #[serde(default = "default_max_entry_doc_lines")]
    pub max_entry_doc_lines: usize,
    #[serde(default = "default_true")]
    pub verify_markdown_links: bool,
    #[serde(default)]
    pub required_docs: Vec<String>,
    #[serde(default = "default_true")]
    pub require_committed_spec: bool,
    #[serde(default = "default_max_review_age_days")]
    pub max_review_age_days: u64,
}

impl Default for OrientationSpec {
    fn default() -> Self {
        Self {
            entry_docs: default_entry_docs(),
            max_entry_doc_lines: default_max_entry_doc_lines(),
            verify_markdown_links: true,
            required_docs: Vec::new(),
            require_committed_spec: true,
            max_review_age_days: default_max_review_age_days(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LayerSpec {
    pub name: String,
    pub paths: Vec<String>,
    #[serde(default)]
    pub allowed_dependencies: Vec<String>,
    #[serde(default)]
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenImportRule {
    pub id: String,
    pub from_globs: Vec<String>,
    pub forbid_patterns: Vec<String>,
    pub message: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureSpec {
    #[serde(default)]
    pub layers: Vec<LayerSpec>,
    #[serde(default)]
    pub forbidden_imports: Vec<ForbiddenImportRule>,
    #[serde(default = "default_max_file_lines")]
    pub max_file_lines: usize,
    #[serde(default)]
    pub file_line_exemptions: Vec<String>,
}

impl Default for ArchitectureSpec {
    fn default() -> Self {
        Self {
            layers: Vec::new(),
            forbidden_imports: Vec::new(),
            max_file_lines: default_max_file_lines(),
            file_line_exemptions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VerifyCommand {
    pub name: String,
    pub cmd: String,
    #[serde(default = "default_verify_kind")]
    pub kind: String,
    #[serde(default = "default_verify_timeout")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VerifySpec {
    #[serde(default)]
    pub commands: Vec<VerifyCommand>,
    #[serde(default = "default_true")]
    pub check_ci_parity: bool,
}

impl Default for VerifySpec {
    fn default() -> Self {
        Self {
            commands: Vec::new(),
            check_ci_parity: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegexRule {
    pub id: String,
    #[serde(default = "default_all_globs")]
    pub globs: Vec<String>,
    #[serde(default)]
    pub exclude_globs: Vec<String>,
    pub pattern: String,
    #[serde(default = "default_error")]
    pub severity: String,
    pub message: String,
    pub remediation: String,
    #[serde(default)]
    pub examples_pass: Vec<String>,
    #[serde(default)]
    pub examples_fail: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InvariantsSpec {
    #[serde(default = "default_true")]
    pub forbid_secrets: bool,
    #[serde(default = "default_secret_exempt")]
    pub secret_exempt_globs: Vec<String>,
    #[serde(default)]
    pub english_prose_only: bool,
    #[serde(default)]
    pub prose_exempt_globs: Vec<String>,
    #[serde(default)]
    pub forbid_debug_leftovers: bool,
    #[serde(default)]
    pub custom_regex_rules: Vec<RegexRule>,
}

impl Default for InvariantsSpec {
    fn default() -> Self {
        Self {
            forbid_secrets: true,
            secret_exempt_globs: default_secret_exempt(),
            english_prose_only: false,
            prose_exempt_globs: Vec::new(),
            forbid_debug_leftovers: false,
            custom_regex_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SemanticRule {
    pub id: String,
    pub description: String,
    pub predicate: String,
    #[serde(default = "default_all_globs")]
    pub globs: Vec<String>,
    #[serde(default = "default_threshold")]
    pub threshold: f64,
    #[serde(default = "default_advisory")]
    pub action: String,
    pub remediation: String,
    #[serde(default)]
    pub examples_pass: Vec<String>,
    #[serde(default)]
    pub examples_fail: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SemanticSpec {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_semantic_url")]
    pub base_url: String,
    #[serde(default = "default_semantic_key_env")]
    pub api_key_env: String,
    #[serde(default = "default_semantic_model")]
    pub model: String,
    #[serde(default = "default_semantic_timeout")]
    pub timeout_seconds: f64,
    #[serde(default = "default_max_diff_chars")]
    pub max_diff_chars: usize,
    #[serde(default = "default_rules_dir")]
    pub rules_dir: String,
    #[serde(default)]
    pub rules: Vec<SemanticRule>,
}

impl Default for SemanticSpec {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: default_semantic_url(),
            api_key_env: default_semantic_key_env(),
            model: default_semantic_model(),
            timeout_seconds: default_semantic_timeout(),
            max_diff_chars: default_max_diff_chars(),
            rules_dir: default_rules_dir(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySpec {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub ledger_path: Option<String>,
    #[serde(default = "default_thrash_threshold")]
    pub thrash_threshold: usize,
    #[serde(default = "default_thrash_window_minutes")]
    pub thrash_window_minutes: i64,
    #[serde(default = "default_stale_min_runs")]
    pub stale_rule_min_runs: usize,
}

impl Default for TelemetrySpec {
    fn default() -> Self {
        Self {
            enabled: true,
            ledger_path: None,
            thrash_threshold: default_thrash_threshold(),
            thrash_window_minutes: default_thrash_window_minutes(),
            stale_rule_min_runs: default_stale_min_runs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProjectSpec {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub project: ProjectIdentity,
    #[serde(default)]
    pub orientation: OrientationSpec,
    #[serde(default)]
    pub architecture: ArchitectureSpec,
    #[serde(default)]
    pub verify: VerifySpec,
    #[serde(default)]
    pub invariants: InvariantsSpec,
    #[serde(default)]
    pub semantic: SemanticSpec,
    #[serde(default)]
    pub telemetry: TelemetrySpec,
    #[serde(default)]
    pub proofs: ProofsSpec,
}

impl Default for ProjectSpec {
    fn default() -> Self {
        Self {
            version: default_version(),
            project: ProjectIdentity::default(),
            orientation: OrientationSpec::default(),
            architecture: ArchitectureSpec::default(),
            verify: VerifySpec::default(),
            invariants: InvariantsSpec::default(),
            semantic: SemanticSpec::default(),
            telemetry: TelemetrySpec::default(),
            proofs: ProofsSpec::default(),
        }
    }
}

impl ProjectSpec {
    /// Fail-closed validation of numeric and enum bounds.
    pub fn validate(&self) -> Result<(), String> {
        const VALID_LANGS: [&str; 6] = ["python", "go", "rust", "lean", "typescript", "javascript"];
        for lang in &self.project.languages {
            if !VALID_LANGS.contains(&lang.as_str()) {
                return Err(format!("Unsupported language '{lang}' in project.languages"));
            }
        }
        if self.orientation.max_entry_doc_lines == 0 {
            return Err("orientation.max_entry_doc_lines must be a positive integer".into());
        }
        if self.orientation.max_review_age_days == 0 {
            return Err("orientation.max_review_age_days must be a positive integer".into());
        }
        if self.architecture.max_file_lines == 0 {
            return Err("architecture.max_file_lines must be a positive integer".into());
        }
        for cmd in &self.verify.commands {
            if !["lint", "typecheck", "test", "build", "custom"].contains(&cmd.kind.as_str()) {
                return Err(format!("Invalid verify command kind '{}'", cmd.kind));
            }
            if cmd.timeout_seconds == 0 {
                return Err(format!(
                    "verify.commands.{}.timeout_seconds must be positive",
                    cmd.name
                ));
            }
        }
        for rule in &self.invariants.custom_regex_rules {
            if !["error", "warning"].contains(&rule.severity.as_str()) {
                return Err(format!(
                    "Invalid severity '{}' on custom regex rule '{}'",
                    rule.severity, rule.id
                ));
            }
        }
        for rule in &self.semantic.rules {
            if !(rule.threshold > 0.0 && rule.threshold <= 1.0) {
                return Err(format!(
                    "Semantic rule '{}' threshold must be in (0, 1]",
                    rule.id
                ));
            }
            if !["advisory", "fix_now"].contains(&rule.action.as_str()) {
                return Err(format!(
                    "Invalid action '{}' on semantic rule '{}'",
                    rule.action, rule.id
                ));
            }
        }
        self.proofs.validate()?;
        Ok(())
    }
}

/// Return the first recognized Birkin spec path inside `repo_root`, if present.
pub fn find_spec_file(repo_root: &Path) -> Option<PathBuf> {
    for rel in SPEC_REL_PATHS {
        let candidate = repo_root.join(rel);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Walk upward from `start` to find a directory containing `.birkin/config.yaml` or `.git`.
pub fn find_repo_root(start: &Path) -> PathBuf {
    let resolved = fs::canonicalize(start).unwrap_or_else(|_| start.to_path_buf());
    let mut cur = if resolved.is_file() {
        resolved
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or(resolved)
    } else {
        resolved
    };
    let start_dir = cur.clone();
    let mut git_fallback: Option<PathBuf> = None;
    loop {
        if find_spec_file(&cur).is_some() {
            return cur;
        }
        if git_fallback.is_none() && cur.join(".git").exists() {
            git_fallback = Some(cur.clone());
        }
        match cur.parent() {
            Some(parent) if parent != cur => cur = parent.to_path_buf(),
            _ => break,
        }
    }
    git_fallback.unwrap_or(start_dir)
}

/// Load strict `ProjectSpec` from `explicit_path` or `repo_root`, failing closed on invalid YAML/keys.
pub fn load_project_spec(
    repo_root: &Path,
    explicit_path: Option<&Path>,
) -> Result<(ProjectSpec, Option<PathBuf>), String> {
    let spec_path = match explicit_path {
        Some(p) => {
            if !p.is_file() {
                return Err(format!("Explicit Birkin spec not found: {}", p.display()));
            }
            Some(p.to_path_buf())
        }
        None => find_spec_file(repo_root),
    };

    let Some(path) = spec_path else {
        let mut spec = ProjectSpec::default();
        spec.project.name = repo_root
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("repo")
            .to_string();
        return Ok((spec, None));
    };

    let raw_text = fs::read_to_string(&path)
        .map_err(|e| format!("Failed reading {}: {e}", path.display()))?;
    let yaml_val: serde_yaml::Value = serde_yaml::from_str(&raw_text)
        .map_err(|e| format!("Invalid YAML in {}: {e}", path.display()))?;

    let mut spec: ProjectSpec = if yaml_val.is_null() {
        ProjectSpec::default()
    } else if yaml_val.is_mapping() {
        serde_yaml::from_value(yaml_val)
            .map_err(|e| format!("Schema validation failed for {}: {e}", path.display()))?
    } else {
        return Err(format!("Birkin spec must be a YAML mapping: {}", path.display()));
    };

    // Merge extra rule files under semantic.rules_dir
    let rules_dir = repo_root.join(&spec.semantic.rules_dir);
    if rules_dir.is_dir() {
        let mut seen_ids: HashSet<String> =
            spec.semantic.rules.iter().map(|r| r.id.clone()).collect();
        let mut rule_files: Vec<PathBuf> = fs::read_dir(&rules_dir)
            .map_err(|e| format!("Failed reading {}: {e}", rules_dir.display()))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| {
                p.is_file()
                    && matches!(
                        p.extension().and_then(|e| e.to_str()),
                        Some("yaml") | Some("yml")
                    )
            })
            .collect();
        rule_files.sort();
        for rule_file in rule_files {
            let txt = fs::read_to_string(&rule_file)
                .map_err(|e| format!("Failed reading {}: {e}", rule_file.display()))?;
            let val: serde_yaml::Value = serde_yaml::from_str(&txt)
                .map_err(|e| format!("Invalid YAML in {}: {e}", rule_file.display()))?;
            if val.is_null() {
                continue;
            }
            let items: Vec<serde_yaml::Value> = match val {
                serde_yaml::Value::Sequence(seq) => seq,
                other => vec![other],
            };
            for item in items {
                let rule: SemanticRule = serde_yaml::from_value(item).map_err(|e| {
                    format!("Invalid semantic rule in {}: {e}", rule_file.display())
                })?;
                if !seen_ids.insert(rule.id.clone()) {
                    return Err(format!(
                        "Duplicate semantic rule id '{}' in {}",
                        rule.id,
                        rule_file.display()
                    ));
                }
                spec.semantic.rules.push(rule);
            }
        }
    }

    spec.validate()?;

    if spec.project.name.is_empty() {
        spec.project.name = repo_root
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("repo")
            .to_string();
    }

    Ok((spec, Some(path)))
}
