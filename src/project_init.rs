//! Auto-detection, scaffolding (.birkin/config.yaml), and compact feedforward guide rendering.

use crate::project_models::{
    ArchitectureSpec, InvariantsSpec, OrientationSpec, ProjectIdentity, ProjectSpec, VerifyCommand,
    VerifySpec,
};
use crate::proof_models::{LeanProjectSpec, ProofsSpec};
use serde_json::Value;
use std::fs;
use std::path::Path;

pub fn detect_project_spec(repo_root: &Path) -> ProjectSpec {
    let mut languages: Vec<String> = Vec::new();
    let mut commands: Vec<VerifyCommand> = Vec::new();

    let pyproject = repo_root.join("pyproject.toml");
    if pyproject.is_file() {
        languages.push("python".into());
        let text = fs::read_to_string(&pyproject).unwrap_or_default();
        if text.contains("ruff") {
            commands.push(VerifyCommand {
                name: "lint".into(),
                cmd: "ruff check src tests".into(),
                kind: "lint".into(),
                timeout_seconds: 120,
            });
        }
        if text.contains("pytest") || repo_root.join("tests").is_dir() {
            commands.push(VerifyCommand {
                name: "test".into(),
                cmd: "pytest -v".into(),
                kind: "test".into(),
                timeout_seconds: 300,
            });
        }
    }

    if repo_root.join("go.mod").is_file() {
        languages.push("go".into());
        commands.push(VerifyCommand {
            name: "go-vet".into(),
            cmd: "go vet ./...".into(),
            kind: "lint".into(),
            timeout_seconds: 120,
        });
        commands.push(VerifyCommand {
            name: "go-test".into(),
            cmd: "go test ./...".into(),
            kind: "test".into(),
            timeout_seconds: 300,
        });
    }

    if repo_root.join("Cargo.toml").is_file() {
        languages.push("rust".into());
        commands.push(VerifyCommand {
            name: "cargo-clippy".into(),
            cmd: "cargo clippy --all-targets -- -D warnings".into(),
            kind: "lint".into(),
            timeout_seconds: 180,
        });
        commands.push(VerifyCommand {
            name: "cargo-test".into(),
            cmd: "cargo test".into(),
            kind: "test".into(),
            timeout_seconds: 300,
        });
    }

    let mut lean_projects: Vec<LeanProjectSpec> = Vec::new();
    if repo_root.join("lakefile.toml").is_file()
        || repo_root.join("lakefile.lean").is_file()
        || repo_root.join("lean").join("lakefile.toml").is_file()
    {
        languages.push("lean".into());
        let (cmd, lean_dir) = if repo_root.join("lean").join("lakefile.toml").is_file() {
            ("cd lean && lake build", "lean")
        } else {
            ("lake build", ".")
        };
        commands.push(VerifyCommand {
            name: "lean-proofs".into(),
            cmd: cmd.into(),
            kind: "build".into(),
            timeout_seconds: 300,
        });
        lean_projects.push(LeanProjectSpec {
            name: "lean-spec".into(),
            dir: lean_dir.into(),
            modules: Vec::new(),
            theorems: Vec::new(),
        });
    }

    let pkg_json = repo_root.join("package.json");
    if pkg_json.is_file() {
        let is_ts = repo_root.join("tsconfig.json").is_file();
        languages.push(if is_ts { "typescript" } else { "javascript" }.into());
        let runner = if repo_root.join("pnpm-lock.yaml").is_file() {
            "pnpm"
        } else {
            "npm"
        };
        if let Ok(text) = fs::read_to_string(&pkg_json) {
            if let Ok(Value::Object(pkg)) = serde_json::from_str::<Value>(&text) {
                if let Some(Value::Object(scripts)) = pkg.get("scripts") {
                    if scripts.contains_key("verify") {
                        commands.push(VerifyCommand {
                            name: "verify".into(),
                            cmd: format!("{runner} run verify"),
                            kind: "test".into(),
                            timeout_seconds: 300,
                        });
                    } else {
                        for (key, kind) in [
                            ("lint", "lint"),
                            ("typecheck", "typecheck"),
                            ("check", "lint"),
                            ("test", "test"),
                        ] {
                            if scripts.contains_key(key) {
                                commands.push(VerifyCommand {
                                    name: key.into(),
                                    cmd: format!("{runner} run {key}"),
                                    kind: kind.into(),
                                    timeout_seconds: 300,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    let mut entry_docs = Vec::new();
    for cand in ["AGENTS.md", "CLAUDE.md"] {
        if repo_root.join(cand).is_file() {
            entry_docs.push(cand.to_string());
        }
    }
    if entry_docs.is_empty() {
        entry_docs.push("AGENTS.md".into());
    }

    let name = repo_root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("repo")
        .to_string();

    ProjectSpec {
        version: 1,
        project: ProjectIdentity {
            name,
            languages,
            ..ProjectIdentity::default()
        },
        orientation: OrientationSpec {
            entry_docs,
            ..OrientationSpec::default()
        },
        architecture: ArchitectureSpec {
            file_line_exemptions: [
                "**/tests/**", "**/__tests__/**", "**/fixture/**", "**/fixtures/**",
                "**/generated/**", "**/*_test.go", "**/test_*.py", "**/*_test.py",
                "**/*.test.js", "**/*.spec.js", "**/*.test.jsx", "**/*.spec.jsx",
                "**/*.test.ts", "**/*.spec.ts", "**/*.test.tsx", "**/*.spec.tsx",
                "**/tests.rs", "**/*_test.rs", "**/*_tests.rs",
            ].into_iter().map(String::from).collect(),
            ..ArchitectureSpec::default()
        },
        verify: VerifySpec {
            commands,
            check_ci_parity: true,
        },
        invariants: InvariantsSpec::default(),
        proofs: ProofsSpec {
            lean_projects,
            ..ProofsSpec::default()
        },
        ..ProjectSpec::default()
    }
}

pub fn render_spec_yaml(spec: &ProjectSpec) -> String {
    let header = "# Birkin Project Specification (.birkin/config.yaml)\n# Enforced mechanically by Birkin across CLI, git hooks, CI, Claude Code, and Hermes.\n";
    let body = serde_yaml::to_string(spec).unwrap_or_default();
    format!("{header}{body}")
}

pub fn render_agent_guide(
    repo_root: &Path,
    spec: &ProjectSpec,
    steering: Option<&Value>,
) -> String {
    let resolved = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let langs = if spec.project.languages.is_empty() {
        "auto".to_string()
    } else {
        spec.project.languages.join(", ")
    };

    let mut lines = vec![
        format!("# Birkin Feedforward Guide — {}", spec.project.name),
        format!("Root: `{}`", resolved.display()),
        format!("Languages: {langs}"),
        String::new(),
    ];

    if !spec.orientation.entry_docs.is_empty() {
        let present: Vec<&str> = spec
            .orientation
            .entry_docs
            .iter()
            .filter(|d| repo_root.join(d).is_file())
            .map(String::as_str)
            .collect();
        let summary = if present.is_empty() {
            "none (missing AGENTS.md)".to_string()
        } else {
            present.join(", ")
        };
        lines.push(format!("## Entry Docs: {summary}"));
    }

    if !spec.verify.commands.is_empty() {
        lines.push("\n## Canonical Verify Commands (Admission Gate)".into());
        for cmd in &spec.verify.commands {
            lines.push(format!("- `{}` ({}): `{}`", cmd.name, cmd.kind, cmd.cmd));
        }
    }

    if !spec.architecture.layers.is_empty() {
        lines.push("\n## Architecture Layer DAG (Mechanically Enforced)".into());
        for layer in &spec.architecture.layers {
            let deps = if layer.allowed_dependencies.is_empty() {
                "(none)".to_string()
            } else {
                layer.allowed_dependencies.join(", ")
            };
            lines.push(format!(
                "- **{}** (`{}`) -> allowed: {deps}",
                layer.name,
                layer.paths.join(", ")
            ));
        }
    }

    if !spec.architecture.forbidden_imports.is_empty() {
        lines.push("\n## Forbidden Imports".into());
        for rule in &spec.architecture.forbidden_imports {
            lines.push(format!("- `{}`: {}", rule.id, rule.message));
        }
    }

    let mut invs = Vec::new();
    if spec.invariants.forbid_secrets {
        invs.push("no hardcoded secrets".to_string());
    }
    if spec.invariants.english_prose_only {
        invs.push("English prose only in docs/comments".to_string());
    }
    if spec.invariants.forbid_debug_leftovers {
        invs.push("no debug breakpoints".to_string());
    }
    invs.push(format!(
        "max file size <= {} lines",
        spec.architecture.max_file_lines
    ));
    if !spec.invariants.custom_regex_rules.is_empty() {
        invs.push(format!(
            "{} custom regex guards",
            spec.invariants.custom_regex_rules.len()
        ));
    }
    if !spec.semantic.rules.is_empty() {
        let state = if spec.semantic.enabled {
            "enabled"
        } else {
            "available via `birkin review`"
        };
        invs.push(format!(
            "{} semantic predicates ({state})",
            spec.semantic.rules.len()
        ));
    }
    lines.push("\n## Active Invariants".into());
    lines.push(format!("- {}", invs.join("; ")));

    if let Some(st) = steering {
        if let Some(hotspots) = st.get("hotspots").and_then(Value::as_array) {
            if !hotspots.is_empty() {
                lines.push("\n## Recent Violation Hotspots (From Telemetry)".into());
                for item in hotspots.iter().take(5) {
                    let r = item.get("rule").and_then(Value::as_str).unwrap_or("");
                    let h = item.get("hits").and_then(Value::as_u64).unwrap_or(0);
                    lines.push(format!("- `{r}` ({h} hits) — watch out before editing"));
                }
            }
        }
    }

    lines.push("\n## Fast Verification Loop".into());
    lines.push("- After edits: `birkin check --files <changed-files>`".into());
    lines.push("- Formal proofs: `birkin prove`".into());
    lines.push("- Before commit/PR: `birkin check --run-verify` && `birkin prove` && `birkin receipt verify --require check,verify,prove`".into());
    lines.join("\n") + "\n"
}
