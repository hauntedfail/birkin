//! CLI parser and dispatcher for Birkin — native Rust engine & Hermes runtime verifier.

use crate::config_utils::{canonical_config_sha256, load_policy, load_yaml_mapping};
use crate::constants::{
    combine_exit_codes, default_hermes_home, EXIT_PASS, EXIT_TOOL_ERROR,
};
use crate::drift::verify_drift;
use crate::live::verify_live;
use crate::models::RuntimePolicy;
use crate::ops_cli::{
    handle_gc, handle_hook_post_edit, handle_hook_pre_commit, handle_hook_pre_complete,
    handle_install_hooks, handle_prove, handle_receipt_verify, handle_steer, handle_sync,
    SyncArgs,
};
use crate::project_cli::{
    handle_audit, handle_check, handle_eval_rules, handle_guide, handle_init, handle_review,
};
use crate::report::{format_human, write_state_atomic};
use crate::static_check::verify_static;
use crate::workflow_cli::{dispatch_workflow, WorkflowCommand};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use serde_json::{json, Map, Value};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "birkin",
    version,
    about = "Birkin — Native Rust Verification Engine & Hermes Runtime Verifier"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Args, Debug, Clone)]
pub struct ProjectCommonArgs {
    #[arg(default_value = ".")]
    pub path: PathBuf,
    #[arg(long)]
    pub spec: Option<PathBuf>,
    #[arg(long = "json")]
    pub as_json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct HermesCommonArgs {
    #[arg(long)]
    pub home: Option<PathBuf>,
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long)]
    pub policy: Option<PathBuf>,
    #[arg(long)]
    pub env: Option<PathBuf>,
    #[arg(long = "json")]
    pub as_json: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Auto-detect stack and scaffold .birkin/config.yaml
    Init {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        write: bool,
        #[arg(long)]
        force: bool,
        #[arg(long = "json")]
        as_json: bool,
    },
    /// Emit compact feedforward guide for coding agents
    Guide(ProjectCommonArgs),
    /// Run 6-axis repository readiness audit
    Audit(ProjectCommonArgs),
    /// Run deterministic sensors and optional canonical verify commands
    Check {
        #[command(flatten)]
        common: ProjectCommonArgs,
        #[arg(long, num_args = 0..)]
        files: Option<Vec<PathBuf>>,
        #[arg(long)]
        run_verify: bool,
        #[arg(long)]
        no_guides: bool,
        #[arg(long)]
        no_receipt: bool,
        #[arg(long, default_value = "cli")]
        surface: String,
    },
    /// Compile repository invariants into Lean 4 and verify them with Lean's kernel
    Prove {
        #[command(flatten)]
        common: ProjectCommonArgs,
        #[arg(long)]
        emit: Option<PathBuf>,
        #[arg(long)]
        no_receipt: bool,
        #[arg(long)]
        skip_lean_projects: bool,
        #[arg(long, default_value = "cli")]
        surface: String,
    },
    /// Run narrow semantic rules against diffs or files
    Review {
        #[command(flatten)]
        common: ProjectCommonArgs,
        #[arg(long)]
        staged: bool,
        #[arg(long)]
        diff: Option<String>,
        #[arg(long, num_args = 0..)]
        files: Option<Vec<PathBuf>>,
        #[arg(long)]
        no_receipt: bool,
    },
    /// Calibrate custom regex and semantic rules against pass/fail fixtures
    #[command(name = "eval-rules")]
    EvalRules {
        #[command(flatten)]
        common: ProjectCommonArgs,
        #[arg(long)]
        live: bool,
    },
    /// Real-time agent and git hook adapter
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
    /// Idempotently wire Birkin into git, Claude Code, and Hermes
    #[command(name = "install-hooks")]
    InstallHooks {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, value_parser = ["git", "claude", "hermes", "all"])]
        target: String,
        #[arg(long = "global")]
        global_install: bool,
        #[arg(long)]
        hermes_home: Option<PathBuf>,
        #[arg(long = "json")]
        as_json: bool,
    },
    /// Deterministically sync or audit cross-client thin adapters under --target-root
    Sync(SyncArgs),
    /// Verify hash-chained revision-pinned receipts
    Receipt {
        #[command(subcommand)]
        action: ReceiptAction,
    },
    /// Experience & decision observability steering report
    Steer(ProjectCommonArgs),
    /// Alias for steer
    Telemetry(ProjectCommonArgs),
    /// Entropy and garbage-collection sweep
    Gc(ProjectCommonArgs),

    // Top-level Hermes runtime verifier commands
    /// [Hermes] Run structural, semantic, and policy checks
    Static(HermesCommonArgs),
    /// [Hermes] Run live provider /v1/models contract checks
    Live {
        #[command(flatten)]
        common: HermesCommonArgs,
        #[arg(long)]
        probe: bool,
        #[arg(long)]
        timeout: Option<f64>,
    },
    /// [Hermes] Prove running gateway matches on-disk config and code
    Drift(HermesCommonArgs),
    /// [Hermes] Run static, optional live, and drift checks
    All {
        #[command(flatten)]
        common: HermesCommonArgs,
        #[arg(long)]
        live: bool,
        #[arg(long)]
        probe: bool,
        #[arg(long)]
        timeout: Option<f64>,
        #[arg(long)]
        skip_drift: bool,
        #[arg(long)]
        no_write_state: bool,
    },
    /// Hermes Agent runtime verifier namespace
    Hermes {
        #[command(subcommand)]
        sub: HermesSubcommand,
    },
    /// Workflow-contract commands (plan, unit, stage, sawyer, review-closure)
    #[command(flatten)]
    Workflow(WorkflowCommand),
}

#[derive(Subcommand, Debug)]
pub enum HookAction {
    #[command(name = "post-edit")]
    PostEdit {
        #[arg(long, num_args = 0..)]
        files: Vec<PathBuf>,
        #[arg(long)]
        claude_stdin: bool,
        #[arg(long)]
        semantic: bool,
        #[arg(long)]
        block_on_error: bool,
        #[arg(long)]
        require_spec: bool,
        #[arg(long, default_value = "hook")]
        surface: String,
    },
    #[command(name = "pre-commit")]
    PreCommit {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    #[command(name = "pre-complete")]
    PreComplete {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, default_value = "check,verify")]
        require: String,
        #[arg(long)]
        require_clean: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ReceiptAction {
    Verify {
        #[command(flatten)]
        common: ProjectCommonArgs,
        #[arg(long, default_value = "check")]
        require: String,
        #[arg(long)]
        require_clean: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum HermesSubcommand {
    Static(HermesCommonArgs),
    Live {
        #[command(flatten)]
        common: HermesCommonArgs,
        #[arg(long)]
        probe: bool,
        #[arg(long)]
        timeout: Option<f64>,
    },
    Drift(HermesCommonArgs),
    All {
        #[command(flatten)]
        common: HermesCommonArgs,
        #[arg(long)]
        live: bool,
        #[arg(long)]
        probe: bool,
        #[arg(long)]
        timeout: Option<f64>,
        #[arg(long)]
        skip_drift: bool,
        #[arg(long)]
        no_write_state: bool,
    },
}

#[allow(clippy::too_many_arguments)]
fn run_hermes_command(
    common: &HermesCommonArgs,
    cmd: &str,
    live_flag: bool,
    probe: bool,
    timeout: Option<f64>,
    skip_drift: bool,
    no_write_state: bool,
) -> i32 {
    let hermes_home = common.home.clone().unwrap_or_else(default_hermes_home);
    let config_path = common
        .config
        .clone()
        .unwrap_or_else(|| hermes_home.join("config.yaml"));
    let default_policy = hermes_home.join("birkin-policy.yaml");
    let env_path = common
        .env
        .clone()
        .unwrap_or_else(|| hermes_home.join(".env"));

    let cfg_res = load_yaml_mapping(&config_path);
    let policy_res = match &common.policy {
        Some(explicit) => {
            if !explicit.exists() {
                Err(format!("Explicit policy file not found: {}", explicit.display()))
            } else {
                load_policy(explicit)
            }
        }
        None if default_policy.exists() => load_policy(&default_policy),
        None => Ok(RuntimePolicy::default()),
    };

    let (cfg, policy) = match (cfg_res, policy_res) {
        (Ok(c), Ok(p)) => (c, p),
        (Err(e), _) | (_, Err(e)) => {
            let err = json!({
                "command": cmd,
                "status": "ERROR",
                "exit_code": EXIT_TOOL_ERROR,
                "error": e,
            });
            if common.as_json {
                eprintln!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
            } else {
                eprintln!("ERROR: {e}");
            }
            return EXIT_TOOL_ERROR;
        }
    };

    let cfg_sha256 = canonical_config_sha256(&cfg);
    let mut sections = Map::new();
    let mut codes = Vec::new();

    if cmd == "static" || cmd == "all" {
        let skills_dir = hermes_home.join("skills");
        let (c, f) = verify_static(&cfg, &policy, Some(&env_path), Some(&skills_dir));
        codes.push(c);
        sections.insert(
            "static".into(),
            json!({"exit_code": c, "findings": f}),
        );
    }

    if cmd == "live" || (cmd == "all" && (live_flag || probe)) {
        let (c, f, meta) = verify_live(&cfg, &policy, Some(&env_path), probe, timeout);
        codes.push(c);
        sections.insert(
            "live".into(),
            json!({"exit_code": c, "meta": meta, "findings": f}),
        );
    }

    if cmd == "drift" || (cmd == "all" && !skip_drift) {
        let (c, f, meta) =
            verify_drift(&config_path, &env_path, &hermes_home, &policy, Some(&cfg_sha256));
        codes.push(c);
        sections.insert(
            "drift".into(),
            json!({"exit_code": c, "meta": meta, "findings": f}),
        );
    }

    let final_code = combine_exit_codes(&codes);
    let report = json!({
        "command": cmd,
        "checked_at": Utc::now().to_rfc3339(),
        "status": if final_code == EXIT_PASS { "PASS" } else { "FAIL" },
        "exit_code": final_code,
        "config_sha256": cfg_sha256,
        "sections": Value::Object(sections),
    });

    if cmd == "all" && !no_write_state {
        let _ = write_state_atomic(&hermes_home.join("state").join("birkin.json"), &report);
    }

    if common.as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        println!("{}", format_human(&report));
    }
    final_code
}

pub fn dispatch(cli: Cli) -> i32 {
    match cli.command {
        Commands::Init {
            path,
            write,
            force,
            as_json,
        } => handle_init(&path, write, force, as_json),
        Commands::Guide(c) => handle_guide(&c.path, c.spec.as_deref(), c.as_json),
        Commands::Audit(c) => handle_audit(&c.path, c.spec.as_deref(), c.as_json),
        Commands::Check {
            common,
            files,
            run_verify,
            no_guides,
            no_receipt,
            surface,
        } => handle_check(
            &common.path,
            common.spec.as_deref(),
            files.as_deref(),
            run_verify,
            no_guides,
            no_receipt,
            &surface,
            common.as_json,
        ),
        Commands::Prove {
            common,
            emit,
            no_receipt,
            skip_lean_projects,
            surface,
        } => handle_prove(
            &common.path,
            common.spec.as_deref(),
            emit.as_deref(),
            no_receipt,
            skip_lean_projects,
            &surface,
            common.as_json,
        ),
        Commands::Review {
            common,
            staged,
            diff,
            files,
            no_receipt,
        } => handle_review(
            &common.path,
            common.spec.as_deref(),
            staged,
            diff.as_deref(),
            files.as_deref(),
            no_receipt,
            common.as_json,
        ),
        Commands::EvalRules { common, live } => {
            handle_eval_rules(&common.path, common.spec.as_deref(), live, common.as_json)
        }
        Commands::Hook { action } => match action {
            HookAction::PostEdit {
                files,
                claude_stdin,
                semantic,
                block_on_error,
                require_spec,
                surface,
            } => handle_hook_post_edit(
                &files,
                claude_stdin,
                semantic,
                block_on_error,
                require_spec,
                &surface,
            ),
            HookAction::PreCommit { path } => handle_hook_pre_commit(&path),
            HookAction::PreComplete {
                path,
                require,
                require_clean,
            } => handle_hook_pre_complete(&path, &require, require_clean),
        },
        Commands::InstallHooks {
            path,
            target,
            global_install,
            hermes_home,
            as_json,
        } => handle_install_hooks(
            &path,
            &target,
            global_install,
            hermes_home.as_deref(),
            as_json,
        ),
        Commands::Sync(args) => handle_sync(&args),
        Commands::Receipt { action } => match action {
            ReceiptAction::Verify {
                common,
                require,
                require_clean,
            } => handle_receipt_verify(
                &common.path,
                common.spec.as_deref(),
                &require,
                require_clean,
                common.as_json,
            ),
        },
        Commands::Steer(c) | Commands::Telemetry(c) => {
            handle_steer(&c.path, c.spec.as_deref(), c.as_json)
        }
        Commands::Gc(c) => handle_gc(&c.path, c.spec.as_deref(), c.as_json),

        Commands::Static(c) => run_hermes_command(&c, "static", false, false, None, true, true),
        Commands::Live {
            common,
            probe,
            timeout,
        } => run_hermes_command(&common, "live", true, probe, timeout, true, true),
        Commands::Drift(c) => run_hermes_command(&c, "drift", false, false, None, false, true),
        Commands::All {
            common,
            live,
            probe,
            timeout,
            skip_drift,
            no_write_state,
        } => run_hermes_command(
            &common,
            "all",
            live,
            probe,
            timeout,
            skip_drift,
            no_write_state,
        ),
        Commands::Hermes { sub } => match sub {
            HermesSubcommand::Static(c) => {
                run_hermes_command(&c, "static", false, false, None, true, true)
            }
            HermesSubcommand::Live {
                common,
                probe,
                timeout,
            } => run_hermes_command(&common, "live", true, probe, timeout, true, true),
            HermesSubcommand::Drift(c) => {
                run_hermes_command(&c, "drift", false, false, None, false, true)
            }
            HermesSubcommand::All {
                common,
                live,
                probe,
                timeout,
                skip_drift,
                no_write_state,
            } => run_hermes_command(
                &common,
                "all",
                live,
                probe,
                timeout,
                skip_drift,
                no_write_state,
            ),
        },
        Commands::Workflow(cmd) => dispatch_workflow(cmd),
    }
}
