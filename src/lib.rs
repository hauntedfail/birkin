//! Birkin — Native Rust Verification Engine & Hermes Runtime Verifier.
//!
//! Enforced 6-layer architecture DAG:
//!   0. core: constants, glob
//!   1. models: models, project_models, proof_models, workflow_models
//!   2. utils: config_utils, imports_parser, ledger
//!   3. engines: static_check, live, drift, guides, project_init, prove, prove_audit, prove_lean, sensors, semantic, verify,
//!      plan_contract, scope_contract, authority_contract, stage_contract, review_closure
//!   4. orchestration: client_sync, gc, steer, hooks, report
//!   5. cli: project_cli, ops_cli, workflow_cli, workflow_stage_cli, cli, lib, main

pub mod authority_contract;
pub mod cli;
pub mod client_sync;
pub mod config_utils;
pub mod constants;
pub mod drift;
pub mod gc;
pub mod glob;
pub mod guides;
pub mod hooks;
pub mod imports_parser;
pub mod ledger;
pub mod live;
pub mod models;
pub mod ops_cli;
pub mod plan_contract;
pub mod project_cli;
pub mod project_init;
pub mod project_models;
pub mod proof_models;
pub mod prove;
pub mod prove_audit;
pub mod prove_lean;
pub mod report;
pub mod review_closure;
pub mod scope_contract;
pub mod semantic;
pub mod sensors;
pub mod stage_contract;
pub mod static_check;
pub mod steer;
pub mod verify;
pub mod workflow_cli;
pub mod workflow_models;
pub mod workflow_stage_cli;
