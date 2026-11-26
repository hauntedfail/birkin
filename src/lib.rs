//! Birkin — Native Rust Verification Engine & Hermes Runtime Verifier.
//!
//! Enforced 6-layer architecture DAG:
//!   0. core: constants, glob
//!   1. models: models, project_models
//!   2. utils: config_utils, imports_parser, ledger
//!   3. engines: static_check, live, drift, guides, project_init, sensors, semantic
//!   4. orchestration: gc, steer, hooks, report
//!   5. cli: project_cli, cli, lib, main

pub mod cli;
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
pub mod project_cli;
pub mod project_init;
pub mod project_models;
pub mod report;
pub mod semantic;
pub mod sensors;
pub mod static_check;
pub mod steer;
