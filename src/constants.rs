//! Exit codes, severity precedence, and path defaults for Birkin.

use std::env;
use std::path::PathBuf;

pub const EXIT_PASS: i32 = 0;
pub const EXIT_STATIC: i32 = 1;
pub const EXIT_LIVE_CONTRACT: i32 = 2;
pub const EXIT_LIVE_TRANSIENT: i32 = 3;
pub const EXIT_DRIFT: i32 = 4;
pub const EXIT_TOOL_ERROR: i32 = 5;

const PRECEDENCE: [i32; 6] = [
    EXIT_TOOL_ERROR,
    EXIT_STATIC,
    EXIT_LIVE_CONTRACT,
    EXIT_DRIFT,
    EXIT_LIVE_TRANSIENT,
    EXIT_PASS,
];

/// Combine exit codes using the formally verified severity lattice:
/// tool error > static/policy > live contract > drift > transient > pass.
pub fn combine_exit_codes(codes: &[i32]) -> i32 {
    for &code in &PRECEDENCE {
        if codes.contains(&code) {
            return code;
        }
    }
    EXIT_PASS
}

/// Resolve the default Hermes home directory (`$HERMES_HOME` or `~/.hermes`).
pub fn default_hermes_home() -> PathBuf {
    if let Ok(val) = env::var("HERMES_HOME") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    home_dir().join(".hermes")
}

/// Resolve the current user's home directory.
pub fn home_dir() -> PathBuf {
    if let Ok(val) = env::var("HOME") {
        if !val.trim().is_empty() {
            return PathBuf::from(val);
        }
    }
    if let Ok(val) = env::var("USERPROFILE") {
        if !val.trim().is_empty() {
            return PathBuf::from(val);
        }
    }
    PathBuf::from(".")
}
