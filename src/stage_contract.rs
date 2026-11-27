//! Lifecycle admission, runner evidence and read-only Sawyer Git verification.
//!
//! Rust parses test transcripts, toolchain pins, and Git/Sawyer state; lifecycle stage
//! admission verdicts are computed directly by the Lean 4 decision kernel
//! (`BirkinSpec.StageAdmission`).

use crate::lean_kernel::{eval_stage, KernelStageRequest, KernelVerdict};
use crate::workflow_models::{LifecycleStage, SawyerContextPack, StageEvidenceInput};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};
use std::process::{Command, Output};

fn stage_wire(stage: LifecycleStage) -> &'static str {
    match stage {
        LifecycleStage::Implemented => "implemented",
        LifecycleStage::Verified => "verified",
        LifecycleStage::Reviewed => "reviewed",
        LifecycleStage::Committed => "committed",
        LifecycleStage::Pushed => "pushed",
        LifecycleStage::CiPassed => "ci_passed",
        LifecycleStage::Released => "released",
    }
}

/// Build the Lean 4 kernel request for lifecycle stage admission and certification.
pub fn build_stage_kernel_request(
    stage: LifecycleStage,
    ev: &StageEvidenceInput,
) -> KernelStageRequest {
    KernelStageRequest {
        stage: stage_wire(stage).into(),
        discovered_tests: ev.discovered_tests,
        executed_tests: ev.executed_tests,
        toolchain_matched: ev.toolchain_matched,
        receipt_chain_ok: ev.receipt_chain_ok,
        tree_bound_ok: ev.tree_bound_ok,
        review_passed: ev.review_passed,
        sawyer_staged_exact: ev.sawyer_staged_exact,
        sawyer_excluded_clean: ev.sawyer_excluded_clean,
        gpg_sign_required: ev.gpg_sign_required,
        gpg_sig_valid: ev.gpg_sig_valid,
        remote_head_matches: ev.remote_head_matches,
        ci_passed: ev.ci_passed,
        release_authorized: ev.release_authorized,
    }
}

/// Evaluate stage admission via the Lean 4 decision kernel, returning `Err` on kernel failure.
pub fn verify_stage_admission(
    stage: LifecycleStage,
    ev: &StageEvidenceInput,
) -> Result<(KernelStageRequest, KernelVerdict), String> {
    let kreq = build_stage_kernel_request(stage, ev);
    let verdict = eval_stage(&kreq)?;
    Ok((kreq, verdict))
}

/// Fail-closed boolean wrapper delegating directly to the Lean 4 decision kernel.
pub fn stage_admitted(stage: LifecycleStage, ev: &StageEvidenceInput) -> bool {
    verify_stage_admission(stage, ev)
        .map(|(_, v)| v.admitted)
        .unwrap_or(false)
}

fn relative_file(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('\\')
        && !name.contains('\0')
        && name
            .split('/')
            .all(|s| !matches!(s, "" | "." | "..") && !s.eq_ignore_ascii_case(".git"))
        && Path::new(name)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

fn read_config_file(root: &Path, name: &str) -> Result<String, String> {
    if !relative_file(name) {
        return Err(format!("Invalid repository path {name:?}"));
    }
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let path = root
        .join(name)
        .canonicalize()
        .map_err(|e| format!("{name}: {e}"))?;
    if !path.starts_with(&root) || !path.is_file() {
        return Err(format!("Expected repository file {name}"));
    }
    fs::read_to_string(path).map_err(|e| format!("{name}: {e}"))
}

/// Compare each configured pin manifest with the independently recorded runner manifest.
/// Keys are repository-relative paths. Multi-tool manifests retain their internal structure.
pub fn verify_toolchain_pins(
    root: &Path,
    files: &[String],
    observed: &BTreeMap<String, String>,
) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for name in files {
        let expected = read_config_file(root, name)?;
        if !seen.insert(name)
            || expected.trim().is_empty()
            || observed.get(name).map(|s| s.trim_end()) != Some(expected.trim_end())
        {
            return Err(format!(
                "Missing, duplicate or mismatched toolchain pin for {name}"
            ));
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct TestCounts {
    pub discovered: usize,
    pub executed: usize,
}

fn number(s: &str) -> Result<usize, String> {
    s.parse().map_err(|_| format!("Invalid test count {s:?}"))
}

fn cargo_counts(text: &str) -> Result<TestCounts, String> {
    let run = Regex::new(r"^running (\d+) tests?$").unwrap();
    let result = Regex::new(r"^test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; 0 filtered out(?:; finished in .+)?$").unwrap();
    let mut pending = None;
    let mut total = 0usize;
    for line in text.lines().map(str::trim) {
        if let Some(c) = run.captures(line) {
            if pending.replace(number(&c[1])?).is_some() {
                return Err("Missing suite result".into());
            }
        } else if line.starts_with("test result:") {
            let c = result
                .captures(line)
                .ok_or("Failed, partial or malformed cargo suite")?;
            let passed = number(&c[1])?;
            if pending.take() != Some(passed) {
                return Err("Cargo suite count mismatch".into());
            }
            total = total.checked_add(passed).ok_or("Test count overflow")?;
        }
    }
    if pending.is_some() {
        return Err("Incomplete cargo output".into());
    }
    Ok(TestCounts {
        discovered: total,
        executed: total,
    })
}

fn go_counts(text: &str) -> Result<TestCounts, String> {
    let mut pending = BTreeSet::new();
    let mut total = 0;
    let mut suite_passed = false;
    let mut suite_open = false;
    for line in text.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix("=== RUN") {
            suite_open = true;
            if !pending.insert(name.trim()) {
                return Err("Duplicate active Go test".into());
            }
        } else if let Some(record) = line.strip_prefix("--- PASS: ") {
            let name = record
                .split_whitespace()
                .next()
                .ok_or("Missing Go test name")?;
            if !pending.remove(name) {
                return Err("Unmatched Go test result".into());
            }
            total += 1;
        } else if line == "PASS" {
            if !pending.is_empty() {
                return Err("Incomplete Go package".into());
            }
            suite_passed = true;
            suite_open = false;
        } else if line.starts_with("--- SKIP:")
            || line.starts_with("--- FAIL:")
            || line.starts_with("FAIL")
        {
            return Err("Failed or skipped Go test".into());
        }
    }
    if suite_open || !suite_passed {
        return Err("Expected complete go test -v output".into());
    }
    Ok(TestCounts {
        discovered: total,
        executed: total,
    })
}

/// Parse one completed runner invocation. Lake delegates tests to a project driver;
/// a counted driver summary is required, and a successful Lake build supplies no tests.
pub fn parse_test_counts(parser: &str, text: &str, exit_code: i32) -> Result<TestCounts, String> {
    if exit_code != 0 {
        return Err(format!("Test command exited with {exit_code}"));
    }
    let ansi = Regex::new(r"\x1b\[[0-9;]*m").unwrap();
    let text = ansi.replace_all(text, "");
    let bad = Regex::new(r"(?i)\b[1-9][0-9]* (?:fail(?:ed|ures?)|errors?|skipped|ignored|filtered out|deselected|xfail(?:ed)?|xpass(?:ed)?|flaky|did not run|interrupted|todo|pending|timed out)\b").unwrap();
    let failed_case = Regex::new(r"(?im)^\s*(?:--- (?:FAIL|SKIP):|(?:FAIL(?:ED)?|SKIP(?:PED)?|ERROR)(?:[:\s]|$)|test .+ \.\.\. (?:FAILED|ignored)\s*$)").unwrap();
    if bad.is_match(&text) || failed_case.is_match(&text) {
        return Err("Transcript reports failed or unexecuted tests".into());
    }
    let counts = match parser {
        "cargo_test" => cargo_counts(&text)?,
        "go_test" => go_counts(&text)?,
        _ => {
            let (discovery, success) = match parser {
                "pytest" => (
                    r"^collected (\d+) items?$",
                    r"^(\d+) passed(?:, \d+ warnings?)? in \d+(?:\.\d+)?s(?: \([0-9:]+\))?$",
                ),
                "vitest" => (
                    r"^Tests\s+\d+ passed\s+\((\d+)\)$",
                    r"^Tests\s+(\d+) passed\s+\(\d+\)$",
                ),
                "playwright" => (
                    r"^Running (\d+) tests? using \d+ workers?$",
                    r"^(\d+) passed \([^)]+\)$",
                ),
                "lake" | "generic" => (
                    r"^(?:Running|running) (\d+) tests?$",
                    r"^(\d+) tests? passed$",
                ),
                _ => return Err(format!("Unsupported test parser {parser}")),
            };
            let count = |pattern: &str| -> Result<Option<usize>, String> {
                let re = Regex::new(pattern).unwrap();
                let mut hits = text
                    .lines()
                    .map(|s| s.trim().trim_matches('=').trim())
                    .filter_map(|s| re.captures(s));
                let result = hits.next().map(|c| number(&c[1])).transpose()?;
                if hits.next().is_some() {
                    return Err("Ambiguous runner summary".into());
                }
                Ok(result)
            };
            let executed = count(success)?.ok_or("Missing complete test summary")?;
            let discovered = match count(discovery)? {
                Some(n) => n,
                None if parser == "pytest" => executed, // Quiet pytest omits its collection line.
                None => return Err("Missing runner discovery count".into()),
            };
            TestCounts {
                discovered,
                executed,
            }
        }
    };
    if counts.discovered == 0 || counts.discovered != counts.executed {
        return Err("Zero or inconsistent test count".into());
    }
    Ok(counts)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SawyerPhase {
    Preflight,
    Staged,
    PostPush,
}

fn git_output(root: &Path, args: &[&str]) -> Result<Output, String> {
    Command::new("git")
        .current_dir(root)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .args(args)
        .output()
        .map_err(|e| e.to_string())
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = git_output(root, args)?;
    if !out.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args[0],
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| e.to_string())
}

fn paths<'a>(values: impl Iterator<Item = &'a str>) -> Result<BTreeSet<&'a str>, String> {
    let mut set = BTreeSet::new();
    for p in values {
        if !relative_file(p) || !set.insert(p) {
            return Err(format!("Invalid or duplicate path {p:?}"));
        }
    }
    Ok(set)
}

fn signing_required(root: &Path, pack: &SawyerContextPack) -> Result<bool, String> {
    let out = git_output(root, &["config", "--type=bool", "--get", "commit.gpgsign"])?;
    let policy = match (out.status.code(), out.stdout.as_slice()) {
        (Some(0), b"true\n") => true,
        (Some(0), b"false\n") | (Some(1), b"") => false,
        _ => return Err("Invalid commit.gpgsign configuration".into()),
    };
    Ok(policy || pack.require_signed.unwrap_or(false))
}

/// Check the requested repository and the actual index or published commit. The post-push
/// phase reads the target ref back from the configured push destination with `git ls-remote`,
/// never from a local tracking ref; that readback is this engine's only network contact.
pub fn verify_sawyer(
    root: &Path,
    pack: &SawyerContextPack,
    phase: SawyerPhase,
    whitelist: Option<&str>,
) -> Result<(), String> {
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let root = root.as_path();
    if Path::new(&pack.repo_root)
        .canonicalize()
        .map_err(|e| e.to_string())?
        != root
        || Path::new(git(root, &["rev-parse", "--show-toplevel"])?.trim_end())
            .canonicalize()
            .map_err(|e| e.to_string())?
            != root
    {
        return Err("Sawyer repository root mismatch".into());
    }
    let branch = format!("refs/heads/{}", pack.target_branch);
    if git(root, &["symbolic-ref", "HEAD"])?.trim_end() != branch {
        return Err("Target branch mismatch".into());
    }
    let approved = paths(pack.approved_files.iter().map(String::as_str))?;
    let excluded = paths(pack.excluded_files.iter().map(String::as_str))?;
    if approved.is_empty() || !approved.is_disjoint(&excluded) {
        return Err("Empty approval or overlapping exclusions".into());
    }
    if !excluded.is_empty() && whitelist.is_none() {
        return Err("Exclusions require a repository whitelist".into());
    }
    if let Some(file) = whitelist {
        let contents = read_config_file(root, file)?;
        let protected = paths(
            contents
                .lines()
                .filter(|s| !s.is_empty() && !s.starts_with('#')),
        )?;
        if !excluded.is_subset(&protected) || !approved.is_disjoint(&protected) {
            return Err("Excluded paths violate the configured whitelist".into());
        }
    }
    let dirty = git(
        root,
        &["status", "--porcelain=v1", "-z", "--no-renames", "-uall"],
    )?;
    for record in dirty.split_terminator('\0') {
        let path = record.get(3..).ok_or("Invalid Git status")?;
        if phase == SawyerPhase::PostPush && approved.contains(path) {
            return Err(format!(
                "Approved path still has outstanding changes: {path}"
            ));
        }
        if !approved.contains(path) && !excluded.contains(path) {
            return Err(format!("Unaccounted change {path}"));
        }
        if matches!(
            record.get(..2),
            Some("DD" | "AU" | "UD" | "UA" | "DU" | "AA" | "UU")
        ) {
            return Err(format!("Unmerged path {path}"));
        }
    }
    let index = git(
        root,
        &[
            "diff",
            "--cached",
            "--no-renames",
            "--name-only",
            "-z",
            "--",
        ],
    )?;
    let staged = paths(index.split_terminator('\0'))?;
    if !staged.is_subset(&approved) {
        return Err("Unapproved staged paths".into());
    }
    let required = signing_required(root, pack)?;
    match phase {
        SawyerPhase::Preflight => Ok(()),
        SawyerPhase::Staged if staged == approved => Ok(()),
        SawyerPhase::Staged => Err("Staged paths differ from approved paths".into()),
        SawyerPhase::PostPush => {
            let head = git(root, &["rev-parse", "--verify", "HEAD"])?;
            let head = head.trim_end();
            if pack.expected_commit_sha.as_deref() != Some(head) {
                return Err("Expected commit differs from HEAD".into());
            }
            let changed = git(
                root,
                &[
                    "diff-tree",
                    "--root",
                    "--no-commit-id",
                    "--name-only",
                    "--no-renames",
                    "-r",
                    "-z",
                    head,
                    "--",
                ],
            )?;
            if paths(changed.split_terminator('\0'))? != approved {
                return Err("Committed paths differ from approval".into());
            }
            if required {
                git(root, &["verify-commit", head])?;
            }
            let remote = pack.remote.as_deref().unwrap_or("origin");
            let url = git(
                root,
                &["remote", "get-url", "--push", "--all", "--", remote],
            )?;
            let destinations: Vec<_> = url.lines().collect();
            let [destination] = destinations.as_slice() else {
                return Err("Expected one configured push destination".into());
            };
            let target = pack.target_ref.as_deref().unwrap_or(&branch);
            if !target.starts_with("refs/heads/") {
                return Err("Expected full target branch ref".into());
            }
            git(root, &["check-ref-format", target])?;
            let readback = git(
                root,
                &[
                    "ls-remote",
                    "--exit-code",
                    "--refs",
                    "--",
                    destination,
                    target,
                ],
            )?;
            if readback.trim_end() != format!("{head}\t{target}") {
                return Err("Remote ref differs from expected HEAD".into());
            }
            Ok(())
        }
    }
}
