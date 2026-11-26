//! Deterministic cross-client thin adapter sync and contract-hash drift detection.
//!
//! Layer 4 (`orchestration`): renders version- and hash-stamped adapters for Git, Claude Code,
//! Hermes, and workflow skill shims, auditing or applying them under an explicit `--target-root`
//! while failing closed on symlinks and unmanaged regular files.

use crate::config_utils::sha256_hex;
use crate::constants::{EXIT_DRIFT, EXIT_PASS, EXIT_STATIC};
use crate::hooks::{render_hermes_plugin_init_py, render_hermes_plugin_yaml};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const CONTRACT_VERSION: u32 = 1;
pub const MANAGED_MARKER: &str = "birkin-managed-adapter";
pub const BIRKIN_VERSION: &str = env!("CARGO_PKG_VERSION");

const MAX_DIFF_LINES: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode { Check, Apply }

impl SyncMode {
    pub fn as_str(self) -> &'static str {
        match self { Self::Check => "check", Self::Apply => "apply" }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SyncTarget { Git, Claude, Hermes, Skills }

impl SyncTarget {
    pub const ALL: [Self; 4] = [Self::Git, Self::Claude, Self::Hermes, Self::Skills];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Git => "git", Self::Claude => "claude",
            Self::Hermes => "hermes", Self::Skills => "skills",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncState { Synchronized, Applied, Missing, Stale, Unmanaged, SymlinkRefused }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterSpec {
    pub target: SyncTarget,
    pub relative_path: String,
    pub executable: bool,
    pub template_sha256: String,
    pub expected_sha256: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdapterReport {
    pub target: String,
    pub relative_path: String,
    pub state: SyncState,
    pub executable: bool,
    pub template_sha256: String,
    pub expected_sha256: String,
    pub actual_sha256: Option<String>,
    pub detail: Option<String>,
    pub diff: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SyncSummary {
    pub total: usize,
    pub synchronized: usize,
    pub applied: usize,
    pub missing: usize,
    pub stale: usize,
    pub unmanaged: usize,
    pub symlink_refused: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncReport {
    pub command: String,
    pub mode: String,
    pub target_root: String,
    pub birkin_version: String,
    pub contract_version: u32,
    pub bundle_sha256: String,
    pub selected_targets: Vec<String>,
    pub status: String,
    pub exit_code: i32,
    pub summary: SyncSummary,
    pub targets: Vec<AdapterReport>,
}

pub fn parse_targets(raw: &[String]) -> Result<Vec<SyncTarget>, String> {
    if raw.is_empty() {
        return Ok(SyncTarget::ALL.to_vec());
    }
    let mut selected = BTreeSet::new();
    for item in raw {
        match item.trim().to_ascii_lowercase().as_str() {
            "all" => selected.extend(SyncTarget::ALL),
            "git" => { selected.insert(SyncTarget::Git); }
            "claude" => { selected.insert(SyncTarget::Claude); }
            "hermes" => { selected.insert(SyncTarget::Hermes); }
            "skills" => { selected.insert(SyncTarget::Skills); }
            other => {
                return Err(format!(
                    "Unknown --target '{other}' (expected one of: git, claude, hermes, skills, all)"
                ));
            }
        }
    }
    Ok(selected.into_iter().collect())
}

fn template_hash(canonical_body: &str) -> String {
    sha256_hex(format!("contract_version={CONTRACT_VERSION}\n{canonical_body}").as_bytes())
}

fn stamp_comment(target: SyncTarget, tmpl_sha: &str) -> String {
    format!(
        "# {MANAGED_MARKER}: target={} version={BIRKIN_VERSION} contract_version={CONTRACT_VERSION} template_sha256={tmpl_sha}",
        target.as_str()
    )
}

#[cfg(unix)]
fn is_eloop(err: &io::Error) -> bool { err.raw_os_error() == Some(libc::ELOOP) }
#[cfg(not(unix))]
fn is_eloop(_err: &io::Error) -> bool { false }

fn make_adapter(
    target: SyncTarget, relative_path: &str, executable: bool, template_sha256: String, content: String,
) -> AdapterSpec {
    let expected_sha256 = sha256_hex(content.as_bytes());
    AdapterSpec { target, relative_path: relative_path.to_string(), executable, template_sha256, expected_sha256, content }
}

fn render_git_adapter() -> AdapterSpec {
    let body = concat!(
        "set -eu\n\n",
        "if [ \"${BIRKIN_SKIP_HOOK:-0}\" = \"1\" ]; then\n  exit 0\nfi\n\n",
        "if ! command -v birkin >/dev/null 2>&1; then\n",
        "  echo \"[birkin] ERROR: birkin binary not found in PATH; install birkin or set BIRKIN_SKIP_HOOK=1 to bypass.\" >&2\n",
        "  exit 1\nfi\n\n",
        "repo_root=\"$(git rev-parse --show-toplevel 2>/dev/null || pwd)\"\n",
        "exec birkin hook pre-commit \"$repo_root\"\n",
    );
    let tmpl_sha = template_hash(body);
    let content = format!(
        "#!/bin/sh\n{}\n# birkin-managed-pre-commit\n{body}",
        stamp_comment(SyncTarget::Git, &tmpl_sha)
    );
    make_adapter(SyncTarget::Git, "git-hooks/pre-commit", true, tmpl_sha, content)
}

fn render_claude_adapter() -> AdapterSpec {
    let hooks_body = json!({
        "PostToolUse": [{
            "matcher": "Write|Edit|MultiEdit",
            "hooks": [{
                "type": "command",
                "command": "birkin hook post-edit --surface claude --claude-stdin",
                "timeout": 10
            }]
        }]
    });
    let tmpl_sha = template_hash(&serde_json::to_string(&hooks_body).unwrap_or_default());
    let doc = json!({
        "_birkin_managed": {
            "marker": MANAGED_MARKER,
            "target": SyncTarget::Claude.as_str(),
            "version": BIRKIN_VERSION,
            "contract_version": CONTRACT_VERSION,
            "template_sha256": tmpl_sha,
        },
        "hooks": hooks_body,
    });
    let rendered = format!("{}\n", serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
    make_adapter(SyncTarget::Claude, "claude/birkin-hooks.json", false, tmpl_sha, rendered)
}

fn render_hermes_adapters() -> Vec<AdapterSpec> {
    let yaml_body = render_hermes_plugin_yaml();
    let yaml_sha = template_hash(&yaml_body);
    let yaml_content = format!("{}\n{yaml_body}", stamp_comment(SyncTarget::Hermes, &yaml_sha));

    let py_body = render_hermes_plugin_init_py("birkin");
    let py_sha = template_hash(&py_body);
    let py_content = format!("{}\n{py_body}", stamp_comment(SyncTarget::Hermes, &py_sha));

    vec![
        make_adapter(SyncTarget::Hermes, "hermes/plugins/birkin/plugin.yaml", false, yaml_sha, yaml_content),
        make_adapter(SyncTarget::Hermes, "hermes/plugins/birkin/__init__.py", false, py_sha, py_content),
    ]
}

fn render_skill_adapters() -> Vec<AdapterSpec> {
    const SHIMS: [(&str, &str); 6] = [
        ("plan-verify.sh", "plan verify"),
        ("unit-admit.sh", "unit admit"),
        ("scope-check.sh", "unit verify-scope"),
        ("stage-verify.sh", "stage verify"),
        ("sawyer-verify.sh", "sawyer verify"),
        ("review-closure.sh", "review-closure verify"),
    ];
    SHIMS
        .iter()
        .map(|(file, sub)| {
            let body = format!(
                "set -eu\n\nif ! command -v birkin >/dev/null 2>&1; then\n  echo \"[birkin] ERROR: birkin binary not found in PATH.\" >&2\n  exit 5\nfi\n\nexec birkin {sub} \"$@\"\n"
            );
            let tmpl_sha = template_hash(&body);
            let content = format!("#!/bin/sh\n{}\n{body}", stamp_comment(SyncTarget::Skills, &tmpl_sha));
            make_adapter(SyncTarget::Skills, &format!("skills/birkin/{file}"), true, tmpl_sha, content)
        })
        .collect()
}

pub fn render_adapters(targets: &[SyncTarget]) -> Vec<AdapterSpec> {
    let mut out = Vec::new();
    for target in targets {
        match target {
            SyncTarget::Git => out.push(render_git_adapter()),
            SyncTarget::Claude => out.push(render_claude_adapter()),
            SyncTarget::Hermes => out.extend(render_hermes_adapters()),
            SyncTarget::Skills => out.extend(render_skill_adapters()),
        }
    }
    out
}

pub fn compute_bundle_sha256(adapters: &[AdapterSpec]) -> String {
    let mut payload = format!("contract_version={CONTRACT_VERSION}\nversion={BIRKIN_VERSION}\n");
    for a in adapters {
        payload.push_str(&format!("{}={}\n", a.relative_path, a.expected_sha256));
    }
    sha256_hex(payload.as_bytes())
}

enum PathProbe {
    Missing,
    RegularFile(PathBuf),
    Symlink(String),
    NonFileBlocked(String),
}

fn split_rel_segments(relative_path: &str) -> Result<Vec<&str>, String> {
    let segs: Vec<&str> = relative_path.split('/').collect();
    if segs.is_empty()
        || segs.iter().any(|s| s.is_empty() || *s == "." || *s == ".." || s.contains('\\'))
    {
        return Err(format!("Invalid adapter relative path: {relative_path}"));
    }
    Ok(segs)
}

fn probe_path_from_root(target_root: &Path, relative_path: &str) -> Result<PathProbe, String> {
    let segs = split_rel_segments(relative_path)?;
    let mut cur = target_root.to_path_buf();
    let mut rel_parts = Vec::with_capacity(segs.len());
    for (idx, seg) in segs.iter().enumerate() {
        cur.push(seg);
        rel_parts.push(*seg);
        let is_leaf = idx + 1 == segs.len();
        match fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => return Ok(PathProbe::Symlink(rel_parts.join("/"))),
            Ok(meta) if !is_leaf && !meta.file_type().is_dir() => {
                return Ok(PathProbe::NonFileBlocked(format!("Intermediate path '{}' is not a directory.", rel_parts.join("/"))));
            }
            Ok(meta) if is_leaf && !meta.file_type().is_file() => {
                return Ok(PathProbe::NonFileBlocked(format!("Target path '{}' exists and is not a regular file.", rel_parts.join("/"))));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(PathProbe::Missing),
            Err(e) => return Err(format!("Failed inspecting {} ({}): {e}", cur.display(), rel_parts.join("/"))),
        }
    }
    Ok(PathProbe::RegularFile(cur))
}

fn read_regular_nofollow(path: &Path) -> Result<Option<(Vec<u8>, bool)>, String> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = match opts.open(path) {
        Ok(f) => f,
        Err(e) if is_eloop(&e) => return Ok(None),
        Err(e) => return Err(format!("Failed reading {}: {e}", path.display())),
    };
    #[cfg(unix)]
    let is_exec = {
        use std::os::unix::fs::PermissionsExt;
        let meta = file.metadata().map_err(|e| format!("Failed metadata for {}: {e}", path.display()))?;
        (meta.permissions().mode() & 0o111) != 0
    };
    #[cfg(not(unix))]
    let is_exec = true;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|e| format!("Failed reading {}: {e}", path.display()))?;
    Ok(Some((buf, is_exec)))
}

enum WriteOutcome {
    Written,
    SymlinkRefused(String),
    NonFileBlocked(String),
}

fn write_adapter_safe(
    target_root: &Path,
    relative_path: &str,
    content: &[u8],
    executable: bool,
) -> Result<WriteOutcome, String> {
    let segs = split_rel_segments(relative_path)?;
    let mut cur = target_root.to_path_buf();
    let mut rel_parts = Vec::with_capacity(segs.len());
    for seg in &segs[..segs.len() - 1] {
        cur.push(seg);
        rel_parts.push(*seg);
        match fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => return Ok(WriteOutcome::SymlinkRefused(rel_parts.join("/"))),
            Ok(meta) if !meta.file_type().is_dir() => {
                return Ok(WriteOutcome::NonFileBlocked(format!("Intermediate path '{}' is not a directory.", rel_parts.join("/"))));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&cur).map_err(|err| format!("Failed creating directory {}: {err}", cur.display()))?;
            }
            Err(e) => return Err(format!("Failed inspecting {}: {e}", cur.display())),
        }
    }

    let leaf = segs[segs.len() - 1];
    cur.push(leaf);
    rel_parts.push(leaf);
    match fs::symlink_metadata(&cur) {
        Ok(meta) if meta.file_type().is_symlink() => return Ok(WriteOutcome::SymlinkRefused(rel_parts.join("/"))),
        Ok(meta) if !meta.file_type().is_file() => {
            return Ok(WriteOutcome::NonFileBlocked(format!("Target path '{}' exists and is not a regular file.", rel_parts.join("/"))));
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("Failed inspecting {}: {e}", cur.display())),
    }

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = match opts.open(&cur) {
        Ok(f) => f,
        Err(e) if is_eloop(&e) => return Ok(WriteOutcome::SymlinkRefused(rel_parts.join("/"))),
        Err(e) => return Err(format!("Failed opening {} for write: {e}", cur.display())),
    };
    file.write_all(content).map_err(|e| format!("Failed writing {}: {e}", cur.display()))?;
    file.flush().map_err(|e| format!("Failed flushing {}: {e}", cur.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o755 } else { 0o644 };
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| format!("Failed setting permissions on {}: {e}", cur.display()))?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    Ok(WriteOutcome::Written)
}

fn is_managed_bytes(bytes: &[u8]) -> bool {
    let needle = MANAGED_MARKER.as_bytes();
    bytes.windows(needle.len()).any(|w| w == needle)
}

fn compact_line_diff(actual_bytes: &[u8], expected: &str) -> Vec<String> {
    let Ok(actual) = std::str::from_utf8(actual_bytes) else {
        return vec!["(non-UTF-8 content differs from expected UTF-8 adapter)".into()];
    };
    let a_lines: Vec<&str> = actual.lines().collect();
    let e_lines: Vec<&str> = expected.lines().collect();
    let mut diff = Vec::new();
    let mut extra = 0usize;
    for idx in 0..a_lines.len().max(e_lines.len()) {
        let (a, e) = (a_lines.get(idx).copied(), e_lines.get(idx).copied());
        if a == e {
            continue;
        }
        for (prefix, line) in [('-', a), ('+', e)] {
            if let Some(l) = line {
                if diff.len() < MAX_DIFF_LINES {
                    diff.push(format!("L{}: {prefix}{l}", idx + 1));
                } else {
                    extra += 1;
                }
            }
        }
    }
    if diff.is_empty() && actual != expected {
        diff.push("(trailing newline or line-ending difference)".into());
    }
    if extra > 0 {
        diff.push(format!("... ({extra} more diff line(s) truncated)"));
    }
    diff
}

fn validate_target_root(target_root: &Path) -> Result<(), String> {
    if target_root.as_os_str().is_empty() {
        return Err("--target-root must be a non-empty directory path.".into());
    }
    let meta = fs::symlink_metadata(target_root)
        .map_err(|e| format!("Invalid --target-root {}: {e}", target_root.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!("Refusing symlink --target-root {}; supply a real directory path.", target_root.display()));
    }
    if !meta.file_type().is_dir() {
        return Err(format!("--target-root {} is not a directory.", target_root.display()));
    }
    Ok(())
}

fn report_entry(
    adapter: &AdapterSpec,
    state: SyncState,
    actual_sha256: Option<String>,
    detail: Option<String>,
    diff: Vec<String>,
) -> AdapterReport {
    AdapterReport {
        target: adapter.target.as_str().to_string(),
        relative_path: adapter.relative_path.clone(),
        state,
        executable: adapter.executable,
        template_sha256: adapter.template_sha256.clone(),
        expected_sha256: adapter.expected_sha256.clone(),
        actual_sha256,
        detail,
        diff,
    }
}

fn apply_adapter_write(
    target_root: &Path,
    adapter: &AdapterSpec,
    prior_sha: Option<String>,
) -> Result<AdapterReport, String> {
    match write_adapter_safe(target_root, &adapter.relative_path, adapter.content.as_bytes(), adapter.executable)? {
        WriteOutcome::Written => Ok(report_entry(adapter, SyncState::Applied, Some(adapter.expected_sha256.clone()), None, Vec::new())),
        WriteOutcome::SymlinkRefused(sym) => Ok(report_entry(adapter, SyncState::SymlinkRefused, None, Some(format!("Refused symlink at '{sym}'.")), Vec::new())),
        WriteOutcome::NonFileBlocked(reason) => Ok(report_entry(adapter, SyncState::Unmanaged, prior_sha, Some(reason), Vec::new())),
    }
}

fn evaluate_adapter(target_root: &Path, adapter: &AdapterSpec, mode: SyncMode) -> Result<AdapterReport, String> {
    match probe_path_from_root(target_root, &adapter.relative_path)? {
        PathProbe::Symlink(sym) => Ok(report_entry(
            adapter, SyncState::SymlinkRefused, None,
            Some(format!("Refused symlink at '{sym}'; never reads or writes through symlinks.")),
            Vec::new(),
        )),
        PathProbe::NonFileBlocked(reason) => Ok(report_entry(adapter, SyncState::Unmanaged, None, Some(reason), Vec::new())),
        PathProbe::Missing => match mode {
            SyncMode::Check => Ok(report_entry(
                adapter, SyncState::Missing, None,
                Some("Managed adapter is missing.".into()),
                vec!["--- (missing)".into(), format!("+++ expected ({} lines)", adapter.content.lines().count())],
            )),
            SyncMode::Apply => apply_adapter_write(target_root, adapter, None),
        },
        PathProbe::RegularFile(leaf_path) => {
            let Some((actual_bytes, is_exec)) = read_regular_nofollow(&leaf_path)? else {
                return Ok(report_entry(adapter, SyncState::SymlinkRefused, None, Some(format!("Refused symlink at '{}'.", adapter.relative_path)), Vec::new()));
            };
            let actual_sha = sha256_hex(&actual_bytes);
            if !is_managed_bytes(&actual_bytes) {
                return Ok(report_entry(
                    adapter, SyncState::Unmanaged, Some(actual_sha),
                    Some(format!("Existing regular file lacks '{MANAGED_MARKER}' header; refusing to overwrite.")),
                    vec!["--- (unmanaged file; content omitted)".into(), format!("+++ expected ({} lines)", adapter.content.lines().count())],
                ));
            }
            let bytes_match = actual_bytes == adapter.content.as_bytes();
            let mode_ok = !adapter.executable || is_exec;
            if bytes_match && mode_ok {
                return Ok(report_entry(adapter, SyncState::Synchronized, Some(actual_sha), None, Vec::new()));
            }
            match mode {
                SyncMode::Check => {
                    let mut diff = if bytes_match { Vec::new() } else { compact_line_diff(&actual_bytes, &adapter.content) };
                    if !mode_ok {
                        diff.push("mode: not executable -> expected 0o755".into());
                    }
                    Ok(report_entry(adapter, SyncState::Stale, Some(actual_sha), Some("Managed adapter differs from canonical template.".into()), diff))
                }
                SyncMode::Apply => apply_adapter_write(target_root, adapter, Some(actual_sha)),
            }
        }
    }
}

pub fn run_client_sync(target_root: &Path, mode: SyncMode, targets: &[SyncTarget]) -> Result<SyncReport, String> {
    validate_target_root(target_root)?;
    let adapters = render_adapters(targets);
    let bundle_sha256 = compute_bundle_sha256(&adapters);

    let mut summary = SyncSummary { total: adapters.len(), ..SyncSummary::default() };
    let mut reports = Vec::with_capacity(adapters.len());
    for adapter in &adapters {
        let entry = evaluate_adapter(target_root, adapter, mode)?;
        match entry.state {
            SyncState::Synchronized => summary.synchronized += 1,
            SyncState::Applied => summary.applied += 1,
            SyncState::Missing => summary.missing += 1,
            SyncState::Stale => summary.stale += 1,
            SyncState::Unmanaged => summary.unmanaged += 1,
            SyncState::SymlinkRefused => summary.symlink_refused += 1,
        }
        reports.push(entry);
    }

    let (status, exit_code) = match mode {
        SyncMode::Check if summary.synchronized == summary.total => ("PASS".into(), EXIT_PASS),
        SyncMode::Check => ("DRIFT".into(), EXIT_DRIFT),
        SyncMode::Apply if summary.unmanaged > 0 || summary.symlink_refused > 0 => ("FAIL".into(), EXIT_STATIC),
        SyncMode::Apply => ("PASS".into(), EXIT_PASS),
    };

    Ok(SyncReport {
        command: "sync".into(),
        mode: mode.as_str().into(),
        target_root: target_root.to_string_lossy().into_owned(),
        birkin_version: BIRKIN_VERSION.into(),
        contract_version: CONTRACT_VERSION,
        bundle_sha256,
        selected_targets: targets.iter().map(|t| t.as_str().to_string()).collect(),
        status,
        exit_code,
        summary,
        targets: reports,
    })
}

pub fn format_sync_human(report: &SyncReport) -> String {
    let short_bundle: String = report.bundle_sha256.chars().take(12).collect();
    let mut lines = vec![format!(
        "birkin sync --{} ({}): status={} bundle={} total={} synced={} applied={} missing={} stale={} unmanaged={} symlink_refused={}",
        report.mode, report.target_root, report.status, short_bundle,
        report.summary.total, report.summary.synchronized, report.summary.applied,
        report.summary.missing, report.summary.stale, report.summary.unmanaged,
        report.summary.symlink_refused,
    )];
    for t in &report.targets {
        let tag = serde_json::to_value(t.state).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_else(|| "unknown".into());
        lines.push(format!("  [{tag}] {}: {}", t.target, t.relative_path));
        if let Some(ref detail) = t.detail {
            lines.push(format!("    {detail}"));
        }
        for d in t.diff.iter().take(10) {
            lines.push(format!("    {d}"));
        }
    }
    lines.join("\n")
}
