use birkin::project_init::detect_project_spec;
use birkin::project_models::ProjectSpec;
use birkin::sensors::run_project_sensors;
use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_birkin");

struct Repo {
    temp: TempDir,
    root: PathBuf,
}

impl Repo {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("repo");
        fs::create_dir_all(root.join(".birkin")).unwrap();
        let repo = Self { temp, root };
        repo.ok("git", &["init", "-q"]);
        fs::write(repo.root.join(".birkin/config.yaml"), "version: 1\nproject: {name: example}\ninvariants: {forbid_debug_leftovers: true}\ntelemetry: {enabled: true, ledger_path: .receipts.jsonl}\n").unwrap();
        fs::write(repo.root.join("AGENTS.md"), "# Example\n").unwrap();
        repo.ok("git", &["add", "."]);
        repo.ok("git", &["commit", "-qm", "initial"]);
        repo
    }

    fn cmd(&self, exe: &str, args: &[&str]) -> Command {
        let inherited_path = env::var_os("PATH").unwrap();
        let paths = std::iter::once(Path::new(BIN).parent().unwrap().to_owned())
            .chain(env::split_paths(&inherited_path));
        let mut cmd = Command::new(exe);
        cmd.args(args)
            .current_dir(&self.root)
            .env(
                "GIT_CONFIG_GLOBAL",
                self.temp.path().join("empty.gitconfig"),
            )
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.org")
            .env("GIT_COMMITTER_EMAIL", "test@example.org")
            .env("PATH", env::join_paths(paths).unwrap());
        cmd
    }

    fn ok(&self, exe: &str, args: &[&str]) -> Output {
        let out = self.cmd(exe, args).output().unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
        out
    }
}

#[test]
fn concurrent_cli_receipts_pin_untracked_contents() {
    let repo = Repo::new();
    let name = if cfg!(windows) {
        "notes space.txt"
    } else {
        "notes\nspace.txt"
    };
    let path = repo.root.join(name);
    fs::write(&path, "one").unwrap();
    let children: Vec<_> = (0..16)
        .map(|_| {
            repo.cmd(BIN, &["check", "--json"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for child in children {
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{out:?}");
    }
    let log = fs::read_to_string(repo.root.join(".receipts.jsonl")).unwrap();
    assert_eq!(log.lines().count(), 16);
    let args = ["receipt", "verify", "--require", "check", "--json"];
    let before: Value = serde_json::from_slice(&repo.ok(BIN, &args).stdout).unwrap();
    assert_eq!(before["chain_ok"], true);
    fs::write(&path, "two").unwrap();
    let out = repo.cmd(BIN, &args).output().unwrap();
    assert!(!out.status.success());
    let after: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(after["missing"][0], "check");
    assert_ne!(after["tree_digest"], before["tree_digest"]);
}

#[test]
fn linked_and_main_worktrees_execute_the_installed_hook() {
    let repo = Repo::new();
    let linked = repo.temp.path().join("linked");
    repo.ok(
        "git",
        &["worktree", "add", "--detach", linked.to_str().unwrap()],
    );
    for root in [&linked, &repo.root] {
        let out = repo.ok(
            BIN,
            &["install-hooks", "--target", "git", root.to_str().unwrap()],
        );
        assert!(out.status.success());
        fs::write(root.join("app.py"), "x = 1\n").unwrap();
        repo.ok("git", &["-C", root.to_str().unwrap(), "add", "app.py"]);
        repo.ok(
            "git",
            &["-C", root.to_str().unwrap(), "commit", "-qm", "valid"],
        );
        fs::write(root.join("app.py"), concat!("break", "point()\n")).unwrap();
        repo.ok("git", &["-C", root.to_str().unwrap(), "add", "app.py"]);
        let bad = repo
            .cmd(
                "git",
                &["-C", root.to_str().unwrap(), "commit", "-qm", "invalid"],
            )
            .output()
            .unwrap();
        assert!(!bad.status.success());
        assert!(
            String::from_utf8_lossy(&bad.stderr).contains("PYTHON_BREAKPOINT"),
            "{bad:?}"
        );
    }
}

#[test]
fn installer_preserves_custom_and_unmanaged_hooks() {
    let repo = Repo::new();
    let custom = repo.temp.path().join("custom hooks");
    fs::create_dir(&custom).unwrap();
    repo.ok(
        "git",
        &["config", "core.hooksPath", custom.to_str().unwrap()],
    );
    for dir in [&custom, &repo.root.join(".git/hooks")] {
        let hook = dir.join("pre-commit");
        fs::write(&hook, "#!/bin/sh\nexit 0\n").unwrap();
        let out = repo
            .cmd(BIN, &["install-hooks", "--target", "git"])
            .output()
            .unwrap();
        assert!(!out.status.success());
        let diagnostic = String::from_utf8_lossy(&out.stderr);
        assert!(
            diagnostic.contains(hook.to_str().unwrap())
                && diagnostic.contains("birkin hook pre-commit"),
            "{diagnostic}"
        );
        assert_eq!(fs::read_to_string(&hook).unwrap(), "#!/bin/sh\nexit 0\n");
        if dir == &custom {
            repo.ok("git", &["config", "--unset", "core.hooksPath"]);
        }
    }
}

#[test]
fn generated_exemptions_apply_only_to_line_counts() {
    let repo = Repo::new();
    let mut spec = detect_project_spec(&repo.root);
    spec.architecture.max_file_lines = 1;
    spec.invariants.forbid_debug_leftovers = true;
    let paths: Vec<_> = [
        "sample_test.go",
        "sub/test_app.py",
        "app.test.ts",
        "tests/app.rs",
        "artifact/fixture/app.js",
        "generated/mod.rs",
        "src/core.rs",
    ]
    .iter()
    .map(|p| repo.root.join(p))
    .collect();
    for path in &paths {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, concat!("x = 1\nbreak", "point()\n")).unwrap();
    }
    let check = |spec: &ProjectSpec| run_project_sensors(&repo.root, spec, Some(&paths)).0;
    let findings = check(&spec);
    let long: Vec<_> = findings
        .iter()
        .filter(|f| f.rule == "ARCH_FILE_TOO_LARGE")
        .map(|f| f.file.as_deref())
        .collect();
    assert_eq!(long, [Some("src/core.rs")]);
    assert!(findings
        .iter()
        .any(|f| f.rule.contains("PYTHON_BREAKPOINT")));
    let explicit: ProjectSpec = serde_yaml::from_str("version: 1\nproject: {name: example}\narchitecture: {max_file_lines: 1, file_line_exemptions: []}\n").unwrap();
    assert_eq!(
        check(&explicit)
            .iter()
            .filter(|f| f.rule == "ARCH_FILE_TOO_LARGE")
            .count(),
        paths.len()
    );
}

#[test]
fn check_surfaces_receipt_write_failure_instead_of_ignoring_it() {
    let repo = Repo::new();
    let blocked_dir = repo.temp.path().join("ledger-is-a-directory");
    fs::create_dir(&blocked_dir).unwrap();
    fs::write(
        repo.root.join(".birkin/config.yaml"),
        format!(
            "version: 1\nproject: {{name: example}}\ntelemetry: {{enabled: true, ledger_path: {:?}}}\n",
            blocked_dir.to_string_lossy()
        ),
    )
    .unwrap();
    let out = repo.cmd(BIN, &["check", "--json"]).output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        parsed["receipt_sha256"].is_null(),
        "expected null receipt_sha256: {parsed}"
    );
    let err = parsed["receipt_error"].as_str().unwrap_or("");
    assert!(!err.is_empty(), "expected receipt_error in JSON: {parsed}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("failed recording receipt"),
        "expected stderr receipt warning, got: {stderr}"
    );
}
