use birkin::scope_contract::{collect_git_changed_paths, verify_task_scope, PathAuthority};
use birkin::workflow_models::PlanTaskSpec;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn task() -> PlanTaskSpec {
    PlanTaskSpec {
        id: "scope".into(),
        title: "Edit source files".into(),
        context: "Local fixture".into(),
        expected_behavior: "Keep writes within scope".into(),
        status: "ready".into(),
        depends_on: vec![],
        allowed_paths: vec!["src/".into()],
        forbidden_paths: vec!["src/private/".into()],
        verification_output_paths: vec!["out/".into()],
        checkout_root: None,
        acceptance: vec!["Writes stay in scope".into()],
        verification: vec![],
        stop_conditions: vec![],
        owner: "worker".into(),
        completion_evidence: vec![],
    }
}

// Each expected pair gives source-edit and verification-output admission, in that order.
fn assert_scope(root: &Path, path: &str, source: bool, verification: bool) {
    for (authority, expected) in [
        (PathAuthority::SourceEdit, source),
        (PathAuthority::VerificationOutput, verification),
    ] {
        let result = verify_task_scope(root, &task(), &[path.to_owned()], authority, &[]);
        let [decision] = result.decisions.as_slice() else {
            panic!("expected a single decision for {path:?}");
        };
        assert_eq!(decision.path, path);
        assert_eq!(decision.admitted, expected, "{authority:?} {decision:?}");
        assert_eq!(result.admitted, expected, "{authority:?} {path:?}");
    }
}

#[test]
fn new_paths_require_a_directory_as_their_existing_ancestor() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    fs::create_dir(root.join("src")).unwrap();
    fs::write(root.join("src/file"), "fixture").unwrap();
    assert_scope(root, "src/new/deep/file", true, true);
    assert_scope(root, "out/new/deep/file", false, true);
    assert_scope(root, "src/file", true, true);
    assert_scope(root, "src/file/", false, false);
    assert_scope(root, "src/file/.", false, false);
    assert_scope(root, "src/file/child", false, false);
    assert_scope(root, "src/file/nested/child", false, false);
}

#[cfg(unix)]
mod unix_paths {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::{ffi::OsStrExt, fs::symlink};

    #[test]
    fn inaccessible_ancestor_cannot_admit_a_missing_path() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("src");
        fs::create_dir(&dir).unwrap();
        let permissions = dir.metadata().unwrap().permissions();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).unwrap();
        let error = fs::symlink_metadata(dir.join("new")).unwrap_err();
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            // Privileged test runners may traverse mode-000 directories.
            assert_scope(tmp.path(), "src/new", false, false);
        } else {
            assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        }
        fs::set_permissions(&dir, permissions).unwrap();
        assert_scope(tmp.path(), "src/new", true, true);
    }

    #[test]
    fn concurrent_declarations_require_resolvable_names() {
        use birkin::workflow_models::ActiveUnitRecord;
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("src/real")).unwrap();
        symlink("real", root.join("src/alias")).unwrap();
        symlink("missing", root.join("src/broken")).unwrap();
        for (mine, theirs, admitted) in [
            ("src/real/file", "src/alias", false),
            ("src/alias/file", "src/real", false),
            ("src/new", "src/broken/file", false),
            ("src/real/file", "src/alias/other", true),
        ] {
            let peer = ActiveUnitRecord {
                task_id: "peer".into(),
                checkout_root: root.to_str().unwrap().into(),
                write_paths: vec![theirs.into()],
            };
            let outcome = verify_task_scope(
                root,
                &task(),
                &[mine.into()],
                PathAuthority::SourceEdit,
                &[peer],
            );
            assert_eq!(outcome.admitted, admitted, "{mine}, {theirs}");
            assert_eq!(outcome.findings.is_empty(), admitted);
        }
    }

    #[test]
    fn unresolved_links_deny_leaf_and_descendant_paths() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir(root.join("src")).unwrap();
        symlink("missing", root.join("src/dangling")).unwrap();
        symlink("dangling", root.join("src/chain")).unwrap();
        symlink("dangling/subdir", root.join("src/nested")).unwrap();
        symlink("loop-b", root.join("src/loop-a")).unwrap();
        symlink("loop-a", root.join("src/loop-b")).unwrap();
        fs::create_dir(root.join("src/subdir")).unwrap();
        symlink("subdir", root.join("src/dir-alias")).unwrap();
        symlink("missing", root.join("src/subdir/broken")).unwrap();
        for link in [
            "src/dangling",
            "src/chain",
            "src/nested",
            "src/loop-a",
            "src/dir-alias/broken",
        ] {
            assert_scope(root, link, false, false);
            assert_scope(root, &format!("{link}/new/deep/file"), false, false);
        }
    }

    #[test]
    fn both_path_names_must_be_owned_for_the_requested_authority() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        for dir in ["src/private", "out", "other"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        for dir in ["src", "src/private", "out", "other"] {
            fs::write(root.join(dir).join("existing"), "fixture").unwrap();
        }
        for (alias, target, source, verification) in [
            ("src/to-source", ".", true, true),
            ("out/to-output", ".", false, true),
            ("src/to-output", "../out", false, true),
            ("out/to-source", "../src", false, true),
            ("other/to-source", "../src", false, false),
            ("src/to-other", "../other", false, false),
            ("other/to-output", "../out", false, false),
            ("out/to-other", "../other", false, false),
            ("src/private/to-source", "..", false, false),
            ("src/to-private", "private", false, false),
            ("src/private/to-output", "../../out", false, false),
            ("out/to-private", "../src/private", false, false),
        ] {
            symlink(target, root.join(alias)).unwrap();
            for tail in ["existing", "new/deep/file"] {
                assert_scope(root, &format!("{alias}/{tail}"), source, verification);
            }
        }
    }

    #[test]
    fn unix_backslashes_cannot_turn_a_filename_into_an_owned_directory() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir(root.join("src")).unwrap();
        fs::write(root.join("src/file"), "owned").unwrap();
        for literal in [r"src\file", r"out\file"] {
            fs::write(root.join(literal), "separate file").unwrap();
            assert_scope(root, literal, false, false);
        }
        symlink(r"../src\file", root.join("src/alias")).unwrap();
        assert_scope(root, "src/alias", false, false);
        assert_scope(root, "src/file", true, true);
    }

    #[test]
    fn non_utf8_canonical_component_denies_even_under_an_owned_directory() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir(root.join("src")).unwrap();
        let raw = OsStr::from_bytes(b"name-\xff");
        match fs::create_dir(root.join("src").join(raw)) {
            Ok(()) => (),
            // Some Unix volumes require UTF-8 names, so this fixture cannot exist there.
            Err(e) if matches!(e.raw_os_error(), Some(libc::EILSEQ | libc::EINVAL)) => return,
            Err(e) => panic!("create non-UTF-8 directory: {e}"),
        }
        symlink(raw, root.join("src/alias")).unwrap();
        assert_scope(root, "src/alias", false, false);
        assert_scope(root, "src/alias/new/file", false, false);
    }
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(root)
        .args([
            "-c",
            "core.hooksPath=.git/unused-hooks",
            "-c",
            "commit.gpgSign=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn staged_rename_keeps_both_names_with_rename_detection_on_or_off() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    git(root, &["init", "-q"]);
    fs::create_dir_all(root.join("src/private")).unwrap();
    fs::write(root.join("src/private/old name"), "rename fixture\n").unwrap();
    git(root, &["add", "-f", "--", "src/private/old name"]);
    git(
        root,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
    );
    git(root, &["mv", "--", "src/private/old name", "src/new name"]);
    for setting in ["true", "false"] {
        git(root, &["config", "diff.renames", setting]);
        git(root, &["config", "status.renames", setting]);
        for staged_only in [true, false] {
            let paths = collect_git_changed_paths(root, staged_only).unwrap();
            assert_eq!(
                paths,
                ["src/new name", "src/private/old name"],
                "renames={setting}, staged_only={staged_only}"
            );
            for authority in [PathAuthority::SourceEdit, PathAuthority::VerificationOutput] {
                let result = verify_task_scope(root, &task(), &paths, authority, &[]);
                assert!(!result.admitted);
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_git_name_fails_collection_in_both_modes() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    git(root, &["init", "-q"]);
    fs::write(root.join("plain"), "blob").unwrap();
    git(root, &["add", "-f", "--", "plain"]);
    let oid = git(root, &["rev-parse", ":plain"]);
    // The index can hold this name even on volumes that require UTF-8 filenames.
    let output = Command::new("git")
        .current_dir(root)
        .args(["update-index", "--add", "--cacheinfo", "100644", oid.trim()])
        .arg(OsStr::from_bytes(b"src/name-\xff"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for staged_only in [true, false] {
        let result = collect_git_changed_paths(root, staged_only);
        assert!(result.is_err(), "staged_only={staged_only}: {result:?}");
    }
}
