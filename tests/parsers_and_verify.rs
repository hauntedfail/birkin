//! Multi-language import parser tests (Python, Go, Rust, Lean 4, TS/JS),
//! canonical verify timeout enforcement, and project auto-detection tests.

use birkin::imports_parser::extract_imports_for_file;
use birkin::project_init::detect_project_spec;
use birkin::project_models::{ForbiddenImportRule, LayerSpec, ProjectSpec, VerifyCommand};
use birkin::sensors::run_project_sensors;
use birkin::verify::run_verify_commands;
use std::fs;
use std::time::Instant;
use tempfile::TempDir;

#[test]
fn parsers_extract_python_go_rust_ts_and_lean_imports() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();

    // Python: relative + absolute + ignores comments & triple-quoted docstrings
    fs::create_dir_all(root.join("src/pkg")).unwrap();
    fs::write(root.join("src/pkg/__init__.py"), "").unwrap();
    fs::write(root.join("src/pkg/core.py"), "X = 1\n").unwrap();
    let py_app = root.join("src/pkg/app.py");
    fs::write(
        &py_app,
        "\"\"\"\nimport fake_docstring_mod\n\"\"\"\n# import fake_comment_mod\nfrom . import core\nimport pkg.core\n",
    )
    .unwrap();
    let py_edges = extract_imports_for_file(&py_app, root, None);
    let py_resolved: Vec<Option<&str>> = py_edges.iter().map(|e| e.resolved_path.as_deref()).collect();
    assert!(py_resolved.contains(&Some("src/pkg/core.py")), "py_edges={py_edges:?}");
    assert!(!py_edges.iter().any(|e| e.raw.contains("fake_")), "py_edges={py_edges:?}");

    // Go: local module vs stdlib
    fs::write(root.join("go.mod"), "module example.com/demo\n\ngo 1.23\n").unwrap();
    fs::create_dir_all(root.join("internal/core")).unwrap();
    fs::create_dir_all(root.join("cmd/app")).unwrap();
    let go_main = root.join("cmd/app/main.go");
    fs::write(
        &go_main,
        "package main\nimport (\n\t\"fmt\"\n\t\"example.com/demo/internal/core\"\n)\n",
    )
    .unwrap();
    let go_edges = extract_imports_for_file(&go_main, root, Some("example.com/demo"));
    assert!(go_edges.iter().any(|e| e.raw == "fmt" && e.resolved_path.is_none()));
    assert!(go_edges
        .iter()
        .any(|e| e.raw == "example.com/demo/internal/core" && e.resolved_path.as_deref() == Some("internal/core")));

    // TypeScript/JS: .js specifier resolving to .ts
    fs::create_dir_all(root.join("web/src")).unwrap();
    fs::write(root.join("web/src/util.ts"), "export const ok = 1;\n").unwrap();
    let ts_app = root.join("web/src/index.ts");
    fs::write(
        &ts_app,
        "// import { nope } from './util.js'\nimport { ok } from './util.js';\nimport external from 'lodash';\n",
    )
    .unwrap();
    let ts_edges = extract_imports_for_file(&ts_app, root, None);
    assert!(ts_edges
        .iter()
        .any(|e| e.raw == "./util.js" && e.resolved_path.as_deref() == Some("web/src/util.ts")));
    assert!(ts_edges.iter().any(|e| e.raw == "lodash" && e.resolved_path.is_none()));

    // Lean 4: handles `--` line comments and nested `/- /- ... -/ -/` block comments
    fs::create_dir_all(root.join("lean/Spec")).unwrap();
    fs::write(root.join("lean/lakefile.toml"), "name = \"Spec\"\n").unwrap();
    fs::write(root.join("lean/Spec/Core.lean"), "def x := 1\n").unwrap();
    fs::write(root.join("lean/Spec/Upper.lean"), "import Spec.Core\n").unwrap();
    let lean_core = root.join("lean/Spec/Core.lean");
    fs::write(
        &lean_core,
        concat!(
            "/- outer /- nested\n",
            "import Spec.FakeNested\n",
            "-/ still comment\n",
            "import Spec.FakeOuter\n",
            "-/\n",
            "-- import Spec.FakeLine\n",
            "public import Spec.Upper\n",
            "import Std.Data.HashMap\n"
        ),
    )
    .unwrap();
    let lean_edges = extract_imports_for_file(&lean_core, root, None);
    assert_eq!(lean_edges.len(), 2, "expected 2 lean imports, got {lean_edges:?}");
    assert_eq!(lean_edges[0].raw, "Spec.Upper");
    assert_eq!(lean_edges[0].resolved_path.as_deref(), Some("lean/Spec/Upper.lean"));
    assert_eq!(lean_edges[1].raw, "Std.Data.HashMap");
    assert_eq!(lean_edges[1].resolved_path, None);

    // Proof-of-Life: sensors enforce Lean 4 layer violations and forbidden imports
    let mut spec = ProjectSpec::default();
    spec.project.name = "lean-dag-test".into();
    spec.architecture.layers = vec![
        LayerSpec {
            name: "core".into(),
            paths: vec!["lean/Spec/Core.lean".into()],
            allowed_dependencies: vec![],
            remediation: String::new(),
        },
        LayerSpec {
            name: "upper".into(),
            paths: vec!["lean/Spec/Upper.lean".into()],
            allowed_dependencies: vec!["core".into()],
            remediation: String::new(),
        },
    ];
    spec.architecture.forbidden_imports = vec![ForbiddenImportRule {
        id: "no-std-hashmap".into(),
        from_globs: vec!["lean/Spec/Core.lean".into()],
        forbid_patterns: vec!["Std.Data.*".into()],
        message: "Keep Core dependency-free".into(),
        remediation: "Remove Std.Data import".into(),
    }];
    let (findings, _) = run_project_sensors(root, &spec, Some(&[lean_core]));
    let rules: Vec<&str> = findings.iter().map(|f| f.rule.as_str()).collect();
    assert!(rules.contains(&"ARCH_LAYER_VIOLATION"), "missing Lean layer violation: {rules:?}");
    assert!(
        rules.contains(&"ARCH_FORBIDDEN_IMPORT:no-std-hashmap"),
        "missing Lean forbidden import: {rules:?}"
    );
}

#[test]
fn verify_runner_enforces_timeout_and_captures_pass_fail() {
    let tmp = TempDir::new().unwrap();
    let mut spec = ProjectSpec::default();
    spec.verify.commands = vec![
        VerifyCommand {
            name: "pass-cmd".into(),
            cmd: "echo hello-pass".into(),
            kind: "test".into(),
            timeout_seconds: 5,
        },
        VerifyCommand {
            name: "fail-cmd".into(),
            cmd: "echo boom >&2; exit 2".into(),
            kind: "lint".into(),
            timeout_seconds: 5,
        },
        VerifyCommand {
            name: "hang-cmd".into(),
            cmd: "echo starting; sleep 10".into(),
            kind: "custom".into(),
            timeout_seconds: 1,
        },
    ];

    let started = Instant::now();
    let (findings, results) = run_verify_commands(tmp.path(), &spec);
    let elapsed = started.elapsed();

    assert!(
        elapsed.as_secs_f64() < 4.5,
        "expected hang-cmd to be killed promptly at ~1s, took {:.2}s",
        elapsed.as_secs_f64()
    );
    assert_eq!(results.len(), 3);
    assert_eq!(results[0]["status"], "PASS");
    assert_eq!(results[1]["status"], "FAIL");
    assert_eq!(results[1]["exit_code"], 2);
    assert_eq!(results[2]["status"], "TIMEOUT");
    assert_eq!(results[2]["exit_code"], 124);

    let rules: Vec<&str> = findings.iter().map(|f| f.rule.as_str()).collect();
    assert!(rules.contains(&"ADMISSION_VERIFY_FAILED:fail-cmd"));
    assert!(rules.contains(&"ADMISSION_VERIFY_TIMEOUT:hang-cmd"));
}

#[test]
fn project_init_detects_polyglot_stacks() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    fs::write(root.join("pyproject.toml"), "[tool.ruff]\n[tool.pytest]\n").unwrap();
    fs::write(root.join("go.mod"), "module example.com/x\n").unwrap();
    fs::write(root.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    fs::create_dir_all(root.join("lean")).unwrap();
    fs::write(root.join("lean/lakefile.toml"), "name = \"X\"\n").unwrap();
    fs::write(root.join("tsconfig.json"), "{}\n").unwrap();
    fs::write(
        root.join("package.json"),
        r#"{"scripts":{"lint":"eslint .","test":"vitest"}}"#,
    )
    .unwrap();

    let spec = detect_project_spec(root);
    for lang in ["python", "go", "rust", "lean", "typescript"] {
        assert!(
            spec.project.languages.iter().any(|l| l == lang),
            "missing detected language {lang} in {:?}",
            spec.project.languages
        );
    }
    assert!(
        spec.verify
            .commands
            .iter()
            .any(|c| c.name == "lean-proofs" && c.cmd == "cd lean && lake build"),
        "expected `cd lean && lake build`, got {:?}",
        spec.verify.commands
    );
}
