"""Unit and integration tests for Birkin's project-universal harness engineering engine."""

from __future__ import annotations

import subprocess
from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

from birkin.guides import audit_guides, build_readiness_scorecard
from birkin.imports_parser import extract_imports_for_file
from birkin.project_init import detect_project_spec, render_agent_guide, render_harness_yaml
from birkin.project_models import (
    ArchitectureSpec,
    ForbiddenImportRule,
    InvariantsSpec,
    LayerSpec,
    OrientationSpec,
    ProjectHarnessSpec,
    RegexRule,
    VerifyCommand,
    VerifySpec,
    load_project_harness,
)
from birkin.sensors import evaluate_regex_rules, run_project_sensors


def test_project_harness_spec_rejects_unknown_keys_fail_closed(tmp_path: Path) -> None:
    harness = tmp_path / ".birkin" / "harness.yaml"
    harness.parent.mkdir(parents=True)
    harness.write_text("version: 1\nunknown_typo_section:\n  foo: bar\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_project_harness(tmp_path)


def test_imports_parser_supports_python_go_rust_typescript(tmp_path: Path) -> None:
    # Python
    (tmp_path / "src" / "app").mkdir(parents=True)
    (tmp_path / "src" / "app" / "core.py").write_text("X = 1\n", encoding="utf-8")
    py_svc = tmp_path / "src" / "app" / "service.py"
    py_svc.write_text("from app import core\nfrom .core import X\n", encoding="utf-8")
    py_edges = extract_imports_for_file(py_svc, tmp_path)
    assert any(e.resolved_path == "src/app/core.py" for e in py_edges)

    # Go
    (tmp_path / "go.mod").write_text("module example.com/demo\n\ngo 1.23\n", encoding="utf-8")
    (tmp_path / "internal" / "domain").mkdir(parents=True)
    (tmp_path / "internal" / "cli").mkdir(parents=True)
    go_file = tmp_path / "internal" / "domain" / "user.go"
    go_file.write_text(
        'package domain\nimport (\n\t"fmt"\n\t"example.com/demo/internal/cli"\n)\n',
        encoding="utf-8",
    )
    go_edges = extract_imports_for_file(go_file, tmp_path)
    assert any(e.resolved_path == "internal/cli" for e in go_edges)

    # Rust
    (tmp_path / "src" / "ui").mkdir(parents=True)
    (tmp_path / "src" / "ui" / "view.rs").write_text("pub fn render() {}\n", encoding="utf-8")
    rs_file = tmp_path / "src" / "core.rs"
    rs_file.write_text("// use crate::ignored;\nuse crate::ui::view::render;\n", encoding="utf-8")
    rs_edges = extract_imports_for_file(rs_file, tmp_path)
    assert any(e.resolved_path == "src/ui/view.rs" for e in rs_edges)
    assert not any("ignored" in e.raw for e in rs_edges)

    # TypeScript
    (tmp_path / "web" / "ui").mkdir(parents=True)
    (tmp_path / "web" / "domain").mkdir(parents=True)
    (tmp_path / "web" / "ui" / "Button.tsx").write_text("export const Button = () => null;\n", encoding="utf-8")
    ts_file = tmp_path / "web" / "domain" / "logic.ts"
    ts_file.write_text("import { Button } from '../ui/Button';\n", encoding="utf-8")
    ts_edges = extract_imports_for_file(ts_file, tmp_path)
    assert any(e.resolved_path == "web/ui/Button.tsx" for e in ts_edges)


def test_architecture_layer_dag_catches_upward_violations_across_languages(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/app\n", encoding="utf-8")
    (tmp_path / "internal" / "domain").mkdir(parents=True)
    (tmp_path / "internal" / "ui").mkdir(parents=True)
    (tmp_path / "internal" / "ui" / "page.go").write_text("package ui\n", encoding="utf-8")
    # Bad: domain imports ui
    (tmp_path / "internal" / "domain" / "bad.go").write_text(
        'package domain\nimport "example.com/app/internal/ui"\n',
        encoding="utf-8",
    )
    # Good: ui imports domain
    (tmp_path / "internal" / "ui" / "good.go").write_text(
        'package ui\nimport "example.com/app/internal/domain"\n',
        encoding="utf-8",
    )

    spec = ProjectHarnessSpec(
        architecture=ArchitectureSpec(
            layers=[
                LayerSpec(name="domain", paths=["internal/domain", "internal/domain/**"], allowed_dependencies=[]),
                LayerSpec(name="ui", paths=["internal/ui", "internal/ui/**"], allowed_dependencies=["domain"]),
            ],
            forbidden_imports=[
                ForbiddenImportRule(
                    id="no-unsafe",
                    from_globs=["internal/**"],
                    forbid_patterns=["unsafe"],
                    message="Unsafe package forbidden",
                    remediation="Remove import of unsafe.",
                )
            ],
        )
    )
    findings, _ = run_project_sensors(tmp_path, spec)
    layer_errors = [f for f in findings if f.rule == "ARCH_LAYER_VIOLATION"]
    assert len(layer_errors) == 1
    assert layer_errors[0].file == "internal/domain/bad.go"
    assert layer_errors[0].line == 2
    assert "domain" in layer_errors[0].remediation


def test_sensors_detect_secrets_debug_prose_file_size_and_custom_regex(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    bad_py = tmp_path / "src" / "bad.py"
    fake_tok = "ghp_" + ("A" * 36)
    bad_py.write_text(
        f"# 日本語コメント\nTOKEN = '{fake_tok}'\nbreakpoint()\ntry:\n    pass\nexcept:\n    pass\n",
        encoding="utf-8",
    )
    # File exceeding small line budget
    big_py = tmp_path / "src" / "big.py"
    big_py.write_text("x = 1\n" * 25, encoding="utf-8")

    spec = ProjectHarnessSpec(
        architecture=ArchitectureSpec(max_file_lines=20),
        invariants=InvariantsSpec(
            forbid_secrets=True,
            english_prose_only=True,
            forbid_debug_leftovers=True,
            custom_regex_rules=[
                RegexRule(
                    id="no-bare-except",
                    globs=["src/**/*.py"],
                    pattern=r"^\s*except\s*:\s*$",
                    message="No bare except",
                    remediation="Use explicit exception class.",
                    examples_pass=["except ValueError:"],
                    examples_fail=["except:"],
                )
            ],
        ),
    )

    findings, _ = run_project_sensors(tmp_path, spec)
    rules = {f.rule for f in findings}
    assert "INVARIANT_SECRET_LEAK:GITHUB_PAT" in rules
    assert "INVARIANT_DEBUG_LEFTOVER:PYTHON_BREAKPOINT" in rules
    assert "INVARIANT_NON_ENGLISH_PROSE" in rules
    assert "CUSTOM_REGEX:no-bare-except" in rules
    assert "ARCH_FILE_TOO_LARGE" in rules


def test_evaluate_regex_rules_detects_false_positive_and_false_negative() -> None:
    good_spec = ProjectHarnessSpec(
        invariants=InvariantsSpec(
            custom_regex_rules=[
                RegexRule(
                    id="good-rule",
                    pattern=r"\bTODO\b",
                    message="No TODO",
                    remediation="Resolve TODO.",
                    examples_pass=["# done"],
                    examples_fail=["# TODO fix"],
                )
            ]
        )
    )
    assert evaluate_regex_rules(good_spec)["status"] == "PASS"

    broken_spec = ProjectHarnessSpec(
        invariants=InvariantsSpec(
            custom_regex_rules=[
                RegexRule(
                    id="broken-rule",
                    pattern=r"NEVER_MATCHES",
                    message="Broken",
                    remediation="Fix pattern.",
                    examples_pass=["clean"],
                    examples_fail=["should fail"],
                )
            ]
        )
    )
    res = evaluate_regex_rules(broken_spec)
    assert res["status"] == "FAIL"
    assert res["rules"][0]["false_negatives"] == ["should fail"]


def test_guides_audit_checks_links_staleness_bloat_tracking_and_ci_parity(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    # Bloated AGENTS.md with broken link and stale review date
    agents = tmp_path / "AGENTS.md"
    agents.write_text(
        "Last reviewed: 2025-01-01\n"
        "See [missing](docs/does-not-exist.md)\n"
        + ("line\n" * 30),
        encoding="utf-8",
    )
    # CI runs pytest + ruff, but local verify only declares pytest
    wf = tmp_path / ".github" / "workflows" / "ci.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(
        "name: CI\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: ruff check src\n"
        "      - run: pytest -v\n",
        encoding="utf-8",
    )

    spec = ProjectHarnessSpec(
        orientation=OrientationSpec(max_entry_doc_lines=10, max_review_age_days=90),
        verify=VerifySpec(commands=[VerifyCommand(name="test", cmd="pytest -v", kind="test")]),
    )
    findings = audit_guides(tmp_path, spec, today=date(2026, 11, 26))
    rules = {f.rule for f in findings}
    assert "ORIENTATION_ENTRY_DOC_BLOATED" in rules
    assert "ORIENTATION_UNTRACKED_HARNESS_FILE" in rules
    assert "KNOWLEDGE_BROKEN_DOC_LINK" in rules
    assert "KNOWLEDGE_STALE_DOC_REVIEW" in rules
    assert "ADMISSION_CI_LOCAL_DRIFT" in rules

    scorecard = build_readiness_scorecard(tmp_path, spec, findings, [], [])
    assert scorecard["knowledge"]["status"] == "FAIL"
    assert scorecard["admission"]["status"] == "WARN"


def test_detect_project_spec_and_guide_rendering(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/x\n", encoding="utf-8")
    (tmp_path / "Cargo.toml").write_text("[package]\nname='x'\n", encoding="utf-8")
    (tmp_path / "AGENTS.md").write_text("# Agents\n", encoding="utf-8")

    spec = detect_project_spec(tmp_path)
    assert "go" in spec.project.languages
    assert "rust" in spec.project.languages
    assert any("go test" in c.cmd for c in spec.verify.commands)
    assert any("cargo test" in c.cmd for c in spec.verify.commands)

    yaml_text = render_harness_yaml(spec)
    assert "version: 1" in yaml_text
    guide_text = render_agent_guide(tmp_path, spec)
    assert "Birkin Feedforward Guide" in guide_text
    assert "go test ./..." in guide_text
