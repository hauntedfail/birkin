"""Tests for semantic review, hash-chained receipts, AHE telemetry/steering, GC, and hooks."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import httpx

from birkin.constants import EXIT_LIVE_CONTRACT, EXIT_LIVE_TRANSIENT, EXIT_PASS, EXIT_STATIC
from birkin.gc import run_gc_scan
from birkin.hooks import (
    install_claude_hook,
    install_git_pre_commit_hook,
    install_hermes_plugin,
    run_post_edit_hook,
)
from birkin.ledger import (
    append_receipt,
    read_receipts,
    resolve_ledger_path,
    verify_chain,
    verify_receipts_for_current_state,
)
from birkin.project_models import (
    InvariantsSpec,
    ProjectSpec,
    RegexRule,
    SemanticRule,
    SemanticSpec,
    TelemetrySpec,
)
from birkin.semantic import evaluate_semantic_rules, run_semantic_review
from birkin.steer import analyze_telemetry


def _init_git_repo(repo: Path) -> None:
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test User"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "commit.gpgsign", "false"], check=True)


def test_semantic_review_verdicts_and_fail_closed_provider_errors(tmp_path: Path) -> None:
    target = tmp_path / "src" / "app.py"
    target.parent.mkdir(parents=True)
    target.write_text("class Wrapper:\n    def run(self): return real()\n", encoding="utf-8")

    rule_block = SemanticRule(
        id="no-wrapper",
        description="Avoid forwarding-only wrappers",
        predicate="Is this a forwarding-only wrapper?",
        globs=["src/**/*.py"],
        threshold=0.75,
        action="fix_now",
        remediation="Call real() directly.",
        examples_pass=["def real(): return 1"],
        examples_fail=["class W: def run(self): return real()"],
    )
    spec = ProjectSpec(
        semantic=SemanticSpec(enabled=True, model="test-model", rules=[rule_block])
    )

    # 1. Violated above threshold -> EXIT_STATIC (fix_now)
    def ok_violation(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "violated": True,
                                    "probability": 0.91,
                                    "confidence": 0.85,
                                    "line": 1,
                                    "evidence": "Wrapper only delegates to real()",
                                    "suggestion": "Delete Wrapper",
                                }
                            )
                        }
                    }
                ]
            },
        )

    code, findings, meta = run_semantic_review(
        tmp_path, spec, files=[target], transport=httpx.MockTransport(ok_violation)
    )
    assert code == EXIT_STATIC
    assert meta["fix_now"] == 1
    assert findings[0].rule == "SEMANTIC:no-wrapper"
    assert findings[0].severity == "error"

    # 2. HTTP 401 -> EXIT_LIVE_CONTRACT (never approval!)
    code_401, f_401, _ = run_semantic_review(
        tmp_path,
        spec,
        files=[target],
        transport=httpx.MockTransport(lambda req: httpx.Response(401, text="unauthorized")),
    )
    assert code_401 == EXIT_LIVE_CONTRACT
    assert any("SEMANTIC_PROVIDER_ERROR" in f.rule for f in f_401)

    # 3. HTTP 503 -> EXIT_LIVE_TRANSIENT (never approval!)
    code_503, _, _ = run_semantic_review(
        tmp_path,
        spec,
        files=[target],
        transport=httpx.MockTransport(lambda req: httpx.Response(503, text="overloaded")),
    )
    assert code_503 == EXIT_LIVE_TRANSIENT

    # 4. Empirical rule calibration against examples_pass / examples_fail
    def smart_judge(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content.decode("utf-8"))
        prompt = body["messages"][1]["content"]
        is_bad = "class W:" in prompt
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "violated": is_bad,
                                    "probability": 0.95 if is_bad else 0.05,
                                    "confidence": 0.9,
                                    "line": 1,
                                    "evidence": "matched",
                                    "suggestion": "",
                                }
                            )
                        }
                    }
                ]
            },
        )

    cal = evaluate_semantic_rules(spec, transport=httpx.MockTransport(smart_judge))
    assert cal["status"] == "PASS"
    assert cal["rules"][0]["mode"] == "empirical"


def test_receipt_ledger_hash_chain_tamper_detection_and_revision_binding(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    (tmp_path / "main.py").write_text("print('ok')\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "main.py"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "init"], check=True)

    ledger_file = tmp_path / ".ledger.jsonl"
    spec = ProjectSpec(telemetry=TelemetrySpec(ledger_path=str(ledger_file)))

    append_receipt(
        tmp_path, spec, command="check", surface="cli", outcome="PASS", exit_code=0, duration_ms=12
    )
    append_receipt(
        tmp_path, spec, command="verify", surface="cli", outcome="PASS", exit_code=0, duration_ms=45
    )

    ok_res = verify_receipts_for_current_state(tmp_path, spec, required_commands=["check", "verify"])
    assert ok_res["status"] == "PASS"
    assert ok_res["chain_ok"] is True

    # Mutating working tree invalidates tree_digest binding
    (tmp_path / "main.py").write_text("print('changed')\n", encoding="utf-8")
    dirty_res = verify_receipts_for_current_state(tmp_path, spec, required_commands=["check"])
    assert dirty_res["status"] == "FAIL"
    assert "check" in dirty_res["missing"]

    # Tampering with a ledger line breaks hash chain
    raw_lines = ledger_file.read_text(encoding="utf-8").splitlines()
    mutated = json.loads(raw_lines[0])
    mutated["duration_ms"] = 99
    tampered = json.dumps(mutated, sort_keys=True)
    assert tampered != raw_lines[0]
    ledger_file.write_text("\n".join([tampered, *raw_lines[1:]]) + "\n", encoding="utf-8")
    chain_ok, errors = verify_chain(read_receipts(ledger_file))
    assert chain_ok is False
    assert errors


def test_ahe_telemetry_detects_thrashing_self_correction_stale_rules_and_evolution(tmp_path: Path) -> None:
    ledger_file = tmp_path / "ledger.jsonl"
    spec_v1 = ProjectSpec(
        invariants=InvariantsSpec(
            custom_regex_rules=[
                RegexRule(
                    id="never-fires",
                    pattern=r"UNLIKELY_XYZ",
                    message="m",
                    remediation="r",
                    examples_pass=["a"],
                    examples_fail=["UNLIKELY_XYZ"],
                )
            ]
        ),
        telemetry=TelemetrySpec(
            ledger_path=str(ledger_file),
            thrash_threshold=3,
            stale_rule_min_runs=4,
        ),
    )

    # 3 consecutive failures on same file/rule -> thrash alert, then 1 pass -> self-correction 100%
    for _ in range(3):
        append_receipt(
            tmp_path,
            spec_v1,
            command="hook:post-edit",
            surface="hermes-plugin",
            outcome="FAIL",
            exit_code=1,
            duration_ms=10,
            findings=[{"rule": "ARCH_LAYER_VIOLATION", "severity": "error", "file": "src/a.py"}],
            files=["src/a.py"],
        )
    append_receipt(
        tmp_path,
        spec_v1,
        command="hook:post-edit",
        surface="hermes-plugin",
        outcome="PASS",
        exit_code=0,
        duration_ms=8,
        findings=[],
        files=["src/a.py"],
    )

    report = analyze_telemetry(tmp_path, spec_v1)
    assert report["total_runs"] == 4
    assert len(report["thrash_alerts"]) == 1
    assert report["thrash_alerts"][0]["file"] == "src/a.py"
    assert report["self_correction"]["rate"] == 1.0
    assert "CUSTOM_REGEX:never-fires" in report["stale_rule_candidates"]
    assert len(report["spec_evolution"]) == 1
    assert report["recommendations"]

    gc_report = run_gc_scan(tmp_path, spec_v1)
    assert len(gc_report["buckets"]["dead_rules"]) == 1


def test_hooks_installers_and_live_hermes_plugin_transform_tool_result(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    ledger_file = tmp_path / "outside-ledger.jsonl"

    config_yaml = tmp_path / ".birkin" / "config.yaml"
    config_yaml.parent.mkdir(parents=True)
    config_yaml.write_text(
        f"""version: 1
project:
  name: demo
  languages: [python]
architecture:
  layers:
    - name: core
      paths: ["src/core.py"]
      allowed_dependencies: []
    - name: ui
      paths: ["src/ui.py"]
      allowed_dependencies: ["core"]
telemetry:
  enabled: true
  ledger_path: "{ledger_file}"
""",
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "ui.py").write_text("UI = 1\n", encoding="utf-8")
    core_py = tmp_path / "src" / "core.py"
    core_py.write_text("import ui\n", encoding="utf-8")

    # 1. Direct post-edit hook detects violation & records receipt
    code, findings, feedback = run_post_edit_hook([core_py], surface="test-hook")
    assert code == EXIT_STATIC
    assert findings[0].rule == "ARCH_LAYER_VIOLATION"
    assert "Fix:" in feedback
    assert resolve_ledger_path(tmp_path, ProjectSpec(telemetry=TelemetrySpec(ledger_path=str(ledger_file)))).is_file()

    # 2. Git hook installer (idempotent)
    r1 = install_git_pre_commit_hook(tmp_path)
    r2 = install_git_pre_commit_hook(tmp_path)
    assert r1["status"] == "created"
    assert r2["status"] == "already_installed"
    assert (tmp_path / ".git" / "hooks" / "pre-commit").is_file()

    # 3. Claude hook installer (idempotent + preserves existing hooks)
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": []}]}}), encoding="utf-8")
    c1 = install_claude_hook(settings)
    c2 = install_claude_hook(settings)
    assert c1["status"] == "installed"
    assert c2["status"] == "already_installed"
    saved = json.loads(settings.read_text(encoding="utf-8"))
    assert len(saved["hooks"]["PreToolUse"]) == 1
    assert len(saved["hooks"]["PostToolUse"]) == 1

    # 4. Hermes native plugin installer + live transform_tool_result exercise
    plugins_dir = tmp_path / "hermes_plugins"
    h_res = install_hermes_plugin(plugins_dir)
    assert h_res["status"] == "installed"
    plugin_init = plugins_dir / "birkin" / "__init__.py"
    assert (plugins_dir / "birkin" / "plugin.yaml").is_file()
    assert not (plugins_dir / "birkin-harness").exists()

    spec_mod = importlib.util.spec_from_file_location("birkin_test_plugin", plugin_init)
    assert spec_mod and spec_mod.loader
    mod = importlib.util.module_from_spec(spec_mod)
    spec_mod.loader.exec_module(mod)

    registered: list[str] = []

    class _FakeCtx:
        def register_hook(self, name: str, fn: object) -> None:
            registered.append(name)

    mod.register(_FakeCtx())
    assert registered == ["transform_tool_result"]

    # Trigger plugin on violating file -> injects birkin_feedback into JSON result
    transformed = mod.transform_tool_result(
        tool_name="write_file",
        args={"path": str(core_py)},
        result=json.dumps({"verified": True}),
    )
    assert transformed is not None
    parsed_res = json.loads(transformed)
    assert "ARCH_LAYER_VIOLATION" in parsed_res["birkin_feedback"]

    # Clean edit -> returns None (zero noise)
    core_py.write_text("CORE = 1\n", encoding="utf-8")
    clean_res = mod.transform_tool_result(
        tool_name="write_file",
        args={"path": str(core_py)},
        result=json.dumps({"verified": True}),
    )
    assert clean_res is None

    # Unconfigured repo -> silent pass
    other = tmp_path / "other_dir" / "foo.py"
    other.parent.mkdir()
    other.write_text("x = 1\n", encoding="utf-8")
    code_other, f_other, fb_other = run_post_edit_hook([other])
    assert code_other == EXIT_PASS and not f_other and not fb_other
