"""Auto-detection, scaffolding (.birkin/harness.yaml), and compact feedforward guide rendering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from birkin.project_models import (
    ArchitectureSpec,
    InvariantsSpec,
    OrientationSpec,
    ProjectHarnessSpec,
    ProjectIdentity,
    VerifyCommand,
    VerifySpec,
)


def detect_project_spec(repo_root: Path) -> ProjectHarnessSpec:
    """Inspect a repository and infer a portable starter ProjectHarnessSpec."""
    languages: list[str] = []
    commands: list[VerifyCommand] = []

    pyproject = repo_root / "pyproject.toml"
    if pyproject.is_file():
        languages.append("python")
        text = pyproject.read_text(encoding="utf-8", errors="replace")
        if "ruff" in text:
            commands.append(VerifyCommand(name="lint", cmd="ruff check src tests", kind="lint"))
        if "pytest" in text or (repo_root / "tests").is_dir():
            commands.append(VerifyCommand(name="test", cmd="pytest -v", kind="test"))

    if (repo_root / "go.mod").is_file():
        languages.append("go")
        commands.append(VerifyCommand(name="go-vet", cmd="go vet ./...", kind="lint"))
        commands.append(VerifyCommand(name="go-test", cmd="go test ./...", kind="test"))

    if (repo_root / "Cargo.toml").is_file():
        languages.append("rust")
        commands.append(
            VerifyCommand(
                name="cargo-clippy",
                cmd="cargo clippy --all-targets -- -D warnings",
                kind="lint",
            )
        )
        commands.append(VerifyCommand(name="cargo-test", cmd="cargo test", kind="test"))

    pkg_json = repo_root / "package.json"
    if pkg_json.is_file():
        is_ts = (repo_root / "tsconfig.json").is_file()
        languages.append("typescript" if is_ts else "javascript")
        runner = "pnpm" if (repo_root / "pnpm-lock.yaml").is_file() else "npm"
        try:
            pkg = json.loads(pkg_json.read_text(encoding="utf-8"))
            scripts = pkg.get("scripts") if isinstance(pkg, dict) else {}
        except Exception:
            scripts = {}
        if isinstance(scripts, dict):
            if "verify" in scripts:
                commands.append(VerifyCommand(name="verify", cmd=f"{runner} run verify", kind="test"))
            else:
                for key, kind in (
                    ("lint", "lint"),
                    ("typecheck", "typecheck"),
                    ("check", "lint"),
                    ("test", "test"),
                ):
                    if key in scripts:
                        commands.append(VerifyCommand(name=key, cmd=f"{runner} run {key}", kind=kind))

    entry_docs: list[str] = []
    for candidate in ("AGENTS.md", "CLAUDE.md"):
        if (repo_root / candidate).is_file():
            entry_docs.append(candidate)
    if not entry_docs:
        entry_docs = ["AGENTS.md"]

    return ProjectHarnessSpec(
        version=1,
        project=ProjectIdentity(name=repo_root.name, languages=languages),  # type: ignore[arg-type]
        orientation=OrientationSpec(entry_docs=entry_docs),
        architecture=ArchitectureSpec(),
        verify=VerifySpec(commands=commands, check_ci_parity=True),
        invariants=InvariantsSpec(forbid_secrets=True),
    )


def render_harness_yaml(spec: ProjectHarnessSpec) -> str:
    """Serialize a ProjectHarnessSpec to clean, commented YAML."""
    header = (
        "# Portable Agent Harness Specification (.birkin/harness.yaml)\n"
        "# Enforced mechanically by Birkin across CLI, git hooks, CI, Claude Code, and Hermes.\n"
    )
    data = spec.model_dump(mode="json")
    body = yaml.safe_dump(data, sort_keys=False, allow_unicode=False)
    return header + body


def render_agent_guide(
    repo_root: Path,
    spec: ProjectHarnessSpec,
    *,
    steering: dict[str, Any] | None = None,
) -> str:
    """Emit a compact feedforward brief (<60 lines) for coding agents entering a repo."""
    lines: list[str] = [
        f"# Birkin Feedforward Guide — {spec.project.name}",
        f"Root: `{repo_root.resolve()}`",
        f"Languages: {', '.join(spec.project.languages) if spec.project.languages else 'auto'}",
        "",
    ]
    if spec.orientation.entry_docs:
        present = [d for d in spec.orientation.entry_docs if (repo_root / d).is_file()]
        lines.append(f"## Entry Docs: {', '.join(present) if present else 'none (missing AGENTS.md)'}")

    if spec.verify.commands:
        lines.append("\n## Canonical Verify Commands (Admission Gate)")
        for cmd in spec.verify.commands:
            lines.append(f"- `{cmd.name}` ({cmd.kind}): `{cmd.cmd}`")

    if spec.architecture.layers:
        lines.append("\n## Architecture Layer DAG (Mechanically Enforced)")
        for layer in spec.architecture.layers:
            deps = ", ".join(layer.allowed_dependencies) if layer.allowed_dependencies else "(none)"
            lines.append(f"- **{layer.name}** (`{', '.join(layer.paths)}`) -> allowed: {deps}")

    if spec.architecture.forbidden_imports:
        lines.append("\n## Forbidden Imports")
        for rule in spec.architecture.forbidden_imports:
            lines.append(f"- `{rule.id}`: {rule.message}")

    invariants: list[str] = []
    if spec.invariants.forbid_secrets:
        invariants.append("no hardcoded secrets")
    if spec.invariants.english_prose_only:
        invariants.append("English prose only in docs/comments")
    if spec.invariants.forbid_debug_leftovers:
        invariants.append("no debug breakpoints")
    invariants.append(f"max file size <= {spec.architecture.max_file_lines} lines")
    if spec.invariants.custom_regex_rules:
        invariants.append(f"{len(spec.invariants.custom_regex_rules)} custom regex guards")
    if spec.semantic.rules:
        state = "enabled" if spec.semantic.enabled else "available via `birkin review`"
        invariants.append(f"{len(spec.semantic.rules)} semantic predicates ({state})")
    lines.append("\n## Active Invariants")
    lines.append("- " + "; ".join(invariants))

    if steering and steering.get("hotspots"):
        lines.append("\n## Recent Violation Hotspots (From Telemetry)")
        for item in steering["hotspots"][:5]:
            lines.append(f"- `{item['rule']}` ({item['hits']} hits) — watch out before editing")

    lines.append("\n## Fast Verification Loop")
    lines.append("- After edits: `birkin check --files <changed-files>`")
    lines.append("- Before commit/PR: `birkin check --run-verify` && `birkin receipt verify`")
    return "\n".join(lines) + "\n"
