"""Strict Pydantic models for project-level portable harness specifications (.birkin/harness.yaml)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class _StrictModel(BaseModel):
    """Fail-closed base model rejecting unknown keys."""

    model_config = ConfigDict(extra="forbid")


class ProjectFinding(BaseModel):
    """Structured, agent-consumable finding emitted by Birkin project sensors."""

    rule: str
    category: Literal["orientation", "knowledge", "architecture", "admission", "invariant", "semantic", "entropy"]
    severity: Literal["error", "warning", "info"] = "error"
    file: str | None = None
    line: int | None = None
    message: str
    remediation: str
    details: dict[str, Any] = Field(default_factory=dict)


class ProjectIdentity(_StrictModel):
    name: str = ""
    languages: list[Literal["python", "go", "rust", "typescript", "javascript"]] = Field(default_factory=list)
    exclude_globs: list[str] = Field(
        default_factory=lambda: [
            ".git/**",
            "**/.git/**",
            "**/.venv/**",
            "**/venv/**",
            "**/node_modules/**",
            "**/target/**",
            "**/dist/**",
            "**/build/**",
            "**/__pycache__/**",
            "**/*.pyc",
            "**/.pytest_cache/**",
            "**/.ruff_cache/**",
            "**/*.egg-info/**",
            "**/.birkin/ledger/**",
        ]
    )


class OrientationSpec(_StrictModel):
    entry_docs: list[str] = Field(default_factory=lambda: ["AGENTS.md"])
    max_entry_doc_lines: int = 180
    verify_markdown_links: bool = True
    required_docs: list[str] = Field(default_factory=list)
    require_committed_harness: bool = True
    max_review_age_days: int = 90

    @field_validator("max_entry_doc_lines", "max_review_age_days")
    @classmethod
    def _positive_int(cls, v: int) -> int:
        if isinstance(v, bool) or v < 1:
            raise ValueError("must be a positive integer")
        return v


class LayerSpec(_StrictModel):
    name: str
    paths: list[str]
    allowed_dependencies: list[str] = Field(default_factory=list)
    remediation: str = ""


class ForbiddenImportRule(_StrictModel):
    id: str
    from_globs: list[str]
    forbid_patterns: list[str]
    message: str
    remediation: str


class ArchitectureSpec(_StrictModel):
    layers: list[LayerSpec] = Field(default_factory=list)
    forbidden_imports: list[ForbiddenImportRule] = Field(default_factory=list)
    max_file_lines: int = 600
    file_line_exemptions: list[str] = Field(default_factory=list)

    @field_validator("max_file_lines")
    @classmethod
    def _positive_lines(cls, v: int) -> int:
        if isinstance(v, bool) or v < 1:
            raise ValueError("max_file_lines must be a positive integer")
        return v


class VerifyCommand(_StrictModel):
    name: str
    cmd: str
    kind: Literal["lint", "typecheck", "test", "build", "custom"] = "test"
    timeout_seconds: int = 300

    @field_validator("timeout_seconds")
    @classmethod
    def _positive_timeout(cls, v: int) -> int:
        if isinstance(v, bool) or v < 1:
            raise ValueError("timeout_seconds must be a positive integer")
        return v


class VerifySpec(_StrictModel):
    commands: list[VerifyCommand] = Field(default_factory=list)
    check_ci_parity: bool = True


class RegexRule(_StrictModel):
    id: str
    globs: list[str] = Field(default_factory=lambda: ["**/*"])
    exclude_globs: list[str] = Field(default_factory=list)
    pattern: str
    severity: Literal["error", "warning"] = "error"
    message: str
    remediation: str
    examples_pass: list[str] = Field(default_factory=list)
    examples_fail: list[str] = Field(default_factory=list)


class InvariantsSpec(_StrictModel):
    forbid_secrets: bool = True
    secret_exempt_globs: list[str] = Field(default_factory=lambda: ["tests/**", "**/*_test.*", "**/*.test.*"])
    english_prose_only: bool = False
    prose_exempt_globs: list[str] = Field(default_factory=list)
    forbid_debug_leftovers: bool = False
    custom_regex_rules: list[RegexRule] = Field(default_factory=list)


class SemanticRule(_StrictModel):
    id: str
    description: str
    predicate: str
    globs: list[str] = Field(default_factory=lambda: ["**/*"])
    threshold: float = 0.75
    action: Literal["advisory", "fix_now"] = "advisory"
    remediation: str
    examples_pass: list[str] = Field(default_factory=list)
    examples_fail: list[str] = Field(default_factory=list)

    @field_validator("threshold")
    @classmethod
    def _valid_threshold(cls, v: float) -> float:
        if isinstance(v, bool) or not (0.0 < float(v) <= 1.0):
            raise ValueError("threshold must be in (0, 1]")
        return float(v)


class SemanticSpec(_StrictModel):
    enabled: bool = False
    base_url: str = "http://127.0.0.1:3425/v1"
    api_key_env: str = "BIRKIN_SEMANTIC_API_KEY"
    model: str = "auto/gemini-3.8-flash"
    timeout_seconds: float = 15.0
    max_diff_chars: int = 24000
    rules_dir: str = ".birkin/rules"
    rules: list[SemanticRule] = Field(default_factory=list)


class TelemetrySpec(_StrictModel):
    enabled: bool = True
    ledger_path: str | None = None
    thrash_threshold: int = 3
    thrash_window_minutes: int = 30
    stale_rule_min_runs: int = 20


class ProjectHarnessSpec(_StrictModel):
    """Portable per-repository harness specification (.birkin/harness.yaml)."""

    version: int = 1
    project: ProjectIdentity = Field(default_factory=ProjectIdentity)
    orientation: OrientationSpec = Field(default_factory=OrientationSpec)
    architecture: ArchitectureSpec = Field(default_factory=ArchitectureSpec)
    verify: VerifySpec = Field(default_factory=VerifySpec)
    invariants: InvariantsSpec = Field(default_factory=InvariantsSpec)
    semantic: SemanticSpec = Field(default_factory=SemanticSpec)
    telemetry: TelemetrySpec = Field(default_factory=TelemetrySpec)


HARNESS_REL_PATHS = (".birkin/harness.yaml", ".birkin/harness.yml", "birkin.yaml")


def find_harness_file(repo_root: Path) -> Path | None:
    """Return the first recognized harness spec path inside repo_root, if present."""
    for rel in HARNESS_REL_PATHS:
        candidate = repo_root / rel
        if candidate.is_file():
            return candidate
    return None


def find_repo_root(start: Path) -> Path:
    """Walk upward from start to find a directory containing .birkin/harness.yaml or .git."""
    cur = start.resolve()
    if cur.is_file():
        cur = cur.parent
    git_fallback: Path | None = None
    for parent in (cur, *cur.parents):
        if find_harness_file(parent) is not None:
            return parent
        if git_fallback is None and (parent / ".git").exists():
            git_fallback = parent
    return git_fallback or cur


def load_project_harness(repo_root: Path, explicit_path: Path | None = None) -> tuple[ProjectHarnessSpec, Path | None]:
    """Load strict ProjectHarnessSpec from explicit_path or repo_root, failing closed on invalid YAML/keys."""
    spec_path = explicit_path or find_harness_file(repo_root)
    if explicit_path is not None and not explicit_path.is_file():
        raise FileNotFoundError(f"Explicit harness spec not found: {explicit_path}")
    if spec_path is None:
        return ProjectHarnessSpec(project=ProjectIdentity(name=repo_root.name)), None

    raw = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError(f"Harness spec must be a YAML mapping: {spec_path}")
    spec = ProjectHarnessSpec.model_validate(raw)

    # Merge any rule files under semantic.rules_dir
    rules_dir = repo_root / spec.semantic.rules_dir
    if rules_dir.is_dir():
        extra_rules: list[SemanticRule] = []
        seen_ids = {r.id for r in spec.semantic.rules}
        for rule_file in sorted(list(rules_dir.glob("*.yaml")) + list(rules_dir.glob("*.yml"))):
            rule_data = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
            if rule_data is None:
                continue
            items = rule_data if isinstance(rule_data, list) else [rule_data]
            for item in items:
                rule = SemanticRule.model_validate(item)
                if rule.id in seen_ids:
                    raise ValueError(f"Duplicate semantic rule id '{rule.id}' in {rule_file}")
                seen_ids.add(rule.id)
                extra_rules.append(rule)
        if extra_rules:
            spec.semantic.rules = [*spec.semantic.rules, *extra_rules]

    if not spec.project.name:
        spec.project.name = repo_root.name
    return spec, spec_path
