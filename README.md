# Birkin

Portable **Harness Engineering Engine** for coding agents across multi-language repositories (Python, Go, Rust, TypeScript/JavaScript), plus a fail-closed **Hermes Agent** runtime verifier.

## Why Birkin Exists (Research Foundations)

A coding agent is `Model + Harness`. A standalone pass/fail wrapper does not strengthen a harness; a real outer harness is a **closed control loop**:

1. **Feedforward Guides** (OpenAI *Harness Engineering*, Feb 2026; Böckeler / Martin Fowler, Apr 2026) — Steer the agent *before* it edits via a strict, versioned [.birkin/config.yaml](.birkin/config.yaml), concise map-style `AGENTS.md` line budgets, verified doc links, and local-vs-CI command parity.
2. **Computational Sensors** (deterministic, sub-second) — Multi-language static import parsing (Python AST, Go, Rust, TypeScript/JS) enforcing declared architecture layer DAGs and forbidden imports, file size budgets, secret/debug/prose invariants, and custom regex rules — emitting LLM-optimized remediation instructions at edit time.
3. **Inferential Sensors + Self-Calibration** (`jev-lint` / `jev-pref` pattern, vendor-agnostic) — Narrow, single-predicate semantic review rules over diffs or files via any OpenAI-compatible endpoint, with mandatory `examples_pass` / `examples_fail` calibration (`birkin eval-rules`) so broken sensors cannot silently pass.
4. **Append-Only Revision-Pinned Receipts** (*Towards Portable Specification of the Agent Harness*, arXiv:2610.40917) — Every check, hook, and verify run appends a hash-chained receipt outside the repo working tree (`~/.birkin/ledger/`) bound to exact `git HEAD`, working-tree digest, and `spec_sha256`.
5. **Observability-Driven Evolution & Garbage Collection** (*Agentic Harness Engineering*, arXiv:2604.25850; Anthropic *Harness Design*, Mar 2026) — Distills receipts into recurring violation hotspots, agent thrash alerts, self-correction rates, before/after `spec_sha256` impact, and dead/stale rules eligible for pruning (`birkin steer`, `birkin gc`).

## Quick Start (Any Repository)

```bash
# 1. Auto-detect stack (Python/Go/Rust/TS) and scaffold .birkin/config.yaml
birkin init /path/to/repo --write

# 2. Emit compact feedforward brief for an agent entering the repo
birkin guide /path/to/repo

# 3. Run 6-axis harness readiness audit (orientation, knowledge, architecture, admission, sensors, observability)
birkin audit /path/to/repo

# 4. Run computational sensors + canonical verify commands and record a hash-chained receipt
birkin check /path/to/repo --run-verify

# 5. Prove the exact current HEAD/tree has passing receipts
birkin receipt verify /path/to/repo --require check,verify

# 6. Calibrate custom regex & semantic rules against their own pass/fail fixtures
birkin eval-rules /path/to/repo

# 7. Run optional narrow semantic review on staged diff or explicit files
birkin review /path/to/repo --staged

# 8. Inspect AHE telemetry / steering signals and entropy garbage-collection backlog
birkin steer /path/to/repo
birkin gc /path/to/repo
```

## Real-Time Operational Wiring (Hooks & Plugins)

Birkin plugs directly into agent loops so violations are fixed while the file is still open:

```bash
# Install git pre-commit hook in a repo
birkin install-hooks /path/to/repo --target git

# Install Claude Code PostToolUse hook (repo-local .claude/settings.local.json, or --global)
birkin install-hooks /path/to/repo --target claude

# Install native Hermes Agent plugin (~/.hermes/plugins/birkin/, transform_tool_result)
birkin install-hooks --target hermes
```

On non-Birkin repositories (no `.birkin/config.yaml`), hooks exit cleanly in milliseconds with zero interference.

## Hermes Runtime Verifier (Backward Compatible)

All Hermes Agent configuration, live `/v1/models` contract, and gateway runtime drift checks remain available both at top level and under `birkin hermes`:

```bash
birkin static
birkin live --probe
birkin drift
birkin all --live --json
birkin all --skip-drift --no-write-state
```

See [birkin-policy.example.yaml](birkin-policy.example.yaml) for the strict Hermes runtime policy schema.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | `PASS` |
| `1` | `STATIC / POLICY / HARNESS VIOLATION` |
| `2` | `LIVE CONTRACT VIOLATION` (4xx, missing model, context mismatch, invalid semantic response) |
| `3` | `LIVE TRANSIENT UNAVAILABLE` (429/5xx/network/protocol/timeout) |
| `4` | `RUNTIME DRIFT` (gateway older than config/`.env`, missing start time, or SHA mismatch) |
| `5` | `TOOL / IO / SCHEMA ERROR` (missing explicit spec/policy, invalid YAML, unknown keys) |

## Architecture

See [AGENTS.md](AGENTS.md) for the enforced 6-layer DAG across `src/birkin/`.

## Development

```bash
pip install -e ".[dev]"
ruff check src tests
pytest -v
birkin eval-rules
birkin check --no-receipt
```
