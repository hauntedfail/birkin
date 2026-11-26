# Birkin

Native **Rust** verification engine backed by a machine-checked **Lean 4** formal kernel (`BirkinSpec`), serving coding agents across multi-language repositories (Python, Go, Rust, Lean 4, TypeScript/JavaScript) plus fail-closed **Hermes Agent** runtime verification.

## Architecture: Rust Engine + Lean 4 Proof Kernel

Birkin pairs a zero-runtime single native binary (sub-10ms cold start for PostToolUse / pre-commit hooks) with machine-checked Lean 4 theorems and an executable reference oracle (`birkin-oracle`) differentially tested against the Rust implementation in `cargo test`:

1. **Formal Kernel ([lean/lakefile.toml](lean/lakefile.toml))** — Zero-`sorry` Lean 4 proofs covering exit-code severity lattice laws (`ExitCode.lean`), layer DAG acyclicity (`LayerDag.lean`), append-only receipt hash-chain soundness (`Receipt.lean`), and denylist-dominating policy invariants (`Policy.lean`).
2. **Feedforward Guides** — Steer agents before edits via a strict, versioned [.birkin/config.yaml](.birkin/config.yaml) (`#[serde(deny_unknown_fields)]`), concise map-style `AGENTS.md` line budgets, verified doc links, and local-vs-CI command parity.
3. **Computational Sensors** — Deterministic multi-language static import parsing (Python, Go, Rust, TypeScript/JS) enforcing architecture layer DAG acyclicity and boundaries, forbidden imports, file size budgets, secret/debug/prose invariants, and custom regex rules — emitting LLM-optimized remediation instructions at edit time.
4. **Inferential Sensors + Self-Calibration** — Vendor-agnostic narrow semantic review rules over diffs or files via any OpenAI-compatible endpoint, with mandatory `examples_pass` / `examples_fail` calibration (`birkin eval-rules`).
5. **Append-Only Revision-Pinned Receipts** — Every check, hook, and verify run appends a SHA-256 hash-chained receipt outside the repo working tree (`~/.birkin/ledger/`) bound to exact `git HEAD`, working-tree digest, and `spec_sha256`.
6. **Observability-Driven Steering & Garbage Collection** — Distills receipts into recurring violation hotspots, agent thrash alerts, self-correction rates, before/after `spec_sha256` evolution, and dead/stale rules (`birkin steer`, `birkin gc`).

## Quick Start (Any Repository)

```bash
# 1. Auto-detect stack (Python/Go/Rust/Lean/TS) and scaffold .birkin/config.yaml
birkin init /path/to/repo --write

# 2. Emit compact feedforward brief for an agent entering the repo
birkin guide /path/to/repo

# 3. Run 6-axis repository readiness audit
birkin audit /path/to/repo

# 4. Run computational sensors + canonical verify commands and record a hash-chained receipt
birkin check /path/to/repo --run-verify

# 5. Prove the exact current HEAD/tree has passing receipts
birkin receipt verify /path/to/repo --require check,verify

# 6. Calibrate custom regex & semantic rules against their own pass/fail fixtures
birkin eval-rules /path/to/repo

# 7. Run optional narrow semantic review on staged diff or explicit files
birkin review /path/to/repo --staged

# 8. Inspect telemetry steering signals and entropy garbage-collection backlog
birkin steer /path/to/repo
birkin gc /path/to/repo
```

## Real-Time Operational Wiring (Hooks & Plugins)

```bash
# Install git pre-commit hook in a repo
birkin install-hooks /path/to/repo --target git

# Install Claude Code PostToolUse hook (repo-local .claude/settings.local.json, or --global)
birkin install-hooks /path/to/repo --target claude

# Install native Hermes Agent plugin (~/.hermes/plugins/birkin/, transform_tool_result)
birkin install-hooks --target hermes
```

On repositories without `.birkin/config.yaml`, hooks exit cleanly in milliseconds with zero interference.

## Hermes Runtime Verifier

All Hermes Agent configuration, live `/v1/models` contract, and gateway runtime drift checks are available both at top level and under `birkin hermes`:

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
| `1` | `STATIC / POLICY / SPEC VIOLATION` |
| `2` | `LIVE CONTRACT VIOLATION` (4xx, missing model, context mismatch, invalid semantic response) |
| `3` | `LIVE TRANSIENT UNAVAILABLE` (429/5xx/network/protocol/timeout) |
| `4` | `RUNTIME DRIFT` (gateway older than config/`.env`, missing start time, or SHA mismatch) |
| `5` | `TOOL / IO / SCHEMA ERROR` (missing explicit spec/policy, invalid YAML, unknown keys) |

## Development

```bash
lake --dir lean build
cargo clippy --all-targets -- -D warnings
cargo test
cargo run --quiet -- eval-rules
cargo run --quiet -- check --no-receipt
cargo build --release
```
