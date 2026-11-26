# AGENTS.md — Birkin Map

Last reviewed: 2026-11-26

Birkin is a native Rust verification engine (sub-10ms cold start) backed by a machine-checked Lean 4 formal specification kernel (`BirkinSpec`), serving multi-language repositories (Python, Go, Rust, Lean 4, TypeScript/JavaScript) and fail-closed Hermes Agent runtime verification.

## Repository Map

- Project specification: [.birkin/config.yaml](.birkin/config.yaml)
- Human overview & CLI reference: [README.md](README.md)
- Hermes policy example: [birkin-policy.example.yaml](birkin-policy.example.yaml)
- Formal proof kernel: [lean/lakefile.toml](lean/lakefile.toml) (`BirkinSpec.*` + `birkin-oracle`)
- CI pipeline: [.github/workflows/ci.yml](.github/workflows/ci.yml)

## Enforced Architecture DAG (`src/`)

Imports may only point downward; `birkin check` enforces this mechanically and `BirkinSpec.LayerDag` proves acyclicity:

1. **core**: `constants.rs`, `glob.rs` (no internal imports)
2. **models**: `models.rs`, `project_models.rs` -> `core`
3. **utils**: `config_utils.rs`, `imports_parser.rs`, `ledger.rs` -> `core`, `models`
4. **engines**: `static_check.rs`, `live.rs`, `drift.rs`, `guides.rs`, `project_init.rs`, `sensors.rs`, `semantic.rs`, `verify.rs` -> `core`, `models`, `utils`
5. **orchestration**: `gc.rs`, `steer.rs`, `hooks.rs`, `report.rs` -> `core`, `models`, `utils`, `engines`
6. **cli**: `cli.rs`, `project_cli.rs`, `ops_cli.rs`, `lib.rs`, `main.rs` -> lower layers

## Formal Kernel (`lean/BirkinSpec/`)

Zero `sorry` placeholders permitted:

- `ExitCode.lean`: severity lattice laws and fail-closed `combineAll` monotonicity.
- `LayerDag.lean`: topological rank soundness and acyclicity of Birkin's 6-layer DAG.
- `Receipt.lean`: fail-closed hash-chain tamper detection and admission-gate invariants.
- `Policy.lean`: denylist dominance over allowlists and exact compression bounds.
- `Oracle.lean`: executable `birkin-oracle` differentially tested against Rust in `cargo test`.

## Non-Negotiable Invariants

- All repo prose (docs, comments, rules, briefs) must be in English.
- Fail closed: unknown policy/spec keys (`#[serde(deny_unknown_fields)]`), missing explicit specs, and provider/parse errors are never treated as approval.
- Never naively attach literal category words like `harness` to filesystem paths, config filenames, plugins, CLI flags, or identifiers — use Birkin's own identity (`.birkin/config.yaml`, `~/.hermes/plugins/birkin`).
- Keep `AGENTS.md` <= 140 lines and every code module <= 600 lines.
- Every custom regex or semantic rule must ship with both `examples_pass` and `examples_fail` fixtures and pass `birkin eval-rules`.
- Pair every new guard with both positive and negative (Proof-of-Life) tests.

## Canonical Admission Gate (Identical to CI)

```bash
cd lean && lake build && cd ..
cargo clippy --all-targets -- -D warnings
cargo test
cargo run --quiet -- eval-rules
cargo run --quiet -- check --no-receipt
```

Before finishing work, record revision-pinned receipts and confirm verification:

```bash
birkin check --run-verify
birkin receipt verify --require check,verify
```
