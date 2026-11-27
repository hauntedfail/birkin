# AGENTS.md — Birkin Map

Last reviewed: 2026-11-26

Birkin is a native Rust verification engine (sub-10ms cold start) backed by a machine-checked Lean 4 formal specification kernel (`BirkinSpec`), serving multi-language repositories (Python, Go, Rust, Lean 4, TypeScript/JavaScript) and fail-closed Hermes Agent runtime verification.

## Repository Map

- Project specification: [.birkin/config.yaml](.birkin/config.yaml)
- Human overview & CLI reference: [README.md](README.md)
- Hermes policy example: [birkin-policy.example.yaml](birkin-policy.example.yaml)
- Formal proof kernel: [lean/lakefile.toml](lean/lakefile.toml) (`BirkinSpec.*` + `birkin-kernel` + `birkin-oracle`)
- CI pipeline: [.github/workflows/ci.yml](.github/workflows/ci.yml)

## Enforced Architecture DAG (`src/`)

Imports may only point downward; `birkin check` enforces this mechanically, `birkin prove` proves layer-DAG acyclicity and extracted import compliance in Lean 4, and `BirkinSpec.LayerDag` proves acyclicity for Birkin itself:

1. **core**: `constants.rs`, `glob.rs` (no internal imports)
2. **models**: `models.rs`, `project_models.rs`, `proof_models.rs`, `workflow_models.rs` -> `core`
3. **utils**: `config_utils.rs`, `imports_parser.rs`, `lean_kernel.rs`, `ledger.rs` -> `core`, `models`
4. **engines**: `static_check.rs`, `live.rs`, `drift.rs`, `guides.rs`, `lean_certify.rs`, `project_init.rs`, `prove.rs`, `prove_audit.rs`, `prove_lean.rs`, `sensors.rs`, `semantic.rs`, `verify.rs`, `plan_contract.rs`, `scope_contract.rs`, `authority_contract.rs`, `stage_contract.rs`, `review_closure.rs` -> `core`, `models`, `utils`
5. **orchestration**: `client_sync.rs`, `gc.rs`, `steer.rs`, `hooks.rs`, `report.rs` -> `core`, `models`, `utils`, `engines`
6. **cli**: `cli.rs`, `project_cli.rs`, `ops_cli.rs`, `workflow_cli.rs`, `workflow_stage_cli.rs`, `lib.rs`, `main.rs` -> lower layers

## Formal Kernel (`lean/BirkinSpec/`)

Zero `sorry` placeholders permitted:

- `ExitCode.lean`: severity lattice laws and fail-closed `combineAll` monotonicity.
- `LayerDag.lean`: topological rank soundness and acyclicity of Birkin's 6-layer DAG.
- `Receipt.lean`: fail-closed hash-chain tamper detection and admission-gate invariants.
- `Policy.lean`: denylist dominance over allowlists and exact compression bounds.
- `PlanContract.lean`, `ScopeContract.lean`, `AuthorityContract.lean`, `StageAdmission.lean`, `ReviewClosure.lean`: workflow-contract invariants.
- `Json.lean`, `Diagnostics.lean`, `Kernel.lean`: zero-dependency JSON codec, proved diagnostic equivalence theorems, and the production `birkin-kernel` executable (Mode A, ~10 ms, fail-closed) paired with `--certify` Lean kernel certificates (Mode B, ~0.3 s, `#print axioms` audited).
- `Oracle.lean`: legacy line-oriented `birkin-oracle` retained for differential checks.

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
cargo run --quiet -- prove --no-receipt
```

Before finishing work, record revision-pinned receipts and confirm verification:

```bash
birkin check --run-verify
birkin prove
birkin receipt verify --require check,verify,prove
```

Opt-in workflow contract commands (`--json`, `--no-receipt`, exit codes `0`/`1`/`5`):

```bash
birkin plan verify <plan.json>
birkin unit admit --plan <plan.json> --task <id> --role <role> --tier <R|W|F>
birkin unit verify-scope --plan <plan.json> --task <id> --staged
birkin stage verify --stage <stage> [--test-transcript <file>] [--sawyer-pack <pack.json>]
birkin sawyer verify --pack <pack.json> --phase <preflight|staged|post-push>
birkin review-closure verify <review-state.json>
```
