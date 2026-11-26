# AGENTS.md — Birkin Map

Last reviewed: 2026-11-26

Birkin is a portable Harness Engineering engine for multi-language repositories (Python, Go, Rust, TypeScript/JavaScript) plus a fail-closed Hermes runtime verifier.

## Repository Map

- Portable harness spec: [.birkin/harness.yaml](.birkin/harness.yaml)
- Human overview & CLI reference: [README.md](README.md)
- Hermes policy example: [birkin-policy.example.yaml](birkin-policy.example.yaml)
- CI pipeline: [.github/workflows/ci.yml](.github/workflows/ci.yml)

## Enforced Architecture DAG (`src/birkin/`)

Imports may only point downward; `birkin check` enforces this mechanically:

1. **core**: `constants.py` (no internal imports)
2. **models**: `models.py`, `project_models.py` -> `core`
3. **utils**: `config_utils.py`, `imports_parser.py`, `ledger.py` -> `core`, `models`
4. **engines**: `static.py`, `live.py`, `drift.py`, `guides.py`, `project_init.py`, `sensors.py`, `semantic.py` -> `core`, `models`, `utils`
5. **orchestration**: `gc.py`, `steer.py`, `hooks.py`, `report.py` -> `core`, `models`, `utils`, `engines`
6. **cli**: `cli.py`, `project_cli.py`, `__init__.py` -> lower layers

## Non-Negotiable Invariants

- All repo prose (docs, comments, harness rules, briefs) must be in English.
- Fail closed: unknown policy/harness keys (`extra="forbid"`), missing explicit specs, and provider/parse errors are never treated as approval.
- Keep `AGENTS.md` <= 140 lines and every code module <= 600 lines.
- Every custom regex or semantic rule must ship with both `examples_pass` and `examples_fail` fixtures and pass `birkin eval-rules`.
- Pair every new guard with both positive and negative (Proof-of-Life) tests.

## Canonical Admission Gate (Identical to CI)

```bash
ruff check src tests
pytest -v
birkin eval-rules
birkin check --no-receipt
```

Before finishing work, record revision-pinned receipts and confirm verification:

```bash
birkin check --run-verify
birkin receipt verify --require check,verify
```
