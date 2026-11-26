# Birkin

Mechanical verifier for Hermes Agent configuration, provider `/v1/models` contracts, and live gateway runtime drift.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | `PASS` |
| `1` | `STATIC / POLICY VIOLATION` |
| `2` | `LIVE CONTRACT VIOLATION` (404/401/403/400, missing model, context mismatch, invalid probe body) |
| `3` | `LIVE TRANSIENT UNAVAILABLE` (429/5xx/network/protocol/timeout) |
| `4` | `RUNTIME DRIFT` (gateway older than `config.yaml`/`.env`, missing start timestamp, or code/config SHA mismatch) |
| `5` | `TOOL / IO ERROR` (missing config or explicit `--policy`, invalid YAML, unknown policy key) |

## Usage

```bash
# Structural, semantic, and fail-closed policy checks
birkin static

# Live provider /v1/models contract check (add --probe for a 1-token micro-probe)
birkin live
birkin live --probe

# Gateway runtime drift check
birkin drift

# Combined check (writes ~/.hermes/state/birkin.json atomically unless --no-write-state)
birkin all --live
birkin all --live --json

# CLI-only / CI hosts without a running gateway daemon
birkin all --skip-drift --no-write-state
```

## Policy File

Copy `birkin-policy.example.yaml` to `~/.hermes/birkin-policy.yaml` (or pass `--policy <path>`).

- Policy validation is **strict (`extra="forbid"`)**: misspelled keys fail closed with exit code `5` instead of silently falling back to defaults.
- Passing an explicit `--policy <path>` that does not exist fails closed with exit code `5`.
- By default, fallback providers are fail-closed (`allowed: []`), and `forbidden_patterns` (such as `*opus*`) are enforced globally across `model.default`, `auxiliary.<role>.model`, and `fallback_providers`.

## Architecture

```text
src/birkin/
├── constants.py     # Exit codes and default paths
├── models.py        # Finding and strict Pydantic policy models
├── config_utils.py  # YAML/policy loading, secret redaction, dotenv parser, provider lookup
├── static.py        # Layer 1: structural, semantic, and fail-closed policy checks
├── live.py          # Layer 2: /v1/models catalog contract and optional micro-probe
├── drift.py         # Layer 3: live gateway PID, config/env freshness, and SHA checks
├── report.py        # Exit-code precedence, human output, atomic state writer
└── cli.py           # CLI parser and command orchestration
```

## Development

```bash
pip install -e ".[dev]"
ruff check src tests
pytest -v
```
