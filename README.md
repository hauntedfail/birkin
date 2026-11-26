# Birkin

Mechanical verifier for Hermes Agent configuration, provider `/v1/models` contracts, and live gateway runtime drift.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | `PASS` |
| `1` | `STATIC / POLICY VIOLATION` |
| `2` | `LIVE CONTRACT VIOLATION` (404/401/403/400, missing model, context mismatch) |
| `3` | `LIVE TRANSIENT UNAVAILABLE` (429/5xx/network/timeout) |
| `4` | `RUNTIME DRIFT` (gateway older than `config.yaml`/`.env` or code SHA mismatch) |
| `5` | `TOOL / IO ERROR` |

## Usage

```bash
# Structural, semantic, and fail-closed policy checks
birkin static

# Live provider /v1/models contract check (add --probe for a 1-token micro-probe)
birkin live

# Gateway runtime drift check
birkin drift

# Combined check (writes ~/.hermes/state/birkin.json unless --no-write-state)
birkin all --live
birkin all --live --json
```

## Policy File

Copy `birkin-policy.example.yaml` to `~/.hermes/birkin-policy.yaml` (or pass `--policy <path>`).
By default, fallback providers are fail-closed (`allowed: []`) and denylisted patterns (such as `*opus*`) are rejected with exit code `1`.

## Development

```bash
pip install -e ".[dev]"
pytest -v
```
