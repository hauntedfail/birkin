# Birkin Workflow Contracts Architecture & Evolution

This document explains how Birkin separates universal formally verified workflow laws from per-repository configuration and cross-client adapters, and how operational incidents are systematically promoted into machine-enforced checks.

## 1. Three-Layer Separation

Birkin divides workflow enforcement into three decoupled layers so that universal invariants remain formally verified while repositories keep full flexibility and clients stay thin:

| Layer | Location | Responsibility |
| --- | --- | --- |
| **1. Universal Lean 4 Kernel** | [lean/BirkinSpec.lean](../lean/BirkinSpec.lean) & [lean/BirkinSpec/Oracle.lean](../lean/BirkinSpec/Oracle.lean) | Proves core decision invariants in Lean 4 with zero `sorry`, zero `native_decide`, and standard axioms only (`propext`, `Classical.choice`, `Quot.sound`). Compiled into `birkin-oracle` and differential-tested against Rust in [tests/lean_oracle_diff.rs](../tests/lean_oracle_diff.rs). |
| **2. Per-Repository Opt-In Binding** | [.birkin/config.yaml](../.birkin/config.yaml) (`workflow:` + `proofs:`) | Each repository enables only the contracts, toolchain pin files, test-runner parsers, Sawyer exclusion whitelists, service build guards, and domain-specific Lean proofs it needs. Configs without a `workflow:` section remain 100% backward compatible. |
| **3. Thin Cross-Client Adapters** | [src/client_sync.rs](../src/client_sync.rs) (`birkin sync`) | Renders deterministic, version- and SHA-256-stamped shims for Git, Claude Code, Hermes, and shared workflow skills so every client invokes the same native `birkin` binary. Drift across clients is detected via `birkin sync --check`. |

### Per-Repository Configuration (`workflow:` + `proofs:`)

Repositories opt into workflow enforcement inside `.birkin/config.yaml` (validated strictly with `#[serde(deny_unknown_fields)]`):

```yaml
workflow:
  enabled_contracts: [plan, scope, authority, stage, sawyer, review_closure]
  require_plan_receipt: false
  toolchain_pin_files: ["lean/lean-toolchain"]
  exclude_whitelist_path: ".sawyer/exclude-whitelist.txt"
  test_runners:
    - name: cargo-test
      parser: cargo_test
      require_nonzero: true
  service_build_guards: []
```

Domain-specific state machines, access policies, and custom Lean 4 libraries continue to live in `proofs:` and are verified by `birkin prove`, recording into the same hash-chained receipt ledger.

## 2. The Five Workflow Contracts

Every workflow subcommand supports `--json`, `--no-receipt`, `--repo <dir>`, and `--spec <path>`, and records revision-bound, hash-chained receipts when telemetry is enabled.

| Contract | Lean 4 Kernel Module | CLI Command | Key Proved Invariants |
| --- | --- | --- | --- |
| **Plan** | `BirkinSpec.PlanContract` | `birkin plan verify <plan.json>` | Unique task IDs; strict acyclic topological dependency order; transitive blocking propagation from `blocked` tasks and open blocking questions; `intent: plan_only` forbids mutation; `status: done` requires non-empty `completion_evidence`. |
| **Scope** | `BirkinSpec.ScopeContract` | `birkin unit verify-scope --plan <plan.json> --task <id> [--staged]` | Normalized path containment (no traversal or symlink escape); `forbidden_paths` strictly dominates `allowed_paths`; `verification_output_paths` never grants editable source authority; active concurrent write units on the same checkout must have disjoint write sets. |
| **Authority** | `BirkinSpec.AuthorityContract` | `birkin unit admit --plan <plan.json> --task <id> --role <role> --tier <R\|W\|F>` | Composes plan dispatchability with role/tier authority: `R < W < F` lattice, read-only roles (`scope`, `review`, `research`, `docs`) capped at `R`, tier `F` requires `--explicit-f`, reviewer must be independent of implementer (`model` or `runtime` differs), worker refusal forbids tier escalation, retries bounded (`<= 2`), and policy denylist dominance. |
| **Stage & Sawyer** | `BirkinSpec.StageAdmission` | `birkin stage verify --stage <stage>` and `birkin sawyer verify --pack <pack.json> [--phase preflight\|staged\|post-push]` | Strict monotonic lifecycle (`implemented < verified < reviewed < committed < pushed < ci_passed < released`); zero discovered tests and partial execution (`executed < discovered`) fail closed; revision/tree/spec/toolchain-pin binding; exact Sawyer staging, exclusion whitelist disjointness, required commit signature verification, and remote head readback. |
| **Review Closure** | `BirkinSpec.ReviewClosure` | `birkin review-closure verify <review-state.json>` | Canonical review-item deduplication; exhaustive classification (`must_fix`, `already_fixed`, `not_valid`, `out_of_scope`, `needs_clarification`); resolved threads require a reply with a URL; `must_fix` items require verification; any open `needs_clarification` blocks re-review requests. |

### Observed vs. Attested Evidence in `birkin stage verify`

`birkin stage verify` enforces a strict provenance boundary between directly observed machine state and external attestations:

- **Observed facts (`provenance: "observed"`)**: Hash-chained ledger receipts, Git HEAD and working-tree digest, configured toolchain pin files, parsed test counts from `--test-transcript` via `workflow.test_runners`, and Sawyer Git staging/commit/signature/remote-head state. Birkin never accepts caller booleans for any observable fact.
- **Attested facts (`provenance: "attested"`)**: External gates that Birkin cannot directly observe locally (`--review-evidence`, `--ci-evidence`, `--release-evidence`). Each requires a non-empty evidence file whose SHA-256 digest and source path are recorded in both JSON output and ledger receipts (and review state JSON files are additionally validated through `review_closure`).

### Exit Codes

| Exit Code | Constant | Meaning |
| --- | --- | --- |
| `0` | `EXIT_PASS` | All checks, proofs, contract gates, or adapter sync operations passed. |
| `1` | `EXIT_STATIC` | Static rule, contract violation, or `birkin sync --apply` refusal (unmanaged file or symlink). |
| `2` | `EXIT_LIVE_CONTRACT` | Live provider contract violation. |
| `3` | `EXIT_LIVE_TRANSIENT` | Live endpoint unavailable or transient transport failure. |
| `4` | `EXIT_DRIFT` | Runtime drift or adapter drift detected by `birkin sync --check` (missing, stale, unmanaged, or symlink-refused). |
| `5` | `EXIT_TOOL_ERROR` | Invalid CLI flags, missing `--target-root`, unknown `--target`, schema parse error, or I/O error. |

## 3. Cross-Client Adapter Sync & Drift Detection (`birkin sync`)

`birkin sync` materializes and audits thin adapters under an explicit `--target-root <dir>` (never defaulting to live `$HOME`):

```sh
# Read-only drift audit (writes nothing; exits 0 if synchronized, 4 on drift)
birkin sync --check --target-root /path/to/root --json

# Deterministic idempotent write (exits 0 when synchronized/applied, 1 if any target is refused)
birkin sync --apply --target-root /path/to/root --json

# Target filtering (repeatable: git, claude, hermes, skills, all)
birkin sync --apply --target-root /path/to/root --target git --target skills
```

Managed adapter layout under `<target_root>`:

- `git`: `git-hooks/pre-commit` — POSIX `sh` shim invoking `birkin hook pre-commit` (respects `BIRKIN_SKIP_HOOK=1`, mode `0755` on Unix).
- `claude`: `claude/birkin-hooks.json` — PostToolUse hook snippet invoking `birkin hook post-edit --surface claude --claude-stdin` with `_birkin_managed` version and template SHA-256 metadata.
- `hermes`: `hermes/plugins/birkin/plugin.yaml` and `hermes/plugins/birkin/__init__.py` — rendered from the canonical helper in `src/hooks.rs` and stamped with version and template SHA-256.
- `skills`: executable POSIX `sh` shims under `skills/birkin/` (`plan-verify.sh`, `unit-admit.sh`, `scope-check.sh`, `stage-verify.sh`, `sawyer-verify.sh`, `review-closure.sh`) delegating directly to the corresponding `birkin` workflow subcommands.

### Fail-Closed Safety Guarantees

1. **Managed marker & hash stamp**: Every rendered adapter carries the `birkin-managed-adapter` header, Birkin package version, contract version, and deterministic `template_sha256` computed from its canonical payload, while `expected_sha256` hashes the full rendered bytes.
2. **Unmanaged file protection**: If an existing regular file at a target path lacks the `birkin-managed-adapter` marker, `--apply` refuses to overwrite it (`state: "unmanaged"`, exit `1`) and `--check` reports drift (exit `4`).
3. **Symlink refusal**: Before reading or writing any target, Birkin walks every path component from `<target_root>` to the leaf with `symlink_metadata` (and opens with `O_NOFOLLOW` on Unix). Any intermediate or leaf symlink — internal, external, or dangling — is marked `symlink_refused` without ever reading through or writing to the symlink target.

See [tests/client_sync_and_drift.rs](../tests/client_sync_and_drift.rs) for isolated temporary-directory verification of all apply, idempotency, drift, unmanaged-file, and symlink cases.

## 4. Contract Evolution Loop

Whenever an operational failure occurs in any client session, promote the lesson mechanically rather than piling up unverified prose:

1. **Observe incident**: Capture the concrete failure mode (for example: zero-test false pass, out-of-scope file edit, concurrent checkout collision, or premature review thread resolution).
2. **Add failing regression**: Write a minimal failing test in Birkin (or a pass/fail fixture under `.birkin/config.yaml` verified by `birkin eval-rules`).
3. **Promote invariant**:
   - If the rule is universal across repositories, formalize the theorem in `lean/BirkinSpec/`, implement the matching Rust check, and add a differential case in [tests/lean_oracle_diff.rs](../tests/lean_oracle_diff.rs).
   - If the rule is repository-specific, express it in that repository's `.birkin/config.yaml` (`architecture`, `invariants`, `workflow`, or `proofs`).
4. **Compress prose**: Remove duplicated natural-language instructions from client skill docs once the binary enforces the rule deterministically.
5. **Sync and audit clients**: Roll out updated thin adapters with `birkin sync --apply --target-root <dir>` and enforce zero drift across clients with `birkin sync --check --target-root <dir> --json` (`EXIT_DRIFT = 4`).

For top-level installation and CLI quickstart, see [README.md](../README.md).
