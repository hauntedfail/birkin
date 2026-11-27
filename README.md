<h1 align="center">
  <img src="assets/logo/birkin-512.png" width="160" height="160" alt=""><br>
  Birkin
</h1>

Birkin checks a coding agent's changes against the rules of your Git repository. Define which modules may depend on each other, which instructions the agent should read, and which tests must pass. The same CLI can report a violation while the agent edits and record which checks passed for a specific revision in CI.

## Try it on Birkin itself

With Git and a Rust toolchain including Cargo, run the following in a terminal. The first check uses the rules shipped in this repository and works locally without an agent or API key.

```sh
git clone https://github.com/hauntedfail/birkin.git
cd birkin
cargo install --locked --path .
birkin check --no-receipt
```

Cargo installs the executable in its `bin` directory (normally `~/.cargo/bin` on Unix). A clean checkout should report `status=PASS` and `findings=0`.

For example, Birkin's own policy keeps HTTP clients out of its static checks. Adding `use ureq;` to `src/constants.rs` produces this diagnostic, even though `ureq` is a valid dependency elsewhere in the crate. The command exits with code `1`.

```text
[ERROR] ARCH_FORBIDDEN_IMPORT:no-network-in-static-or-models (src/constants.rs:59): Pure static, schema, and parser modules must stay offline and never import HTTP clients. (found import `ureq`)
  remediation: Keep network I/O isolated to src/live.rs or src/semantic.rs.
```

## Use it in your repository

From the root of your own Git repository, preview the detected settings, then write the configuration and inspect the guide.

```sh
birkin init
birkin init --write
birkin guide
```

Birkin detects Python, Go, Rust, Lean, and JavaScript or TypeScript project files. In `.birkin/config.yaml`, review the detected test commands, point `orientation.entry_docs` at your agent instructions, and add the dependency boundaries your project needs. Commit the configuration with your project. Birkin's own [configuration](.birkin/config.yaml) shows a working layer map and the HTTP import rule above.

```sh
birkin check --run-verify
birkin prove
birkin receipt verify --require check,verify,prove
```

`check --run-verify` runs the configured shell commands as well as the built-in checks. `prove` compiles the repository's layer DAG, extracted import graph, declarative state machines, and boundary policies into a self-contained Lean 4 proof module, verifies it with Lean's kernel, and audits custom Lean projects with `#print axioms`. `receipt verify` checks the hash chain in the local ledger and looks for passing receipts matching the current revision, working tree, and configuration. Run these in the same CI job to use their exit codes as a merge condition.

## Agent integrations

| Integration | Command | When it runs |
| --- | --- | --- |
| Git | `birkin install-hooks --target git` | Before a commit |
| Claude Code | `birkin install-hooks --target claude` | After a tool call, via project-local settings |
| Hermes Agent | `birkin install-hooks --target hermes` | As a plugin installed in the user's Hermes environment |

## Other commands

| Command | Use |
| --- | --- |
| `birkin prove` | Compile repository architecture, state machines, and policies to Lean 4, verify them with Lean's kernel, and audit custom Lean projects. |
| `birkin audit` | Inspect repository readiness across seven areas, including architecture, proofs, and observability. |
| `birkin eval-rules` | Check custom rules against their passing and failing examples. |
| `birkin review --staged` | Run configured semantic review rules on a staged diff using an OpenAI-compatible endpoint. |
| `birkin steer` / `birkin gc` | Inspect recurring findings in the ledger and find rules to revisit. |
| `birkin plan verify <plan.json>` | Validate execution-plan DAG order, blocking propagation, and completion evidence. |
| `birkin unit admit --plan <plan.json> --task <id> --role <role> --tier <R\|W\|F>` | Enforce both plan dispatchability and role/tier authority before delegating a unit. |
| `birkin unit verify-scope --plan <plan.json> --task <id> [--staged]` | Verify changed or staged paths stay inside `allowed_paths` and disjoint from active units. |
| `birkin stage verify --stage <stage>` | Verify lifecycle stage admission from observed receipts, Git tree, toolchain pins, test transcripts, Sawyer state, and attested review/CI/release evidence. |
| `birkin sawyer verify --pack <pack.json> [--phase preflight\|staged\|post-push]` | Verify exact staging, exclusion whitelist, commit signature, and remote head readback. |
| `birkin review-closure verify <review-state.json>` | Verify canonical review items are classified, replied with URLs where resolved, verified, and clear of open clarifications. |
| `birkin sync --check\|--apply --target-root <dir>` | Audit or deterministically sync version- and hash-stamped thin client adapters (`git`, `claude`, `hermes`, `skills`), exiting `4` on drift and refusing unmanaged files or symlinks. |
| `birkin static` / `birkin live --probe` / `birkin drift` | Check Hermes configuration, live provider contracts, or gateway drift. See the [example policy](birkin-policy.example.yaml). |

Workflow contract subcommands are opt-in per repository via the optional `workflow:` section in `.birkin/config.yaml` (`enabled_contracts`, `toolchain_pin_files`, `exclude_whitelist_path`, `test_runners`, `require_plan_receipt`). Existing configs without `workflow:` continue working unchanged. Every workflow subcommand supports `--json`, `--no-receipt`, `--certify`, and `--emit-proof <path>`, appends revision-bound hash-chained receipts when telemetry is enabled, and returns Birkin's standard exit codes (`0` pass, `1` contract violation, `5` missing kernel/Lean toolchain, schema, or I/O error). All workflow contract verdicts are evaluated directly by a single formally verified Lean 4 specification — Mode A executes the compiled native `birkin-kernel` binary (~10 ms, fail-closed, zero Rust decision mirrors) and Mode B (`--certify`) emits and kernel-typechecks a `.lean` proof certificate audited with `#print axioms` and recorded in the receipt ledger. In `birkin stage verify`, facts Birkin can observe directly (receipts, tree binding, toolchain pins, parsed test counts, Sawyer Git state, remote head) are never accepted as caller booleans, while external facts (`review_passed`, `ci_passed`, `release_authorized`) require explicit evidence files and are marked `attested` in both JSON output and ledger receipts. See [docs/workflow-contracts.md](docs/workflow-contracts.md) for the architecture, adapter sync contract, and incident-to-theorem evolution loop.

## Verification model

Birkin combines fast native sensors with a single-source Lean 4 formal kernel:

- **Fast local sensors (`birkin check`)**: Native Rust CLI (sub-10ms cold start, no Lean required at edit time).
- **Single-source Lean 4 workflow kernel (Mode A `birkin-kernel` + Mode B `--certify`)**: Workflow contract admission (`plan`, `scope`, `authority`, `stage`, `sawyer`, `review-closure`) delegates 100% of decisions to the Lean 4 specification (`BirkinSpec`) compiled into standalone `birkin-kernel` (Mode A, ~10 ms, zero Lean shared libraries, fail-closed) or kernel-typechecked on demand via `--certify` (Mode B, ~0.3 s, `#print axioms` audited, `proof_sha256` recorded in the ledger).
- **Per-repository formal proofs (`birkin prove`)**: Compiles `.birkin/config.yaml` (`architecture.layers`, `forbidden_imports`, `proofs.state_machines`, `proofs.policies`) together with extracted codebase import facts into a self-contained Lean 4 module, verifies every theorem strictly in Lean's kernel (no `sorry`, no `native_decide`, standard axioms only), and builds/audits repo-owned `proofs.lean_projects`.
- **Trusted Computing Base (TCB)**: Lean 4's kernel guarantees the workflow contract theorems, diagnostic equivalence, DAG acyclicity, compliance of the extracted import graph, exhaustive state-machine/policy safety, and axiom hygiene. Mode A additionally trusts Lean's native code generator; Mode B (`--certify`) removes code generation from the TCB by invoking Lean's type-checker directly. Rust handles I/O fact extraction (JSON parsing, symlink/realpath resolution, test-log parsing, Git readback) only.

| Exit code | Meaning |
| --- | --- |
| `0` | Passed |
| `1` | Static, policy, or repository rule violation |
| `2` | Live contract violation |
| `3` | Live service unavailable or transient request failure |
| `4` | Runtime drift |
| `5` | Tool, I/O, or schema error |

## Development and feedback

For contributor checks, install Clippy and the Lean toolchain pinned in [lean/lean-toolchain](lean/lean-toolchain). From the repository root, run the same checks as [CI](.github/workflows/ci.yml).

```sh
(cd lean && lake build)
cargo clippy --all-targets -- -D warnings
cargo test
cargo run --quiet -- eval-rules
cargo run --quiet -- check --no-receipt
cargo run --quiet -- prove --no-receipt
```

For a false positive or an unexpected pass, [open an issue](https://github.com/hauntedfail/birkin/issues) with the Birkin version, the smallest rule and input that reproduce it, and the expected and actual output. The [repository map](AGENTS.md) lists implementation modules and contributor conventions.
