# Birkin

<p align="center"><img src="assets/logo/birkin-512.png" width="256" height="256" alt="Birkin logo, a cognac leather bag"></p>

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
birkin receipt verify --require check,verify
```

`check --run-verify` runs the configured shell commands as well as the built-in checks. `receipt verify` checks the hash chain in the local ledger and looks for passing receipts matching the current revision, working tree, and configuration. Run both in the same CI job to use their exit codes as a merge condition.

## Agent integrations

| Integration | Command | When it runs |
| --- | --- | --- |
| Git | `birkin install-hooks --target git` | Before a commit |
| Claude Code | `birkin install-hooks --target claude` | After a tool call, via project-local settings |
| Hermes Agent | `birkin install-hooks --target hermes` | As a plugin installed in the user's Hermes environment |

## Other commands

| Command | Use |
| --- | --- |
| `birkin audit` | Inspect repository readiness across six areas, including architecture and observability. |
| `birkin eval-rules` | Check custom rules against their passing and failing examples. |
| `birkin review --staged` | Run configured semantic review rules on a staged diff using an OpenAI-compatible endpoint. |
| `birkin steer` / `birkin gc` | Inspect recurring findings in the ledger and find rules to revisit. |
| `birkin static` / `birkin live --probe` / `birkin drift` | Check Hermes configuration, live provider contracts, or gateway drift. See the [example policy](birkin-policy.example.yaml). |

## Verification model

The Rust CLI performs repository checks. The [Lean 4 specification](lean/BirkinSpec.lean) models selected properties of exit-code ordering, layer dependencies, receipts, and policy decisions. [Differential tests](tests/lean_oracle_diff.rs) compare Rust behavior with the executable Lean reference on test inputs. The proofs apply to those models. Each project's configured commands determine what a passing verification covers.

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
```

For a false positive or an unexpected pass, [open an issue](https://github.com/hauntedfail/birkin/issues) with the Birkin version, the smallest rule and input that reproduce it, and the expected and actual output. The [repository map](AGENTS.md) lists implementation modules and contributor conventions.
