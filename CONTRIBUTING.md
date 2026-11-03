# Contributing

## Workflow

`main` is protected. Every change goes through a pull request:

1. Branch from `main`: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`, `ci/<topic>`.
2. Keep the PR to one feature or fix.
3. Title the PR as a conventional commit, e.g. `feat: list listening TCP sockets`.
   The title becomes the squash commit on `main`.
4. These checks must pass: `lint`, `test`, `build`, `deny` and `pr-title`.
5. The `claude-review` workflow reviews every push to the PR. Address every
   comment and resolve all conversations before merging.
6. Merge with **Squash and merge**. The branch is deleted automatically.

## Setup

Install Rust with [rustup](https://rustup.rs); `rust-toolchain.toml` selects the
toolchain and components. For the full check you also need
`cargo install cargo-llvm-cov cargo-deny` (or `brew install cargo-llvm-cov cargo-deny`).

## Make targets

| Target | What it does | Used by |
| --- | --- | --- |
| `lint` | `cargo fmt --check` and `cargo clippy -D warnings` | CI `lint` |
| `test` | Unit and integration tests with an 80% line coverage gate | CI `test` |
| `build` | Debug build | CI `build` (macOS) |
| `deny` | Advisories, licences, bans and sources (`deny.toml`) | CI `deny` |
| `coverage` | HTML coverage report in `target/llvm-cov/html` | local only |
| `check` | All of the above plus the changelog script test | local only |
| `fmt` | Formats the code | local only |

## Rules

- reachmap is read-only and has no telemetry. Never add code that changes the
  system it inspects.
- Never report "blocked" or "safe" without evidence. Missing data is shown as
  unknown.
- Parsing and decision logic are pure functions, developed test-first with
  fixture files; code that touches the system stays thin.
- No `unsafe`; no `unwrap()` or `expect()` outside tests.
- Files under 400 lines, small functions. New dependencies need a reason and
  must pass `make deny`.

## Releases

Changes go under `## [Unreleased]` in `CHANGELOG.md`. Before a release, that
section is renamed to `## [X.Y.Z] - YYYY-MM-DD` in a PR. Maintainers then tag
the merged commit on `main` with `vX.Y.Z`; the release workflow uses that
section as the release notes. A tag without a matching section fails, so
pre-release tags are not supported.
