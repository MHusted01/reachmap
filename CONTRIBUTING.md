# Contributing

## Workflow

`main` is protected. Every change goes through a pull request:

1. Branch from `main` as `<type>/<issue>-<slug>`, e.g. `feat/2-tcp-sockets`.
2. Keep the PR to one feature or fix.
3. Title the PR as a conventional commit, e.g. `feat: list listening TCP sockets`.
   The title becomes the squash commit on `main`.
4. Sign your commits: every commit in the PR needs a
   [verified signature](https://docs.github.com/en/authentication/managing-commit-signature-verification),
   not only the squash commit.
5. These checks must pass: `lint`, `test`, `build`, `deny` and `pr-title`. The
   branch must be up to date with `main`. The `macos` check runs the tests on
   macOS but is not required, because macOS runners can take long to start. If
   it fails, fix the failure, also when it fails after the merge.
6. Every PR is reviewed, and all conversations must be resolved before merging.
   The `claude-review` workflow comments on the owner's PRs from this
   repository; it does not run on PRs from forks, because they get no secrets.
   Its output is advisory: it can miss problems and be wrong, so tests and human
   judgement decide.
7. Merge with **Squash and merge**. The branch is deleted automatically.

## Setup

Install Rust with [rustup](https://rustup.rs); `rust-toolchain.toml` selects the
toolchain and components. For the full check you also need
`cargo install cargo-llvm-cov cargo-deny` (or `brew install cargo-llvm-cov cargo-deny`)
and Docker, which runs the workflow and script linters.

## Make targets

| Target | What it does | Used by |
| --- | --- | --- |
| `lint` | `cargo fmt --check` and `cargo clippy -D warnings` | CI `lint` |
| `lint-ci` | actionlint on the workflows, ShellCheck on `scripts/` | CI `lint` |
| `test` | Unit and integration tests with an 80% line coverage gate | CI `test` |
| `msrv` | The tests on the `rust-version` from `Cargo.toml` | CI `test` |
| `build` | Debug build | CI `build`, CI `macos` |
| `check-macos` | Type-checks the macOS code from any OS | CI `build` |
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
- Non-test code under 400 lines per file (800 at most with tests), small
  functions. New dependencies need a reason and must pass `make deny`.

## Releases

Changes go under `## [Unreleased]` in `CHANGELOG.md`. Before a release, that
section is renamed to `## [X.Y.Z] - YYYY-MM-DD` in a PR. Maintainers then tag
the merged commit on `main` with `vX.Y.Z`; the release workflow uses that
section as the release notes. A tag without a matching section fails, so
pre-release tags are not supported.
