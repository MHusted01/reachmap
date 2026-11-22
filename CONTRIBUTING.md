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
| `check` | All of the above plus the release script tests | local only |
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

## Changelog

A PR with a user-visible change adds one fragment file to `changelog.d/` instead
of editing `CHANGELOG.md`, so PRs that merge in any order never conflict on the
changelog. Name it `<issue>.<category>.md`, where `<category>` is the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) group: `added`,
`changed`, `deprecated`, `removed`, `fixed` or `security`. It holds one bullet
that ends with the absolute issue link; continuation lines are indented by two
spaces. For example, `changelog.d/123.fixed.md`:

```markdown
- `reachmap scan` shows the owning process of sockets in another network
  namespace ([#123](https://github.com/MHusted01/reachmap/issues/123)).
```

## Releases

A release PR runs `scripts/changelog-assemble.sh X.Y.Z YYYY-MM-DD`. It folds the
fragments into a new `## [X.Y.Z] - YYYY-MM-DD` section below `## [Unreleased]`,
with the groups in Keep a Changelog order and the newest issue first, and
deletes them. It checks the version, the date and every fragment first, and
changes nothing if one is wrong. The PR then adds an optional summary paragraph
under the heading and bumps the version in `Cargo.toml`. Maintainers then tag
the merged commit on `main` with `vX.Y.Z`; the release workflow uses that
section as the release notes. A tag without a matching section fails, so
pre-release tags are not supported.

The workflow checks the tag, builds the binaries, creates the GitHub Release,
publishes to crates.io and opens a formula PR in `MHusted01/homebrew-tap`. It
needs two secrets in the `release` environment: `CARGO_REGISTRY_TOKEN` and
`TAP_TOKEN` (Contents and Pull requests on the tap). A PR that changes the
workflow or its scripts rehearses the checks and builds without publishing.

Tags cannot be moved. If a release fails after the tag, re-run the failed jobs;
if the tag itself is wrong, release the next patch version.
