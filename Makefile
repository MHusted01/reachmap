COVERAGE_MIN := 80

# The minimum supported Rust version, as advertised in Cargo.toml.
MSRV := $(shell sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml)

# Pinned by digest, so CI and local runs use the same tools. The image also
# contains ShellCheck, which actionlint uses for `run:` blocks.
ACTIONLINT_IMAGE := rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
IN_LINT_IMAGE := docker run --rm -v "$(CURDIR)":/repo:ro -w /repo

.PHONY: fmt lint lint-ci test test-docker msrv coverage deny build check clean

fmt:
	cargo fmt --all

lint:
	cargo fmt --all --check
	cargo clippy --all-targets --all-features --locked -- -D warnings

# GitHub Actions workflows and shell scripts. Needs Docker.
lint-ci:
	$(IN_LINT_IMAGE) $(ACTIONLINT_IMAGE) -color
	$(IN_LINT_IMAGE) --entrypoint shellcheck $(ACTIONLINT_IMAGE) scripts/changelog-section.sh scripts/test-changelog-section.sh scripts/test-docker-scan.sh

# Unit and integration tests with a line coverage gate (cargo-llvm-cov).
test:
	cargo llvm-cov --all-targets --locked --fail-under-lines $(COVERAGE_MIN)

# reachmap against a real Docker daemon. Linux only, so not part of `check`;
# CI runs it in the test job.
test-docker: build
	scripts/test-docker-scan.sh target/debug/reachmap

# The tests on the minimum supported Rust version, in their own target
# directory so they do not evict the stable build.
msrv:
	$(if $(MSRV),,$(error could not read rust-version from Cargo.toml))
	rustup toolchain install $(MSRV) --profile minimal
	CARGO_TARGET_DIR=target/msrv cargo +$(MSRV) test --locked

# HTML coverage report in target/llvm-cov/html for local browsing.
coverage:
	cargo llvm-cov --all-targets --locked --html

deny:
	cargo deny check

build:
	cargo build --locked

# Everything CI runs, in one go.
check: lint lint-ci test msrv deny build
	scripts/test-changelog-section.sh

clean:
	cargo clean
	rm -rf dist lcov.info
