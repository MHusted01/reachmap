COVERAGE_MIN := 80

.PHONY: fmt lint test coverage deny build check clean

fmt:
	cargo fmt --all

lint:
	cargo fmt --all --check
	cargo clippy --all-targets --all-features --locked -- -D warnings

# Unit and integration tests with a line coverage gate (cargo-llvm-cov).
test:
	cargo llvm-cov --all-targets --locked --fail-under-lines $(COVERAGE_MIN)

# HTML coverage report in target/llvm-cov/html for local browsing.
coverage:
	cargo llvm-cov --all-targets --locked --html

deny:
	cargo deny check

build:
	cargo build --locked

# Everything CI runs, in one go.
check: lint test deny build
	scripts/test-changelog-section.sh

clean:
	cargo clean
	rm -rf dist lcov.info
