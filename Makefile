.PHONY: all build test coverage check fmt clean install help

all: build test

build:
	cargo build --locked

test:
	cargo test --locked --workspace --all-targets --all-features

coverage:
	cargo llvm-cov --locked --all-features --workspace --lcov --output-path lcov.info --fail-under-lines 70
	python3 scripts/coverage-summary.py lcov.info

check:
	cargo fmt --check
	cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

fmt:
	cargo fmt

clean:
	cargo clean

install:
	cargo install --locked --path .

help:
	@echo "Available Makefile targets:"
	@echo "  build    - Compile the Saugra WAF binary (using Cargo.lock)"
	@echo "  test     - Run the full Saugra WAF test suite"
	@echo "  check    - Verify code formatting and clippy lints"
	@echo "  fmt      - Format codebase using rustfmt"
	@echo "  install  - Install binary locally via cargo install"
	@echo "  coverage - Generate and summarize test coverage"
	@echo "  clean    - Remove build artifacts"
