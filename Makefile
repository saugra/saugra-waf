.PHONY: all build test coverage check fmt clean install

all: build test

build:
	cargo build

test:
	cargo test --workspace --all-targets --all-features

coverage:
	cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info --fail-under-lines 70
	python3 scripts/coverage-summary.py lcov.info

check:
	cargo fmt --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings

fmt:
	cargo fmt

clean:
	cargo clean

install:
	cargo install --path .
