#!/usr/bin/env bash
set -euo pipefail

echo "==> Verifying lockfiles..."
test -f Cargo.lock || { echo "ERROR: Cargo.lock missing!"; exit 1; }
test -f package-lock.json || { echo "ERROR: package-lock.json missing!"; exit 1; }

echo "==> Running coverage parser unit test..."
python3 -m unittest tests/test_coverage_summary.py

echo "==> Running Saugra WAF test suite (300+ unit and integration tests)..."
cargo test --locked --workspace --all-targets --all-features

echo "==> Saugra WAF test suite passed successfully!"
