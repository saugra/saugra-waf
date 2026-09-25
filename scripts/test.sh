#!/usr/bin/env bash
set -euo pipefail

echo "==> Running Saugra WAF test suite..."
cargo test --locked --workspace --all-targets --all-features
