#!/usr/bin/env bash
set -euo pipefail

echo "==> Running Saugra WAF test suite..."
cargo test --workspace --all-targets --all-features
