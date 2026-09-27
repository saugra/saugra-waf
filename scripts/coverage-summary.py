#!/usr/bin/env python3
import sys
import os
import collections

def parse_lcov(lcov_file):
    """Parses an lcov.info file and returns module coverage stats and overall totals."""
    if not os.path.exists(lcov_file):
        raise FileNotFoundError(f"{lcov_file} not found.")

    file_coverage = collections.defaultdict(lambda: [0, 0])
    current_file = None

    with open(lcov_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('SF:'):
                current_file = line[3:]
            elif line.startswith('DA:'):
                if current_file:
                    parts = line[3:].split(',')
                    hits = int(parts[1])
                    file_coverage[current_file][1] += 1
                    if hits > 0:
                        file_coverage[current_file][0] += 1

    modules = collections.defaultdict(lambda: [0, 0])
    total_hits = 0
    total_lines = 0

    for filepath, (hits, lines) in file_coverage.items():
        total_hits += hits
        total_lines += lines

        relpath = os.path.relpath(filepath)
        parts = relpath.split(os.sep)
        if len(parts) > 1 and parts[0] == 'src':
            mod = f"src/{parts[1]}"
        elif len(parts) > 0:
            mod = parts[0]
        else:
            mod = 'root'
        modules[mod][0] += hits
        modules[mod][1] += lines

    overall_pct = (100.0 * total_hits / total_lines) if total_lines > 0 else 0.0
    return modules, total_hits, total_lines, overall_pct

def print_text_summary(modules, total_hits, total_lines, overall_pct):
    print("==========================================================")
    print("                SAUGRA WAF COVERAGE SUMMARY               ")
    print("==========================================================")
    print(f"{'Module / Path':<35} | {'Lines Hit':<10} | {'Coverage':<8}")
    print("----------------------------------------------------------")

    for mod, (hits, lines) in sorted(modules.items()):
        pct = (100.0 * hits / lines) if lines > 0 else 0.0
        print(f"{mod:<35} | {hits}/{lines:<8} | {pct:>6.2f}%")

    print("----------------------------------------------------------")
    print(f"{'TOTAL LINE COVERAGE':<35} | {total_hits}/{total_lines:<8} | {overall_pct:>6.2f}%")
    print("==========================================================")

def print_markdown_summary(modules, total_hits, total_lines, overall_pct):
    print("# Saugra WAF Code Coverage & Module Breadth Summary")
    print()
    print("[![CI](https://github.com/saugra/saugra-waf/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/saugra/saugra-waf/actions/workflows/ci.yml?query=branch%3Amain)")
    print("[![codecov](https://codecov.io/github/saugra/saugra-waf/graph/badge.svg)](https://codecov.io/github/saugra/saugra-waf)")
    print()
    print(f"**Total Line Coverage**: `{overall_pct:.2f}%` ({total_hits}/{total_lines} lines hit)")
    print()
    print("## Per-Module Line Coverage")
    print()
    print("| Module / Subsystem | Lines Hit | Coverage |")
    print("| :--- | :--- | :--- |")
    for mod, (hits, lines) in sorted(modules.items()):
        pct = (100.0 * hits / lines) if lines > 0 else 0.0
        print(f"| `{mod}` | `{hits}/{lines}` | `{pct:.2f}%` |")
    print(f"| **TOTAL** | `{total_hits}/{total_lines}` | **`{overall_pct:.2f}%`** |")
    print()
    print("## Module Test Breadth & Dedicated Test File Mapping")
    print()
    print("| Module / Component | Primary Source Path | Dedicated Test Suite File(s) | Test Type |")
    print("| :--- | :--- | :--- | :--- |")
    print("| `rules` | `src/rules/` | Dedicated unit tests (`src/rules/*.rs`) + `tests/test_proxy_e2e.rs` | Unit & E2E Integration |")
    print("| `unknown_threats` | `src/unknown_threats/` | Dedicated unit tests (`src/unknown_threats/*.rs`) + `tests/test_proxy_e2e.rs` | Unit & E2E Integration |")
    print("| `ai` | `src/ai/` | Dedicated unit tests (`src/ai/*.rs`) + `tests/test_cli.rs` | Unit & CLI Integration |")
    print("| `proxy` | `src/proxy/` | Dedicated integration suite (`tests/test_proxy_e2e.rs`) | E2E Proxy Tunneling |")
    print("| `cli` | `src/cli/` | Dedicated integration suite (`tests/test_cli.rs`) | CLI Integration |")
    print("| `console` | `src/console/` | Dedicated integration suites (`tests/test_console_integration.rs`, `tests/test_console_live_http.rs`) | Console API & Heartbeat Integration |")
    print("| `rate_limit` | `src/rate_limit.rs` | Dedicated suite (`tests/test_rate_limit_redis.rs`) + unit tests | Live Redis & In-Memory Rate Limiting |")
    print()
    print("> *Note*: Coverage is generated automatically during CI runs using `cargo llvm-cov` and recorded in `lcov.info`.")

def main():
    args = sys.argv[1:]
    markdown_mode = '--markdown' in args
    filtered_args = [a for a in args if a != '--markdown']
    lcov_file = filtered_args[0] if filtered_args else 'lcov.info'

    try:
        modules, total_hits, total_lines, overall_pct = parse_lcov(lcov_file)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if markdown_mode:
        print_markdown_summary(modules, total_hits, total_lines, overall_pct)
    else:
        print_text_summary(modules, total_hits, total_lines, overall_pct)

if __name__ == '__main__':
    main()

