# Saugra WAF Code Coverage & Module Breadth Summary

[![CI](https://github.com/saugra/saugra-waf/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/saugra/saugra-waf/actions/workflows/ci.yml?query=branch%3Amain)
[![codecov](https://codecov.io/github/saugra/saugra-waf/graph/badge.svg)](https://codecov.io/github/saugra/saugra-waf)

**Total Line Coverage**: `85.67%` (11371/13273 lines hit)

## Per-Module Line Coverage

| Module / Subsystem | Lines Hit | Coverage |
| :--- | :--- | :--- |
| `src/ai` | `1031/1197` | `86.13%` |
| `src/behavior` | `532/546` | `97.44%` |
| `src/bot` | `677/701` | `96.58%` |
| `src/campaign` | `548/675` | `81.19%` |
| `src/cli` | `427/579` | `73.75%` |
| `src/config` | `1422/1671` | `85.10%` |
| `src/console` | `892/1168` | `76.37%` |
| `src/crs_convert` | `389/457` | `85.12%` |
| `src/decision.rs` | `282/283` | `99.65%` |
| `src/event_store` | `469/484` | `96.90%` |
| `src/logging.rs` | `38/71` | `53.52%` |
| `src/main.rs` | `3/3` | `100.00%` |
| `src/owasp.rs` | `287/305` | `94.10%` |
| `src/posture.rs` | `240/282` | `85.11%` |
| `src/proxy` | `1354/1567` | `86.41%` |
| `src/rate_limit.rs` | `129/150` | `86.00%` |
| `src/redis_connection.rs` | `45/45` | `100.00%` |
| `src/reports.rs` | `135/154` | `87.66%` |
| `src/rule_drafts.rs` | `146/148` | `98.65%` |
| `src/rules` | `678/717` | `94.56%` |
| `src/runtime_policy` | `322/361` | `89.20%` |
| `src/security_summary` | `432/508` | `85.04%` |
| `src/standards.rs` | `50/63` | `79.37%` |
| `src/storage_cleanup.rs` | `191/198` | `96.46%` |
| `src/unknown_threats` | `566/648` | `87.35%` |
| `vendor` | `86/292` | `29.45%` |
| **TOTAL** | `11371/13273` | **`85.67%`** |

## Module Test Breadth & Dedicated Test File Mapping

| Module / Component | Primary Source Path | Dedicated Test Suite File(s) | Test Type |
| :--- | :--- | :--- | :--- |
| `rules` | `src/rules/` | Dedicated unit tests (`src/rules/*.rs`) + `tests/test_proxy_e2e.rs` | Unit & E2E Integration |
| `unknown_threats` | `src/unknown_threats/` | Dedicated unit tests (`src/unknown_threats/*.rs`) + `tests/test_proxy_e2e.rs` | Unit & E2E Integration |
| `ai` | `src/ai/` | Dedicated unit tests (`src/ai/*.rs`) + `tests/test_cli.rs` | Unit & CLI Integration |
| `proxy` | `src/proxy/` | Dedicated integration suite (`tests/test_proxy_e2e.rs`) | E2E Proxy Tunneling |
| `cli` | `src/cli/` | Dedicated integration suite (`tests/test_cli.rs`) | CLI Integration |
| `console` | `src/console/` | Dedicated integration suites (`tests/test_console_integration.rs`, `tests/test_console_live_http.rs`) | Console API & Heartbeat Integration |
| `rate_limit` | `src/rate_limit.rs` | Dedicated suite (`tests/test_rate_limit_redis.rs`) + unit tests | Live Redis & In-Memory Rate Limiting |

> *Note*: Coverage is generated automatically during CI runs using `cargo llvm-cov` and recorded in `lcov.info`.
