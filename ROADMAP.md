# Saugra Public Roadmap

This roadmap tracks public community-edition development for Saugra. The MVP is
intended to become production-usable for real web applications, not just a demo.

Saugra is developed with an open-core direction: this public repository focuses
on the self-hosted WAF engine, reverse proxy, rules, local logs, CLI, local
visibility, deployment examples, and basic explain-only AI summaries. Future
Saugra Pro and cloud capabilities may include centralized management,
organization-level controls, external integrations, and reporting. Commercial
planning and private implementation details are tracked outside this public
repository.

## Current Status

Current phase: **Phase 3 — Production-Ready Proxy Verification + Abuse Controls**

The repository has a working Rust foundation:

- CLI scaffold
- YAML config loading and validation
- Built-in WAF rule metadata
- Regex-based attack inspection helpers
- WAF decision model
- Basic AI-style explanation helper
- Structured logging setup
- Catch-all reverse proxy service
- Local JSONL security event store
- Initial in-memory rate limiter for local/demo use
- Example config at `configs/saugra.example.yml`

## Verified Commands

```bash
cargo fmt --check
cargo test
cargo run -- test-config --config configs/saugra.example.yml
cargo run -- rules list
```

Current test status:

```txt
22 passed; 0 failed
```

## Production-Ready MVP Principle

Saugra should avoid throwaway implementations for security-critical features.
Each MVP feature should be built as a production-oriented foundation that can be
improved without rewriting call sites or changing the operator workflow.

Required implications:

- Rate limiting must use a stable storage abstraction and support a
  production-safe backend such as Redis before it is considered MVP-complete.
  In-memory rate limiting is only a local/demo backend.
- Security events must be written to durable, queryable storage suitable for
  `logs tail`, `explain <request-id>`, and basic audit workflows.
- Monitor-first rollout remains the default recommendation, but block mode must
  be deterministic, observable, tested, and safe for production use after tuning.
- Features should be marked done only when they are usable in the documented
  deployment path without being replaced later.

## Community Edition Scope

The public edition should remain useful by itself:

- Reverse proxy runtime
- Request inspection
- Built-in OWASP-style rules
- Monitor and block modes
- Structured JSON security logs
- Local CLI tools
- Local dashboard or log viewer
- Nginx and Apache integration examples
- Docker/demo deployment examples
- Basic explain-only AI summaries

## Open-Core Boundary

The public edition should provide real security value without requiring a paid
or hosted service. Saugra Pro and cloud features should extend Saugra for larger
teams and organizations, not replace the community WAF core.

Public development should prioritize:

- Reliable local protection
- Transparent rule-based decisions
- Clear monitor and block behavior
- Safe structured logs
- Practical deployment examples
- Explainable findings

Future Saugra Pro/cloud work may focus on:

- Centralized dashboards
- Multi-node management
- Team access controls
- External identity integrations
- Alerting and security tool integrations
- Organization-level reporting

## Next Public Development Work

- [x] Replace the placeholder root route with a catch-all proxy route.
- [x] Accept all HTTP methods and paths.
- [x] Normalize request path, query, headers, user-agent, and body.
- [x] Run built-in rules before forwarding traffic.
- [x] Log a structured security event when rules match.
- [x] In `monitor` mode, allow suspicious traffic after logging.
- [x] In `block` mode, return a safe block response.
- [x] Forward allowed traffic to the configured upstream.
- [x] Add tests for monitor and block behavior.

## Phase 3 — Production-Ready Proxy Verification + Abuse Controls

- [x] Add JSON decision output shape tests.
- [x] Add initial in-memory per-client rate limiting for local/demo use.
- [x] Introduce a `RateLimitStore` abstraction.
- [x] Add Redis-backed distributed rate limiting for production use.
- [x] Support configurable per-route limits with burst settings.
- [x] Treat in-memory rate limiting as `backend: memory` for local/demo only.
- [x] Add a Redis-backed production config example.
- [x] Return safe `429` JSON responses for blocked rate-limit abuse.
- [x] Add proxy handler tests for rule blocking and rate-limit blocking.
- [x] Add local JSONL request-decision storage.
- [x] Add `logs tail` and `explain <request-id>` CLI groundwork.
- [x] Validate JSONL event storage as durable enough for single-node production.
- [x] Add configurable external/durable event storage path and retention policy.
- [x] Add forwarding tests with a fake upstream transport.
- [x] Add structured JSON security event shape tests.
- [ ] Add safer end-to-end demo scripts for local proxy smoke tests.

## Production Readiness Gate

Before Saugra is recommended for production use, complete:

- [x] Redis-backed distributed rate limiting.
- [x] Rate-limit store abstraction with memory and Redis backends.
- [x] Configurable per-route and global rate-limit policies.
- [x] Durable security event retention with documented rotation.
- [x] Nginx and Apache production deployment examples.
- [x] End-to-end tests for forwarding, monitor mode, block mode, rate limiting,
      event persistence, and `explain <request-id>`.
- [x] Safe defaults documented for first production rollout.
- [x] Source install and systemd service documented.

## Public Built-In Rules

- `SAUGRA-SQLI-001` — basic SQL injection pattern
- `SAUGRA-XSS-001` — basic cross-site scripting pattern
- `SAUGRA-PATH-001` — path traversal pattern
- `SAUGRA-CMD-001` — command injection pattern
- `SAUGRA-BOT-001` — suspicious scanner user agent
- `SAUGRA-CT-001` — suspicious content type
- `SAUGRA-BODY-001` — suspicious body script pattern
- `SAUGRA-RATE-001` — per-client request rate limit
