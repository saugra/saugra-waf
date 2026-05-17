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
cargo run -- rules list --config configs/saugra.example.yml
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

## Phase 3.5 — External Rule Packs and CRS-Style Tuning

Saugra should scale beyond hardcoded Rust rules. The community rule engine will
load validated YAML rule packs at startup, compile rule regexes before accepting
traffic, and expose the same rules through `saugra rules list`.

The rule-pack design is inspired by OWASP CRS operational concepts while
remaining native to Saugra instead of copying ModSecurity syntax directly:

- [x] Define Saugra YAML as the product rule format; CRS is an upstream rule
      source that can be converted into Saugra YAML, not a runtime syntax Saugra
      must clone.
- [x] Move the current public rules into CRS-style modular files under
      `configs/rules/`.
- [x] Support multiple configured rule files through `rules.files`.
- [x] Compile and validate all rule regexes at startup.
- [x] Support rule metadata: id, name, category, severity, targets,
      paranoia level, OWASP category, transforms, and explanation.
- [x] Add an initial `saugra rules convert-crs` command for supported CRS
      `@rx` rules.
- [ ] Support monitor-first rollout with CRS-style detection and blocking
      paranoia levels.
- [x] Add anomaly scoring thresholds so multiple lower-severity findings can
      combine into a block decision instead of relying only on first-match
      blocking.
- [x] Add local tuning controls: disable rules by ID, disable categories, and
      exclude specific rules by path, parameter, header, and rule ID.
- [x] Add rule-pack validation output so operators can see loaded files, rule
      counts, disabled rules, configured exclusions, and warnings before
      starting traffic.
- [ ] Add rule-pack versioning and unsupported-import reporting to validation
      output.
- [ ] Treat transforms as first-class ordered pipelines with tests for
      URL-decoding, plus-to-space handling, lowercasing, and future CRS
      transform equivalents.
- [ ] Expand CRS conversion coverage for chains, operators such as
      `@pmFromFile`, data files, and engine-specific features such as
      libinjection.
- [ ] Add support for CRS-style data files and `@pmFromFile` matchers.
- [ ] Add test fixtures for every imported CRS category, including SQLi, XSS,
      LFI/path traversal, RCE/command injection, scanner detection, protocol
      enforcement, and file upload rules.
- [ ] Document unsupported CRS features clearly so operators understand which
      converted rules are active, skipped, or partially represented.
- [ ] Document the import flow as `OWASP CRS .conf -> saugra rules convert-crs
      -> Saugra YAML rule packs -> Saugra rule engine`.
- [x] Keep bad rule files as clear startup/config errors, not silent weak
      protection.

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

## Phase 4 — WebSocket and Upgrade-Aware Proxying

Saugra currently protects normal HTTP request paths that are routed through the
Saugra reverse proxy. WebSocket locations such as `/ws/` often remain proxied
directly from Nginx to an ASGI server such as Daphne, which means those upgrade
requests are not inspected by Saugra yet.

- [ ] Detect HTTP upgrade requests for WebSocket handshakes.
- [ ] Inspect the initial WebSocket handshake path, query string, headers,
      origin, user-agent, cookies, and client identity before upgrade.
- [ ] Apply existing allow, monitor, block, and rate-limit decisions to the
      handshake request.
- [ ] Preserve required upgrade semantics, including `Upgrade`,
      `Connection`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version`, and
      `Sec-WebSocket-Protocol` headers.
- [ ] Tunnel accepted upgraded connections between client and upstream without
      breaking long-lived WebSocket sessions.
- [ ] Add WebSocket-specific logging fields for upgrade decisions, upstream
      target, close/error outcomes, and request ID correlation.
- [ ] Add configurable origin and host validation guidance for WebSocket
      deployments.
- [ ] Add Nginx and Django Channels/Daphne deployment examples that route
      `/ws/` through Saugra.
- [ ] Add tests for allowed, monitored, blocked, and rate-limited WebSocket
      handshake requests.
- [ ] Document the temporary deployment posture: `/ws/` should be hardened at
      Nginx and the application layer until Saugra supports upgrade tunneling.

## Phase 4.5 — OWASP Top 10 Layered Coverage

Default request rules provide starter signals for every OWASP Top 10:2025
category, but Saugra should not claim that regex inspection alone solves
deployment, supply chain, cryptographic, authentication, design, or operational
risks. The implementation target is layered OWASP coverage:

- request rules for visible payloads
- rate limits and anomaly scoring for abusive behavior
- deployment posture checks for configuration and transport assumptions
- external report ingestion for SBOM, dependency, CI, and integrity evidence
- durable events, explanations, and coverage reporting for operators

Planned work:

- [x] Document the layered OWASP Top 10 strategy.
- [x] Add `saugra owasp coverage` to report active controls and gaps by OWASP
      category.
- [x] Add a `posture` config section for deployment assumptions.
- [x] Add `saugra posture check` for local deterministic checks such as
      expected external scheme, allowed methods, response security headers,
      secure cookies, and upload/body policy.
- [ ] Add normalized local report ingestion for SBOM and dependency scan
      outputs.
- [ ] Show OWASP category coverage in logs, explanations, and the future
      dashboard/log viewer.
- [x] Support future standard mappings, such as `owasp-top-10:2026`, through
      YAML metadata and coverage mappings rather than proxy rewrites.

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
- [ ] WebSocket upgrade support, or clear production documentation that
      WebSocket paths must bypass Saugra and be protected by Nginx and the
      application layer until upgrade-aware proxying is enabled.

## Public Built-In Rules

- `SAUGRA-SQLI-001` — basic SQL injection pattern
- `SAUGRA-XSS-001` — basic cross-site scripting pattern
- `SAUGRA-PATH-001` — path traversal pattern
- `SAUGRA-CMD-001` — command injection pattern
- `SAUGRA-BOT-001` — suspicious scanner user agent
- `SAUGRA-AUTH-001` — credential stuffing tool user agent
- `SAUGRA-AUTH-002` — credential exposure in URL
- `SAUGRA-DESIGN-001` — dangerous method override header
- `SAUGRA-CT-001` — suspicious content type
- `SAUGRA-CRYPTO-001` — insecure forwarded protocol
- `SAUGRA-BODY-001` — suspicious body script pattern
- `SAUGRA-SC-001` — package install script injection
- `SAUGRA-INTEGRITY-001` — unsafe serialized object marker
- `SAUGRA-LOG-001` — log injection sequence
- `SAUGRA-EXC-001` — exceptional parser stress sequence
- `SAUGRA-RATE-001` — per-client request rate limit
