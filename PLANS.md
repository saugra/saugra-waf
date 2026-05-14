# PLANS.md — Saugra WAF Implementation Plan

## Product Vision

Saugra is a lightweight Rust-based, AI-assisted WAF for modern web apps and APIs. It should be easy to deploy, easy to configure, compatible with Nginx and Apache, and useful for protecting common stacks such as Django, Laravel, and Express.

The implementation should prioritize a reliable demo-ready MVP before advanced features.

## Current Progress

Current phase: **Phase 2 — Reverse Proxy Core**

Phase 1 foundation has been started and the repo now contains a working Rust
single-crate application. The project can parse configuration, validate the
example YAML file, list built-in WAF rules, run unit tests for the first attack
detections, and start a minimal HTTP service with a health endpoint.

### Completed So Far

- [x] Created Rust package files: `Cargo.toml` and `Cargo.lock`.
- [x] Added CLI entrypoint in `src/main.rs`.
- [x] Added YAML config schema and validation in `src/config.rs`.
- [x] Added example config at `configs/saugra.example.yml`.
- [x] Added WAF action and decision model in `src/decision.rs`.
- [x] Added built-in rule metadata and regex inspection in `src/rules.rs`.
- [x] Added deterministic AI-style explanation helper in `src/ai.rs`.
- [x] Added structured logging initialization in `src/logging.rs`.
- [x] Added minimal Axum service in `src/proxy.rs`.
- [x] Implemented `saugra test-config`.
- [x] Implemented `saugra rules list`.
- [x] Implemented `saugra init`, `saugra init nginx`, and `saugra init apache` output.
- [x] Added initial tests for config validation and attack rule detection.
- [x] Updated `README.md` with quick-start commands.

### Verified Commands

```bash
cargo fmt --check
cargo test
cargo run -- test-config --config configs/saugra.example.yml
cargo run -- rules list
```

Current test status:

```txt
6 passed; 0 failed
```

### Current Built-In Rules

- `SAUGRA-SQLI-001` — basic SQL injection pattern
- `SAUGRA-XSS-001` — basic cross-site scripting pattern
- `SAUGRA-PATH-001` — path traversal pattern
- `SAUGRA-CMD-001` — command injection pattern
- `SAUGRA-BOT-001` — suspicious scanner user agent
- `SAUGRA-CT-001` — suspicious content type
- `SAUGRA-BODY-001` — suspicious body script pattern

### Next Immediate Work

- [ ] Replace the placeholder root route with a catch-all proxy route.
- [ ] Accept all HTTP methods and paths.
- [ ] Normalize request path, query, headers, user-agent, and body.
- [ ] Run built-in rules before forwarding traffic.
- [ ] Log a structured security event when rules match.
- [ ] In `monitor` mode, allow suspicious traffic after logging.
- [ ] In `block` mode, return a safe block response.
- [ ] Forward allowed traffic to the configured upstream.
- [ ] Add tests for monitor and block behavior.

## MVP Scope

The first version should include:

1. Rust reverse proxy
2. YAML configuration
3. Built-in attack detection rules
4. Monitor and block modes
5. Nginx integration
6. Apache integration
7. JSON security logs
8. Basic rate limiting
9. CLI commands
10. AI-style explanation module
11. Docker/demo deployment examples

## Phase 1 — Project Foundation

### Goals

- Create the Rust project structure.
- Add config loading.
- Add CLI foundation.
- Add basic logging.

### Tasks

- [x] Initialize Rust workspace or single-crate app.
- [x] Add dependencies: `tokio`, `axum`/`hyper`, `tower`, `serde`, `serde_yaml`, `clap`, `tracing`, `regex`.
- [x] Create config schema.
- [x] Implement `saugra test-config`.
- [x] Implement basic `saugra run` command.
- [x] Add sample `saugra.example.yml`.

### Output

A binary that can load config, validate it, and start a basic HTTP service.

Status: **complete enough to move into Phase 2**.

## Phase 2 — Reverse Proxy Core

### Goals

- Accept incoming HTTP requests.
- Forward safe requests to the configured upstream.
- Preserve important proxy headers.

### Tasks

- [ ] Implement reverse proxy request forwarding.
- [ ] Support host-based upstream selection.
- [ ] Support path-based routing later if time allows.
- [ ] Preserve `Host`, `X-Real-IP`, `X-Forwarded-For`, and `X-Forwarded-Proto`.
- [ ] Add upstream error handling.
- [ ] Add request IDs.

### Output

Saugra can sit between Nginx/Apache and a backend app.

## Phase 3 — Rule Engine

### Goals

- Inspect requests before forwarding.
- Detect common web attacks.
- Produce allow, monitor, or block decisions.

### MVP Rules

- SQL injection
- XSS
- Path traversal
- Command injection
- Suspicious user agents
- Scanner patterns
- Suspicious file extensions
- Oversized request body

### Tasks

- [x] Define `Rule`, `RuleMatch`, `WafDecision`, and `WafAction` models.
- [x] Implement regex-based rule matching.
- [ ] Inspect path, query string, headers, and body in live proxy requests.
- [x] Add severity scoring.
- [x] Add OWASP category mapping.
- [x] Add built-in rules.
- [ ] Add unit tests for each rule category.

### Output

Saugra can detect and classify common attack payloads.

## Phase 4 — Security Modes

### Goals

Support safe deployment and tuning.

### Modes

- `off`: forward without inspection
- `monitor`: log suspicious traffic but allow it
- `block`: block malicious traffic
- `strict`: future aggressive mode

### Tasks

- Implement mode handling.
- Ensure monitor mode never blocks.
- Ensure block mode returns a clear HTTP response.
- Add clear logs for all matched rules.

### Output

Users can safely test Saugra before enforcing protection.

## Phase 5 — Logging and Explanation

### Goals

- Produce structured security events.
- Make blocked requests understandable.

### Tasks

- Emit JSON logs for security events.
- Include timestamp, request ID, client IP, method, path, rule ID, severity, action, risk score, category, and explanation.
- Mask sensitive fields.
- Implement `saugra explain <request-id>` using stored logs.
- Add explain-only AI-style summaries.

### Output

Users can understand why traffic was blocked or flagged.

## Phase 6 — Rate Limiting and Bot Defense

### Goals

Add practical abuse protection.

### Tasks

- Implement in-memory per-IP rate limiting.
- Add per-route limits.
- Add login route protection.
- Add temporary IP blocking.
- Add suspicious user-agent detection.

### Output

Saugra can reduce brute-force and noisy bot traffic.

## Phase 7 — Proxy Integrations

### Goals

Make Saugra easy to use with common infrastructure.

### Tasks

- Add `saugra init nginx` to generate Nginx config.
- Add `saugra init apache` to generate Apache config.
- Add docs for Django + Gunicorn + Nginx + Saugra.
- Add docs for Laravel + Apache + Saugra.
- Add docs for Express + Nginx + Saugra.

### Output

Users can copy working deployment examples.

## Phase 8 — Dashboard or Log Viewer

### Goals

Provide a simple visibility layer for the capstone demo.

### MVP Options

Option A: simple web dashboard.

- total requests
- blocked requests
- recent events
- top paths
- top IPs
- rule categories

Option B: CLI log viewer.

- `saugra logs tail`
- `saugra logs summary`
- `saugra explain <request-id>`

### Recommendation

Start with CLI log viewer. Add a minimal dashboard only after the engine works.

## Phase 9 — Demo Applications

### Goals

Show Saugra protecting real stacks.

### Required Demo Setups

1. Django + Gunicorn + Nginx + Saugra
2. Laravel + Apache + Saugra
3. Node.js/Express + Nginx + Saugra

### Demo Attack Commands

```bash
curl "http://example.com/search?q=' OR 1=1--"
curl "http://example.com/comment?text=<script>alert(1)</script>"
curl "http://example.com/download?file=../../../../etc/passwd"
for i in {1..20}; do curl -s http://example.com/login; done
```

## Phase 10 — Packaging

### Goals

Make Saugra easy to run.

### Tasks

- Add Dockerfile.
- Add Docker Compose example.
- Add systemd service example.
- Add release build instructions.
- Add README quick start.

## Future Roadmap

### Version 0.2

- Better OWASP Top 10 mapping
- Rule exclusion UI/config
- OpenAPI schema import
- GraphQL query inspection
- IP reputation integration

### Version 0.3

- CRS-style rule import
- Plugin system
- Multi-site support
- Slack/email/webhook alerts
- Persistent PostgreSQL storage

### Version 1.0

- Production-ready rule engine
- Stable rule format
- Kubernetes support
- Helm chart
- Enterprise reporting
- Hosted dashboard option

## Capstone Success Criteria

The project is successful if it can:

- Run as a reverse proxy.
- Protect a sample backend app.
- Detect and block SQLi, XSS, path traversal, and command injection.
- Run behind Nginx.
- Run behind Apache.
- Log blocked requests in JSON.
- Explain why a request was blocked.
- Support monitor and block modes.
- Use a simple YAML configuration file.
