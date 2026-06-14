# AGENTS.md — Saugra WAF Coding Agent Guide

## Project Context

**Saugra WAF** is a rule-based + AI-assisted Web Application Firewall for modern web applications and APIs. It should protect against OWASP Top 10-style attacks, work behind Nginx and Apache, and remain easy to configure through simple YAML files.

The product direction is:

```txt
Rules-first protection + rate limiting + behavior scoring + AI explanations
```

AI must assist with explanations and tuning. It must not be the only blocking mechanism.

## Production-Ready Product Rule

Saugra is a production-oriented security product. Agents must avoid throwaway
implementations for security-critical features. Build each feature once as a
production foundation, then improve it incrementally. Do not implement a
temporary version that must be replaced later unless it is clearly isolated
behind a stable interface and the follow-up work is tracked immediately.

Security features must be designed for real deployment from the start:

- Rate limiting must support a durable or distributed backend for production
  deployments. In-memory rate limiting is acceptable only as a local-only backend
  behind a stable storage abstraction, not as the production endpoint.
- Request logs and explanations must be retained in a queryable local store or
  explicitly configured external store. Do not rely only on stdout for production
  workflows.
- Blocking behavior must be deterministic, configurable, observable, and tested.
- Any feature marked done must be usable in the documented production path
  without a rewrite.
- Default guidance should be monitor-first for safe rollout, then block mode
  after tuning.

## Primary Goal

Build and maintain a production WAF that can:

1. Run as a reverse proxy.
2. Inspect HTTP requests.
3. Detect common attacks.
4. Block or monitor suspicious requests.
5. Forward safe traffic to backend apps.
6. Produce structured JSON logs.
7. Integrate with Nginx and Apache.
8. Provide a simple dashboard or log viewer.
9. Explain why a request was blocked.

## Recommended Repository Structure

```txt
saugra-waf/
├── crates/
│   ├── saugra-waf-core/        # rule engine, request model, decisions
│   ├── saugra-waf-proxy/       # reverse proxy runtime
│   ├── saugra-waf-config/      # YAML config parsing and validation
│   ├── saugra-waf-rules/       # built-in rules
│   ├── saugra-waf-ai/          # explain-only AI assistant layer
│   ├── saugra-waf-cli/         # CLI commands
│   └── saugra-waf-dashboard/   # optional dashboard backend/frontend
├── configs/
│   ├── saugra-waf.example.yml
│   ├── nginx.example.conf
│   └── apache.example.conf
├── examples/
│   ├── django-gunicorn-nginx/
│   ├── laravel-apache/
│   └── express-nginx/
├── docs/
│   ├── ADMIN_GUIDE.md
│   ├── ARCHITECTURE.md
│   └── RELEASE_PROCESS.md
├── ROADMAP.md
├── tests/
│   ├── integration/
│   └── attacks/
└── README.md
```

For a single-crate production repository, this structure is acceptable while the
module boundaries remain clear:

```txt
saugra-waf/
├── src/
│   ├── main.rs
│   ├── config.rs
│   ├── proxy.rs
│   ├── rules.rs
│   ├── rate_limit.rs
│   ├── logging.rs
│   └── ai.rs
├── examples/
├── configs/
├── docs/
└── README.md
```

## Rust Stack

Use these libraries unless there is a strong reason not to:

- `tokio` for async runtime
- `axum` or `hyper` for HTTP server/proxy behavior
- `tower` for middleware layering
- `serde` and `serde_yaml` for config parsing
- `regex` for pattern rules
- `tracing` and `tracing-subscriber` for logs
- `clap` for CLI
- `uuid` for request IDs
- `thiserror` or `anyhow` for error handling

## Coding Principles

- Prefer simple, readable code over clever abstractions.
- Keep the WAF engine separate from proxy transport code.
- Make decisions explainable.
- Avoid hard-coding security rules, OWASP/category mappings, posture mappings,
  thresholds, risky method lists, operator-facing policy choices, or other
  configurable security behavior in Rust code. Put them in rule packs, standard
  catalogs, YAML config, or documented data files, then load and validate them
  through stable interfaces. Rust defaults may point to bundled config/catalog
  files, but the behavior itself should remain data-driven and upgradeable
  without code changes.
- Prefer stable interfaces around storage, rate limiting, logging, and proxy
  transport so implementations can improve without rewriting call sites.
- Never silently block traffic without producing a security event.
- Support `monitor` mode before `block` mode.
- Avoid panics in request-handling paths.
- Treat config parsing errors as clear user-facing errors.
- Write tests for rules, config validation, attack detection, monitor/block
  behavior, rate limiting, and production deployment assumptions.

## Security Principles

Saugra must not give users a false sense of security. It should be described as an additional protection layer, not a replacement for secure application development.

Important rules:

- Do not depend only on AI for blocking.
- Do not log sensitive full request bodies by default.
- Mask secrets such as passwords, tokens, cookies, and authorization headers.
- Preserve client IP headers carefully.
- Support allowlists and blocklists.
- Default new deployments to `monitor` mode where appropriate.
- Provide clear false-positive tuning options.
- Do not mark a security feature production-ready if it resets state on process
  restart, cannot work across multiple Saugra instances, or cannot be observed
  and tuned from logs.

## Rule Categories

Implement built-in rules for:

- SQL injection
- Cross-site scripting
- Path traversal
- Command injection
- Suspicious user agents
- Scanner/bot behavior
- Oversized request bodies
- Suspicious file upload extensions
- Suspicious content types
- Login brute-force/rate-limit abuse

Each rule should include:

```yaml
id: SAUGRA-SQLI-001
name: Basic SQL Injection Pattern
category: sql_injection
severity: high
target: query
action: block
```

## Request Decision Model

Every inspected request should produce a decision:

```rust
enum WafAction {
    Allow,
    Monitor,
    Block,
}
```

Decision fields should include:

- request ID
- action
- matched rules
- severity
- risk score
- explanation
- OWASP category if applicable

## Configuration Requirements

Support YAML configuration similar to:

```yaml
server:
  listen: 127.0.0.1:8787
  mode: monitor

upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000

security:
  max_body_size: 2mb
  enable_rate_limiting: true
  block_suspicious_user_agents: true
  inspect_json_body: true

rate_limit:
  backend: redis
  redis_url: redis://127.0.0.1:6379
  requests_per_minute: 120
  burst: 30
  routes:
    - path: /sensitive-action
      requests_per_minute: 10
      burst: 5

rules:
  owasp_crs: true
  paranoia_level: 1

ai:
  enabled: true
  mode: explain_only

logging:
  format: json
  level: info
  event_log_path: /var/log/saugra-waf/saugra-waf-events.jsonl
  event_log_max_size: 100mb
  event_log_max_files: 30
  timezone: Africa/Nairobi
```

## CLI Requirements

Implement these commands first:

```bash
saugra-waf init
saugra-waf init nginx
saugra-waf init apache
saugra-waf test-config
saugra-waf run
saugra-waf rules list
saugra-waf logs tail
saugra-waf explain <request-id>
```

## Integration Examples Required

Maintain examples for:

1. Django + Gunicorn + Nginx + Saugra
2. Laravel + Apache + Saugra
3. Node.js/Express + Nginx + Saugra

Each example should include:

- request flow
- app startup command
- Saugra YAML config
- Nginx or Apache config
- test curl commands

## Testing Requirements

Add tests for:

- config parsing
- invalid config errors
- SQLi detection
- XSS detection
- path traversal detection
- command injection detection
- monitor mode behavior
- block mode behavior
- rate limiting
- JSON log output shape
- behavior scoring, durable behavior state, and threshold decisions when those
  features are touched

Example attack test cases:

```txt
/search?q=' OR 1=1--
/comment?text=<script>alert(1)</script>
/download?file=../../../../etc/passwd
/api?cmd=cat /etc/passwd
```

## SDLC Coverage Requirements

Saugra's SDLC loop should include Codecov-backed test coverage for pull
requests and release branches.

Coverage expectations:

- Run the normal Rust test suite before coverage collection.
- Generate coverage with a Rust-compatible tool such as `cargo llvm-cov` or
  `cargo tarpaulin`, then upload the report to Codecov from CI.
- Treat coverage as a regression signal, not a vanity metric. Do not add weak
  tests only to increase percentages.
- Preserve or improve coverage for security-critical code paths, especially
  request inspection, rule matching, monitor/block decisions, rate limiting,
  behavior scoring, event storage, explanation output, config validation, and
  proxy forwarding.
- Pull requests that lower coverage on security-critical modules should add
  focused tests or clearly document why the uncovered code is acceptable.
- Coverage checks should complement, not replace, attack-case tests,
  integration/e2e tests, and production deployment verification commands.

## Documentation Requirements

Keep documentation practical and production-focused:

- `README.md` is the primary documentation entry point and quick start.
- `docs/ADMIN_GUIDE.md` owns installation, configuration, deployment,
  operations, AI providers, and troubleshooting.
- `docs/ARCHITECTURE.md` owns technical design, security model, rule formats,
  and developer-facing implementation concepts.
- `docs/RELEASE_PROCESS.md` owns packaging, APT repository, signing, and release
  procedures.
- `ROADMAP.md` owns planned and completed product work.
- Deployment examples should stay beside their configuration or example code.

Documentation constraints:

- Update an existing canonical document instead of creating a new `.md` file.
- Create a new Markdown file only when the content has a distinct audience,
  lifecycle, or legal/community purpose that does not fit an existing owner.
- Before creating a document, search the repository for an existing section
  covering the topic and extend or reorganize it.
- Do not create one-document-per-feature notes, temporary implementation plans,
  duplicate quick starts, or separate guides for each provider or platform.
- Keep one source of truth for each command, configuration field, installation
  flow, and operational procedure. Link to it instead of copying it.
- When replacing documentation, merge any still-useful content, delete the
  superseded file, and repair all links in the same change.
- Keep `docs/index.md` as a short website pointer to `README.md` and the
  canonical guides; do not duplicate the README there.

## Production Readiness Definition

The product path is production-ready when a user can:

1. Start a backend app.
2. Start Saugra with a YAML config.
3. Place Nginx or Apache in front of Saugra.
4. Send normal traffic successfully.
5. Send attack payloads and see them blocked or logged.
6. View structured JSON logs.
7. Run `saugra-waf explain <request-id>`.
8. Configure production-safe rate limiting with durable or distributed state.
9. Restart Saugra without losing the security events needed for explanation and
   audit workflows.
10. Run the documented deployment path without replacing core security
    implementations.
