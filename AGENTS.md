# AGENTS.md — Saugra WAF Coding Agent Guide

## Project Context

**Saugra WAF** is a Rust-based, AI-assisted Web Application Firewall for modern web applications and APIs. It should protect against OWASP Top 10-style attacks, work behind Nginx and Apache, and remain easy to configure through simple YAML files.

The product direction is:

```txt
Rules-first protection + rate limiting + behavior scoring + AI explanations
```

AI must assist with explanations and tuning. It must not be the only blocking mechanism in the MVP.

## Primary Goal

Build a working capstone MVP that can:

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
saugra/
├── crates/
│   ├── saugra-core/        # rule engine, request model, decisions
│   ├── saugra-proxy/       # reverse proxy runtime
│   ├── saugra-config/      # YAML config parsing and validation
│   ├── saugra-rules/       # built-in rules
│   ├── saugra-ai/          # explain-only AI assistant layer
│   ├── saugra-cli/         # CLI commands
│   └── saugra-dashboard/   # optional dashboard backend/frontend
├── configs/
│   ├── saugra.example.yml
│   ├── nginx.example.conf
│   └── apache.example.conf
├── examples/
│   ├── django-gunicorn-nginx/
│   ├── laravel-apache/
│   └── express-nginx/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── PLANS.md
│   └── CAPSTONE_SPEC.md
├── tests/
│   ├── integration/
│   └── attacks/
└── README.md
```

For a smaller capstone repository, a simpler structure is acceptable:

```txt
saugra/
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
- `regex` for MVP pattern rules
- `tracing` and `tracing-subscriber` for logs
- `clap` for CLI
- `uuid` for request IDs
- `thiserror` or `anyhow` for error handling

## Coding Principles

- Prefer simple, readable code over clever abstractions.
- Keep the WAF engine separate from proxy transport code.
- Make decisions explainable.
- Never silently block traffic without producing a security event.
- Support `monitor` mode before `block` mode.
- Avoid panics in request-handling paths.
- Treat config parsing errors as clear user-facing errors.
- Write tests for rules, config validation, and attack detection.

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

## MVP Rule Categories

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

rules:
  owasp_crs: true
  paranoia_level: 1

ai:
  enabled: true
  mode: explain_only

logging:
  format: json
  level: info
```

## CLI Requirements

Implement these commands first:

```bash
saugra init
saugra init nginx
saugra init apache
saugra test-config
saugra run
saugra rules list
saugra logs tail
saugra explain <request-id>
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

Example attack test cases:

```txt
/search?q=' OR 1=1--
/comment?text=<script>alert(1)</script>
/download?file=../../../../etc/passwd
/api?cmd=cat /etc/passwd
```

## Documentation Requirements

Keep documentation practical and demo-friendly:

- README quick start
- CAPSTONE_SPEC.md product specification
- ARCHITECTURE.md technical architecture
- PLANS.md implementation plan
- deployment examples
- demo commands

## Definition of Done for MVP

The MVP is done when a user can:

1. Start a demo backend app.
2. Start Saugra with a YAML config.
3. Place Nginx or Apache in front of Saugra.
4. Send normal traffic successfully.
5. Send attack payloads and see them blocked or logged.
6. View structured JSON logs.
7. Run `saugra explain <request-id>`.
