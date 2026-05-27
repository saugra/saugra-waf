# PRODUCT SPEC: Saugra WAF

## Project Name

**Saugra WAF**

**Meaning:** Derived from the Lithuanian root *Sauga*, meaning security/protection.

## Project Summary

Saugra WAF is a lightweight, rule-based + AI-assisted Web Application Firewall designed to protect web applications and APIs from common security threats, including OWASP Top 10 risks. It is built to be easy to deploy behind common reverse proxies such as Nginx and Apache, while also being capable of running as a standalone reverse proxy.

The goal is not to replace traditional WAF rules with AI, but to combine proven rule-based protection, behavioral scoring, rate limiting, and AI-assisted explanations to help developers and small teams secure their applications with less configuration complexity.

The product goal is production-ready, not throwaway. Features should be built
once as stable foundations that can be improved over time. Local-only backends
are acceptable only when they sit behind stable abstractions and production
backends are available in the documented deployment path.

## Problem Statement

Many small teams, startups, and developers need web application protection but face challenges with existing WAF solutions:

- Cloud WAFs can be expensive or vendor-locked.
- Traditional WAFs can be hard to configure.
- False positives are difficult to understand and tune.
- Open-source WAF tooling can feel complex for beginners.
- API-first applications need modern JSON, REST, and GraphQL-aware protection.

Saugra WAF addresses this by offering a developer-friendly, self-hosted, Rust-powered WAF with simple configuration and AI-assisted observability.

## Positioning Against Established WAFs

Mature WAF platforms are powerful and widely deployed, but many teams find them
expensive, complex to configure, difficult to tune, or hard to explain. Saugra
should be positioned as a developer-friendly, self-hosted alternative for teams
that want rules-first protection, transparent decisions, and a monitor-first
path to production blocking.

Saugra's differentiation is developer experience:

- simpler configuration
- Rust-based single-binary deployment
- explainable decisions
- API-first inspection direction
- monitor-first tuning workflow
- local-first operation with future centralized management options

The product promise should be:

```txt
Modern, developer-friendly, rules-first protection with explainable decisions.
```

Saugra should communicate its scope clearly: it is an additional protection
layer that combines deterministic rules, rate limiting, observability, and
explainable security events. It should be evaluated and tuned in monitor mode
before being used to block production traffic.

## Production-Ready Product Principle

Saugra should avoid implementing the same security feature twice: once for a
prototype and again for production. Implementations must use stable
interfaces and production-oriented data models so they can be improved without
rewriting the feature.

Required principles:

- Rate limiting must support durable or distributed state before a feature is
  marked complete. In-memory counters are only a local-only backend.
- Security events must be retained in durable, queryable storage for audit,
  `logs tail`, and `explain <request-id>` workflows. Local JSONL storage must
  include bounded retention and rotation.
- Block decisions must be deterministic, explainable, configurable, and tested.
- Monitor-first rollout is required for safe adoption, but block mode must be
  production-safe after tuning.
- Any implementation that is intentionally incomplete must be isolated behind a
  stable trait/interface and tracked in the roadmap before it is merged.

## Target Users

- Small SaaS teams
- API-first startups
- DevOps engineers
- Backend developers
- Self-hosted application owners
- Students and security learners
- Organizations that want lightweight protection without full cloud lock-in

## Core Product Promise

Saugra WAF should be:

1. **Secure** — protects against common web threats and OWASP Top 10 risks.
2. **Fast** — built in Rust for high-performance request inspection.
3. **Easy to configure** — uses simple YAML/TOML configuration.
4. **Proxy compatible** — works with Nginx, Apache, and standalone deployments.
5. **Explainable** — shows why requests were blocked and suggests safer tuning.
6. **Developer-friendly** — includes logs, dashboard, CLI tools, and Docker support.

## High-Level Architecture

```txt
Client
  ↓
Nginx / Apache / Direct Traffic
  ↓
Saugra WAF
  ↓
Backend Application
```

Saugra can run in two main modes:

### 1. Behind Existing Proxy

```txt
Client → Nginx/Apache → Saugra WAF → Backend App
```

This mode is useful for teams already using Nginx or Apache.

### 2. Standalone Reverse Proxy

```txt
Client → Saugra WAF → Backend App
```

This mode is useful for simpler deployments, Docker Compose, and development environments.

## Core Product Features

### 1. Rust Reverse Proxy

Saugra should include a lightweight reverse proxy capable of:

- Receiving HTTP/HTTPS requests
- Forwarding requests to upstream backend services
- Inspecting request method, path, headers, query parameters, and body
- Returning allow/block decisions
- Supporting host-based routing
- Supporting path-based routing
- Supporting upstream health checks

Recommended Rust libraries:

- `axum`
- `hyper`
- `tower`
- `tokio`
- `serde`
- `serde_yaml`
- `tracing`

## 2. OWASP Top 10:2025 Protection

Saugra should provide protection signals for common OWASP Top 10:2025-style
risks, while remaining clear that some categories require application,
dependency, deployment, or operational controls outside a WAF:

- Broken access control patterns
- Security misconfiguration exposure
- Software supply chain attack indicators
- Cryptographic misconfiguration hints
- Injection, including SQL injection, XSS, and command injection
- Insecure design and API abuse indicators
- Authentication abuse
- Software or data integrity failure indicators
- Security logging and alerting abuse indicators
- Mishandled exceptional-condition probes

Saugra should include practical detection rules for:

- SQL injection
- XSS
- Path traversal
- Command injection
- Suspicious user agents
- Scanner/bot behavior
- Credential exposure in URLs
- Insecure forwarded protocol headers
- Dangerous method override headers
- Supply-chain install script payloads
- Unsafe serialized object markers
- Log injection markers
- Parser edge-case payloads
- Oversized request bodies
- Suspicious file upload extensions

Saugra should describe OWASP coverage as a layered control model rather than a
claim that request rules alone solve every category:

- request rules for visible payloads
- rate limits and anomaly scoring for abusive behavior
- posture checks for deployment and response hardening
- external report ingestion for supply chain and integrity evidence
- durable events and explanations for audit and tuning workflows

See `docs/OWASP_TOP_10_STRATEGY.md` for the detailed coverage strategy and
implementation phases.

## 3. Rule Engine

The rule engine should be rule-first, not AI-first.

Saugra should support:

- Built-in security rules
- Custom user-defined rules
- Rule IDs
- Rule descriptions
- Rule severity levels
- Rule categories
- Rule enable/disable options
- Per-route exclusions
- Monitor mode
- Block mode

Example rule structure:

```yaml
rules:
  - id: SAUGRA-SQLI-001
    name: Basic SQL Injection Pattern
    category: injection
    severity: high
    target: query
    pattern: "(?i)(union select|or 1=1|drop table)"
    action: block
```

## 4. CRS-Compatible Direction

Saugra should aim to become compatible with OWASP Core Rule Set concepts.

Supported CRS-compatible concepts should include:

- CRS-inspired rule categories
- Paranoia level concept
- Severity score
- Rule exclusions
- Rule IDs
- Detection phases

Future versions may support importing a subset of established rule formats and
community rule sets.

Example configuration:

```yaml
site:
  name: api.example.com
  upstream: http://127.0.0.1:8080

mode: block

rules:
  owasp_crs: true
  paranoia_level: 1
  detection_paranoia_level: 1
  blocking_paranoia_level: 1

exclusions:
  - path: /api/upload
    disable_rules:
      - file_upload_strict
```

## 5. Nginx Compatibility

Saugra should provide simple integration with Nginx.

Example Nginx configuration:

```nginx
location / {
    proxy_pass http://127.0.0.1:8787;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Saugra CLI should support:

```bash
saugra init nginx
saugra test-config
saugra reload
```

Production examples should be maintained in:

- `configs/nginx.production.example.conf`
- `docs/PRODUCTION_DEPLOYMENT.md`

## 6. Apache Compatibility

Saugra should also provide simple Apache reverse-proxy integration.

Example Apache configuration:

```apache
ProxyPass / http://127.0.0.1:8787/
ProxyPassReverse / http://127.0.0.1:8787/
RequestHeader set X-Forwarded-Proto "https"
```

Saugra CLI should support:

```bash
saugra init apache
saugra test-config
saugra reload
```

Production examples should be maintained in:

- `configs/apache.production.example.conf`
- `docs/PRODUCTION_DEPLOYMENT.md`

## 7. Configuration System

Saugra should use a simple configuration file.

Recommended format: YAML.

Example:

```yaml
server:
  listen: 0.0.0.0:8787
  mode: block

upstreams:
  - name: main-api
    host: api.example.com
    target: http://127.0.0.1:8080

security:
  max_body_size: 2mb
  block_suspicious_user_agents: true
  enable_rate_limiting: true

rate_limit:
  requests_per_minute: 120
  burst: 30

behavior:
  enabled: true
  mode: monitor
  backend: local
  state_path: /var/lib/saugra/saugra-behavior-state.json
  score_window: 10m
  decay_window: 30m
  monitor_threshold: 40
  block_threshold: 80
  route_overrides:
    - path: /login
      monitor_threshold: 30
      block_threshold: 60
      score_window: 5m
  category_overrides:
    - category: scanner_behavior
      score_delta: 15
      monitor_threshold: 30
      block_threshold: 70
  probe_path_catalog: builtin
  probe_paths_extra: []

bot_protection:
  enabled: true
  mode: monitor
  backend: local
  state_path: /var/lib/saugra/saugra-bot-state.json
  score_window: 10m
  monitor_threshold: 40
  block_threshold: 80
  temporary_block_duration: 15m
  allowlists:
    user_agents:
      - Googlebot
    ip_ranges: []
  blocklists:
    user_agents: []
    ip_ranges: []
  routes:
    - path: /login
      monitor_threshold: 30
      block_threshold: 60
  scanner_path_catalog: builtin
  scanner_paths_extra: []
  rule:
    id: SAUGRA-BOT-PROTECTION-001
    name: Bot Protection Threshold
    category: bot_protection
    monitor_severity: medium
    block_severity: high
    paranoia_level: 1
    explanation: Bot protection score reached the configured threshold.
    owasp_category: A06:2025-Insecure Design

ai:
  enabled: true
  mode: explain_only

logging:
  format: json
  level: info
  event_log_path: /var/log/saugra/saugra-events.jsonl
  event_log_max_size: 100mb
  event_log_max_files: 30
  timezone: Africa/Nairobi
```

Supported modes:

- `off` — WAF disabled
- `monitor` — log suspicious traffic but do not block
- `block` — actively block malicious traffic

## 8. AI-Assisted Features

AI should assist, not fully control blocking decisions.

Recommended AI features:

- Explain why a request was blocked
- Summarize attack logs
- Suggest possible rule exclusions for false positives
- Classify requests into categories such as SQLi, XSS, bot, scanner, brute force, or unknown
- Provide a risk score explanation

Recommended decision model:

```txt
Final decision = Rules + Rate Limiting + Behavior Score + Optional AI Risk Score
```

AI should not be the only blocking mechanism.

## 9. Rate Limiting and Bot Defense

Saugra should include production-oriented traffic abuse protection:

- Per-IP rate limiting
- Per-route rate limiting
- Login brute-force protection
- Suspicious user-agent detection
- Known scanner pattern detection
- Request burst protection
- Temporary IP blocking
- Allowlist and blocklist support

Example:

```yaml
rate_limit:
  backend: redis
  redis_url: redis://127.0.0.1:6379
  redis_password: null

  default:
    requests_per_minute: 120
    burst: 30

  routes:
    - path: /sensitive-action
      requests_per_minute: 10
      burst: 5
```

Saugra may include `backend: memory` for local development and single-process
testing, but production documentation must recommend `backend: redis` or another
durable/distributed backend. The rate-limiting engine should be abstracted so
memory and Redis implementations share the same policy evaluation path.

Behavior scoring is the abuse layer for repeated suspicious activity over time.
It is separate from per-request rule anomaly scoring: anomaly score answers
"what did this request match?", while behavior score answers "what has this
client been doing recently?" The community implementation should persist local
behavior state for single-node deployments, emit score contributors in security
events, include those contributors in explanations and log summaries, and keep
monitor-first rollout as the default.

Bot protection is the bot-specific traffic abuse layer. It should not use
CAPTCHA. It should rely on deterministic request signals, route-sensitive
thresholds, allowlists, blocklists, temporary blocking, and durable local state
for single-node deployments. Bot outcomes should be explainable in the same
security event and request decision model as WAF rules, rate limiting, and
behavior scoring.

Recommended rollout:

1. Start with `bot_protection.enabled: true` and `mode: monitor`.
2. Review `logs tail`, `logs summary`, and `explain <request-id>` output for
   bot score contributors.
3. Tune trusted crawler, internal IP, and service-account allowlists.
4. Lower thresholds only on sensitive routes such as `/login` after observing
   real traffic.
5. Enable `mode: block` only after monitor-mode events show acceptable false
   positive behavior.

## 10. API Security Features

Because many modern applications are API-first, Saugra should support:

- JSON body inspection
- REST API protection
- Oversized payload blocking
- Suspicious content-type blocking
- Basic JWT validation helper
- GraphQL query depth limit in future versions
- OpenAPI schema import in future versions

API protections:

- Inspect JSON request bodies
- Limit body size
- Detect malicious payloads inside JSON fields
- Apply different rules per route

## 11. Logging and Observability

Saugra should produce structured logs.

Each security event should include:

- Timestamp
- Request ID
- Client IP
- HTTP method
- Path
- Rule ID
- Rule name
- Severity
- Action taken
- Risk score
- OWASP category
- Explanation

Example JSON log:

```json
{
  "timestamp": "2026-05-14T19:00:00Z",
  "request_id": "req_12345",
  "client_ip": "192.168.1.10",
  "method": "GET",
  "path": "/search?q=' OR 1=1",
  "rule_id": "SAUGRA-SQLI-001",
  "severity": "high",
  "action": "blocked",
  "risk_score": 92,
  "category": "sql_injection",
  "explanation": "Query parameter matched a common SQL injection pattern."
}
```

Local event retention:

- Saugra may use local JSONL files for single-node production event retention.
- The event log path must be configurable.
- The active event log must rotate when it reaches a configured maximum size.
- Operators must be able to configure how many rotated files are retained.
- `saugra logs tail` and `saugra explain <request-id>` should read across active
  and rotated event files.

## 12. Developer Dashboard

The dashboard should help users understand what is happening.

Dashboard features:

- Total requests
- Blocked requests
- Allowed requests
- Top attacking IPs
- Most targeted paths
- Recent blocked requests
- Rule triggered
- Risk score
- OWASP category
- Request timeline
- False positive review

Future dashboard features:

- Rule tuning assistant
- Attack trend charts
- Geo/IP intelligence
- Team accounts
- Multi-site management
- Export reports

## 13. CLI Tool

Saugra should include a CLI for setup and management.

Recommended commands:

```bash
saugra init
saugra init nginx
saugra init apache
saugra --version
saugra test-config
saugra run
saugra reload
saugra rules list
saugra rules enable <rule-id>
saugra rules disable <rule-id>
saugra logs tail
saugra explain <request-id> --config /etc/saugra/saugra.yml
```

## 14. Deployment Options

Saugra should be easy to deploy in different environments.

Deployment targets:

- Single binary
- Docker image
- Docker Compose
- Linux systemd service

Future deployment targets:

- Kubernetes sidecar
- Kubernetes ingress integration
- Helm chart
- Cloud marketplace image

Example Docker Compose:

```yaml
services:
  saugra:
    image: saugra/saugra:latest
    ports:
      - "8787:8787"
    volumes:
      - ./saugra.yml:/etc/saugra/saugra.yml
    depends_on:
      - app

  app:
    image: example/backend:latest
    ports:
      - "8080:8080"
```

## 15. Security Modes

Saugra should support multiple operating modes:

### Off Mode

No inspection or blocking. Useful for disabling protection temporarily.

### Monitor Mode

Logs suspicious traffic but does not block. Useful for testing and reducing false positives.

### Block Mode

Actively blocks malicious traffic.

### Strict Mode

Future mode with stronger rules, higher paranoia level, and more aggressive blocking.

## 16. False Positive Management

False positives are a major WAF problem, so Saugra should make tuning easy.

Features:

- Monitor mode before block mode
- Rule exclusions per route
- Rule exclusions per parameter
- Severity-based blocking
- AI explanation for blocked requests
- Suggested safe exclusions
- Temporary allow action

Example:

```yaml
exclusions:
  - path: /api/articles
    params:
      - content
    disable_rules:
      - SAUGRA-XSS-002
```

## 17. Production Product Scope

Recommended production scope:

1. Rust reverse proxy
2. YAML configuration
3. Built-in SQLi, XSS, path traversal, command injection rules
4. Monitor and block modes
5. Nginx integration template
6. Apache integration template
7. JSON security logs
8. Production-safe rate limiting with a durable/distributed backend
9. Simple dashboard
10. AI explanation for blocked requests
11. Docker deployment
12. CLI commands for init, run, reload, and config testing

## 18. Future Roadmap

### Version 0.2

- More complete OWASP Top 10 mapping
- Rule exclusion UI
- Better dashboard charts
- IP reputation integration
- OpenAPI schema import
- GraphQL query inspection

### Version 0.3

- CRS-style rule import
- Plugin system
- Multi-site support
- Team accounts
- Alert notifications
- Slack/email/webhook alerts

### Version 1.0

- Production-ready WAF engine
- Stable rule format
- Kubernetes support
- Helm chart
- Cloud deployment templates
- Advanced reporting

## 19. Differentiation

Saugra should differentiate itself by being:

- Rust-native and fast
- Easy to configure
- AI-assisted but not AI-dependent
- Friendly to developers and students
- Compatible with Nginx and Apache
- Suitable for APIs, not only traditional websites
- Self-hosted by default
- Transparent and explainable

## 20. Success Criteria

The product path is successful if Saugra can:

- Run as a reverse proxy
- Protect a sample backend app
- Detect and block SQLi, XSS, path traversal, and command injection attempts
- Run behind Nginx
- Run behind Apache
- Log blocked requests in JSON
- Show blocked requests in a dashboard
- Explain why a request was blocked
- Support monitor and block modes
- Be configured using a simple YAML file

## 21. Example Verification Scenario

A verification scenario can include:

1. Run a vulnerable backend app in an isolated test environment.
2. Place Saugra WAF in front of it.
3. Send normal requests and show they are allowed.
4. Send SQL injection payloads and show they are blocked.
5. Send XSS payloads and show they are blocked.
6. Show logs in JSON format.
7. Open the dashboard and view blocked attacks.
8. Click a blocked request and show the AI explanation.
9. Switch from monitor mode to block mode.
10. Demonstrate Nginx or Apache proxy compatibility.

## 22. Recommended Tech Stack

### Core Engine

- Rust
- Axum or Hyper
- Tokio
- Tower middleware
- Serde
- Serde YAML
- Regex engine
- Tracing

### Storage

Production baseline:

- SQLite or local JSONL logs for single-node event retention
- Redis for distributed rate limiting

Later:

- PostgreSQL
- ClickHouse for high-volume logs

### Dashboard

Options:

- React / Next.js
- SvelteKit
- Rust-based frontend with Leptos/Yew, if desired

### AI Layer

Production baseline:

- Local explain-only module
- Optional LLM API integration

Later:

- Local ONNX model
- Anomaly detection model
- Privacy-preserving local inference

## 23. Final Recommendation

Saugra should be positioned as:

> **A lightweight rule-based + AI-assisted Web Application Firewall for modern web apps and APIs.**

The strongest product direction is not pure AI blocking. The better and more trustworthy approach is:

```txt
Rules-first protection + rate limiting + behavior scoring + AI explanations
```

This makes Saugra practical, safer, and easier for operators to trust.
