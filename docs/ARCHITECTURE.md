# ARCHITECTURE.md — Saugra WAF Architecture

## Overview

Saugra WAF is a Rust-based reverse-proxy Web Application Firewall. It sits in front of a backend application, inspects HTTP requests, applies security rules and rate limits, logs security events, and either allows, monitors, or blocks traffic.

Saugra is designed to work in two deployment modes:

```txt
Client → Nginx/Apache → Saugra WAF → Backend Application
```

or:

```txt
Client → Saugra WAF → Backend Application
```

The recommended production-style capstone setup is to keep Nginx or Apache as the public web server and run Saugra on a local/private port.

## Design Philosophy

Saugra should be:

- rules-first
- AI-assisted
- explainable
- proxy-compatible
- simple to configure
- fast enough for real web traffic
- safe to test in monitor mode before block mode

The decision model is:

```txt
Final decision = Rules + Rate Limiting + Behavior Score + Optional AI Explanation
```

AI should explain and assist. It should not be the only reason a request is blocked in the MVP.

## Main Components

```txt
┌──────────────────────┐
│ Client               │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Nginx / Apache       │
│ Optional public edge │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Saugra Proxy         │
├──────────────────────┤
│ Config Loader        │
│ Request Normalizer   │
│ Rule Engine          │
│ Rate Limiter         │
│ Decision Engine      │
│ Logger               │
│ AI Explanation Layer │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Backend Application  │
│ Django/Laravel/Node  │
└──────────────────────┘
```

## Request Lifecycle

1. Client sends a request.
2. Nginx or Apache forwards the request to Saugra.
3. Saugra assigns a request ID.
4. Saugra normalizes request metadata.
5. Saugra checks body size and content type.
6. Saugra applies rate limits.
7. Saugra runs built-in and custom rules.
8. Saugra computes a risk score.
9. Saugra creates a decision: allow, monitor, or block.
10. Saugra logs the decision.
11. If allowed or monitored, Saugra forwards the request to the backend.
12. If blocked, Saugra returns a safe block response.

## Core Modules

### 1. Proxy Runtime

Responsible for:

- accepting HTTP requests
- forwarding requests to upstream apps
- preserving proxy headers
- handling upstream errors
- returning block responses

Recommended Rust libraries:

- `tokio`
- `hyper`
- `axum`
- `tower`

### 2. Configuration Loader

Responsible for:

- loading YAML config
- validating required fields
- parsing server mode
- parsing upstreams
- parsing security settings
- parsing rate limits
- parsing rule settings

Example config shape:

```yaml
server:
  listen: 127.0.0.1:8787
  mode: monitor

upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000
```

### 3. Request Normalizer

Responsible for extracting normalized values from each request:

- method
- path
- query string
- headers
- client IP
- content type
- body size
- parsed JSON fields where enabled

Normalization helps rules behave consistently.

### 4. Rule Engine

Responsible for detecting suspicious patterns.

MVP rule targets:

- path
- query
- headers
- body
- JSON fields
- user-agent
- file extension

MVP rule categories:

- SQL injection
- XSS
- path traversal
- command injection
- suspicious bot/scanner
- suspicious upload
- oversized body

Rule output:

```txt
RuleMatch {
  rule_id,
  rule_name,
  category,
  severity,
  matched_target,
  explanation
}
```

### 5. Rate Limiter

Responsible for abuse control.

MVP behavior:

- per-IP limits
- per-route limits
- login route limits
- burst control
- temporary blocking

Initial implementation can use in-memory storage. Redis can be added later for distributed deployments.

### 6. Decision Engine

Responsible for converting rule matches and rate-limit results into a final action.

Actions:

- `allow`
- `monitor`
- `block`

Mode behavior:

| Mode | Behavior |
|---|---|
| off | Forward without inspection |
| monitor | Log suspicious traffic but allow |
| block | Block malicious traffic |
| strict | Future aggressive blocking mode |

### 7. Logging and Observability

Responsible for structured security events.

Each event should include:

- timestamp
- request ID
- client IP
- method
- path
- action
- matched rule IDs
- severity
- risk score
- OWASP category
- explanation

Example:

```json
{
  "request_id": "req_12345",
  "method": "GET",
  "path": "/search?q=' OR 1=1",
  "rule_id": "SAUGRA-SQLI-001",
  "severity": "high",
  "action": "blocked",
  "risk_score": 92,
  "category": "sql_injection"
}
```

### 8. AI Explanation Layer

Responsible for human-friendly explanations.

MVP behavior:

- explain why a request was blocked
- summarize matched rules
- suggest possible tuning direction
- classify event type

The MVP can use deterministic templates instead of a real LLM. This keeps the project simple and privacy-friendly while still demonstrating AI-assisted behavior.

Example:

```txt
This request was blocked because the query parameter matched a SQL injection pattern commonly used to bypass authentication or alter database queries.
```

## Deployment Architecture

### Django + Gunicorn + Nginx + Saugra

```txt
Client → Nginx → Saugra WAF → Gunicorn → Django
```

Recommended ports:

- Nginx: public `80/443`
- Saugra: local `127.0.0.1:8787`
- Gunicorn: local `127.0.0.1:8000`

### Laravel + Apache + Saugra

```txt
Client → Apache → Saugra WAF → Laravel
```

Recommended ports:

- Apache: public `80/443`
- Saugra: local `127.0.0.1:8787`
- Laravel demo server: local `127.0.0.1:8000`

### Node.js/Express + Nginx + Saugra

```txt
Client → Nginx → Saugra WAF → Express
```

Recommended ports:

- Nginx: public `80/443`
- Saugra: local `127.0.0.1:8787`
- Express: local `127.0.0.1:3000`

## Data Storage

### MVP

Use local files or SQLite for:

- security events
- request explanations
- recent blocked requests

### Future

Use:

- PostgreSQL for dashboard and user configuration
- ClickHouse for high-volume logs
- Redis for distributed rate limiting

## Security Considerations

Saugra should avoid unsafe logging and accidental data exposure.

Important requirements:

- mask `Authorization` headers
- mask cookies
- mask password fields
- avoid full body logging by default
- bind Saugra to `127.0.0.1` when behind Nginx/Apache
- keep backend apps on local/private ports
- start new sites in monitor mode
- require explicit config for block mode

## Configuration Architecture

Configuration should support global settings plus per-route overrides.

Example:

```yaml
server:
  listen: 127.0.0.1:8787
  mode: block

security:
  max_body_size: 2mb
  inspect_json_body: true

rate_limit:
  default:
    requests_per_minute: 120
    burst: 30
  routes:
    - path: /login
      requests_per_minute: 10
      burst: 5

exclusions:
  - path: /api/articles
    params:
      - content
    disable_rules:
      - SAUGRA-XSS-002
```

## Rule Architecture

A built-in rule should have:

- stable ID
- name
- category
- severity
- target
- pattern or matcher
- action
- explanation
- OWASP mapping where possible

Example:

```yaml
id: SAUGRA-SQLI-001
name: Basic SQL Injection Pattern
category: sql_injection
severity: high
target: query
pattern: "(?i)(union select|or 1=1|drop table)"
action: block
```

## API and Dashboard Architecture

For the capstone, the dashboard can be simple.

Possible endpoints:

```txt
GET /_saugra/health
GET /_saugra/events
GET /_saugra/events/:request_id
GET /_saugra/summary
POST /_saugra/explain/:request_id
```

Dashboard cards:

- total requests
- blocked requests
- monitored requests
- top attacking IPs
- top targeted paths
- top rule categories
- recent blocked requests

## Future Architecture

Future versions can add:

- CRS-style rule importer
- plugin system
- OpenAPI schema-aware validation
- GraphQL inspection
- Kubernetes sidecar deployment
- Helm chart
- cloud-hosted dashboard
- distributed rate limiting with Redis
- high-volume analytics with ClickHouse

## Architecture Success Criteria

The architecture is successful if:

- the proxy layer is separate from the WAF decision engine
- rules are testable without running the proxy
- config is easy to validate
- logs are structured and explainable
- deployment works with Nginx and Apache
- normal traffic passes through safely
- attack traffic is blocked or monitored according to mode
