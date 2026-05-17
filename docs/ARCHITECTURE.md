# ARCHITECTURE.md — Saugra WAF Architecture

## Overview

Saugra WAF is a rule-based + AI-assisted reverse-proxy Web Application Firewall. It sits in front of a backend application, inspects HTTP requests, applies security rules and rate limits, logs security events, and either allows, monitors, or blocks traffic.

Saugra is designed to work in two deployment modes:

```txt
Client → Nginx/Apache → Saugra WAF → Backend Application
```

or:

```txt
Client → Saugra WAF → Backend Application
```

The recommended production setup is to keep Nginx or Apache as the public web server and run Saugra on a local/private port.

Production deployment examples live in:

- `configs/nginx.production.example.conf`
- `configs/apache.production.example.conf`
- `docs/PRODUCTION_DEPLOYMENT.md`

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

AI should explain and assist. It should not be the only reason a request is blocked.

OWASP Top 10 coverage should be modeled as layered controls, not only request
regex rules. Request rules handle visible payloads, rate limits handle abuse
over time, posture checks validate deployment assumptions, external report
ingestion captures supply chain evidence, and durable logs provide audit and
tuning evidence. The detailed strategy lives in
`docs/OWASP_TOP_10_STRATEGY.md`.

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

Rule targets:

- path
- query
- headers
- body
- JSON fields
- user-agent
- file extension

Rule categories:

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

Rate-limiting behavior:

- per-IP limits
- per-route limits
- login route limits
- burst control
- temporary blocking

In-memory storage is only for local development. Production deployments should use Redis or another durable/distributed backend.

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
  "timestamp": "2026-05-14T19:00:00Z",
  "request_id": "req_12345",
  "client_ip": "192.168.1.10",
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

Explanation behavior:

- explain why a request was blocked
- summarize matched rules
- suggest possible tuning direction
- classify event type

Saugra may use deterministic templates, an LLM integration, or both. Blocking remains deterministic and based on rules, rate limits, and explicit configuration.

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
- Laravel app server: local `127.0.0.1:8000`

### Node.js/Express + Nginx + Saugra

```txt
Client → Nginx → Saugra WAF → Express
```

Recommended ports:

- Nginx: public `80/443`
- Saugra: local `127.0.0.1:8787`
- Express: local `127.0.0.1:3000`

## Data Storage

### Production Baseline

Use queryable local or external storage for:

- security events
- request explanations
- recent blocked requests

### Scale-Out Options

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
    - path: /sensitive-action
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
metadata:
  name: saugra-application-attack-sqli
  version: 0.1.0
  standards:
    - owasp-top-10:2025

rules:
  - id: SAUGRA-SQLI-001
    name: Basic SQL Injection Pattern
    category: sql_injection
    severity: high
    paranoia_level: 1
    targets:
      - query
    transforms:
      - url_decode
      - plus_to_space
    pattern: "(?i)(union\\s+select|or\\s+1\\s*=\\s*1|drop\\s+table)"
    explanation: Query data matched a common SQL injection pattern.
    owasp_category: A05:2025-Injection
```

Native rule packs are split into CRS-style files such as
`REQUEST-941-APPLICATION-ATTACK-XSS.yml` and
`REQUEST-942-APPLICATION-ATTACK-SQLI.yml`. Operators can also import supported
OWASP CRS regex rules with:

```bash
saugra rules convert-crs --input /path/to/coreruleset/rules --output /etc/saugra/rules/converted-crs.yml
```

The converter is intentionally conservative: unsupported CRS operators and
engine-specific features are skipped until Saugra has equivalent execution
support.

Saugra YAML is the product rule format. OWASP CRS is treated as an upstream
source of maintained detection knowledge that can be converted into Saugra's
native format; Saugra does not aim to become a ModSecurity syntax clone. The
intended flow is:

```txt
OWASP CRS .conf files
  -> saugra rules convert-crs
  -> Saugra YAML rule packs
  -> Saugra rule engine
```

Rule-pack metadata declares the standard release a file maps to, for example
`owasp-top-10:2025`. Future OWASP releases, such as a later `owasp-top-10:2026`
mapping, should be shipped as new or updated YAML rule packs and enabled through
`rules.files`; the proxy and decision model do not need a rewrite for a new
standard label.

In `block` mode, Saugra uses inbound anomaly scoring. Each matched rule adds
points based on severity: low = 2, medium = 3, high = 5, critical = 5. Requests
are blocked when the accumulated score reaches `rules.inbound_anomaly_threshold`.
`monitor` mode still records findings without blocking, and `strict` mode blocks
on any matched rule.

Rule exclusions are applied before anomaly scoring. They are intended for
false-positive tuning and can be scoped by rule ID, category, path prefix, query
parameter, and header:

```yaml
rules:
  exclusions:
    - name: Allow article HTML previews
      rule_ids:
        - SAUGRA-XSS-001
      path_prefixes:
        - /api/articles
      query_params:
        - content
```

Next rule-engine milestones:

- Add rule-pack versioning and validation output that lists loaded files, rule
  counts, skipped imports, disabled rules, and warnings.
- Treat transforms as first-class ordered pipelines with dedicated tests.
- Add CRS-style data files and `@pmFromFile` matcher support.
- Add fixtures for every imported CRS category before marking that category
  production-supported.
- Keep unsupported CRS features explicitly documented.

## API and Dashboard Architecture

The dashboard should provide practical operational visibility.

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

## Local Event Retention

For single-node deployments, Saugra stores security events in local JSONL files.
The active event log path, maximum file size, and number of retained rotated
files are configurable. When the active log would exceed the configured size,
Saugra rotates it to `.1`, shifts older rotated files upward, and removes files
older than the configured retention count.

`saugra logs tail` and `saugra explain <request-id>` read across the active and
rotated event files so recent audit and explanation workflows continue after
rotation.

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
