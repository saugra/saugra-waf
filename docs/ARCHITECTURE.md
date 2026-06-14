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
- `docs/ADMIN_GUIDE.md`

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
tuning evidence. The [security model](#security-model) defines that strategy.

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

### 5.5. Behavior Engine

Responsible for repeated-abuse scoring before the final proxy decision.

Behavior configuration is monitor-first and separate from per-request rule
anomaly scoring:

- global score window and decay window
- monitor and block thresholds
- per-route threshold and window overrides
- per-category score and threshold overrides
- configured probe paths for repeated enumeration and scanner-path behavior
- local durable state for single-node deployments
- memory state for local development and tests

Behavior scoring adds contributors for repeated suspicious activity from the
same client, including scanner paths, development/internal endpoint probes,
authentication abuse categories, and repeated low-severity rule matches. The
behavior result is stored on the request decision and written to security
events with score, thresholds, window, storage backend, and contributors.

Behavior score is not the same as rule anomaly score. Rule anomaly score is
computed from matches on the current request. Behavior score is accumulated over
a configured window for the client and can move repeated low-confidence signals
from allow to monitor, or from monitor to block when `behavior.mode: block` is
explicitly enabled.

Production note: `behavior.backend: local` persists state on disk and survives a
single Saugra process restart. Multi-instance deployments should treat this as a
single-node backend until a distributed backend is added.

### 5.6. Bot Protection

Responsible for deterministic bot and automation abuse controls without CAPTCHA.

Bot protection uses the same monitor-first posture as the behavior engine, but
tracks bot-specific policy and state:

- allowlists for trusted crawler user agents, internal IP ranges, and service
  accounts
- blocklists for high-risk clients and user-agent patterns
- deterministic signals such as missing user agents, automation user agents,
  configured scanner path probes, and suspicious forwarded headers
- route-specific monitor and block thresholds
- temporary blocking with persisted local state for single-node deployments
- configurable synthetic rule metadata for the bot-protection threshold event

Bot protection writes its outcome into the WAF decision so `logs tail`,
`logs summary`, and `explain <request-id>` can show the score, contributors,
thresholds, storage backend, allowlist/blocklist status, and temporary block
duration. CAPTCHA remains out of scope; Saugra should block or monitor based on
observable request and behavior evidence, not interactive challenges.

### 5.7. Runtime Policy

Responsible for local no-restart operational policy such as emergency IP/CIDR
allowlisting.

The first runtime policy target is a file-backed allow/block policy stored at
`/var/lib/saugra-waf/runtime-policy.json`. Saugra should reload this file while
running and apply active entries before final decision enforcement. Runtime
allowlist effects can bypass bot/behavior blocking, downgrade all findings to
monitor, or allow all traffic for a matching client. Runtime blocklist entries
force a deterministic block.

Runtime policy changes must be observable. Security events and
`explain <request-id>` should show when an allowlist entry affected the
decision. Operational use is documented in `docs/ADMIN_GUIDE.md`.

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

Saugra uses a provider-neutral asynchronous interface with loopback llama.cpp
and Qwen3 0.6B as the lightweight default, local Ollama as an alternative,
native OpenAI-compatible and Gemini HTTPS providers, a deterministic local
fallback, and an optional command-based adapter.
Before a model or adapter runs, Saugra builds a minimized input containing route
shapes, query parameter names, rule
metadata, scores, baseline signals, behavior history, and campaign counts. Raw
query values, request bodies, cookies, authorization values, client addresses,
and upstream credentials are excluded.

Provider output is advisory. Tuning suggestions are restricted to narrow,
reviewable configuration changes and are never applied automatically. Each
invocation is written to a JSONL audit trail with model, prompt version, input
digest, output, latency, fallback status, and failure state. Blocking remains
deterministic and based on rules, rate limits, scoring, and explicit
configuration.

All event fields are treated as untrusted data rather than model instructions.
Provider explanations must preserve the deterministic action and relevant rule,
behavior, unknown-threat, and campaign identifiers. Model-written score or
threshold narration is rejected because Saugra renders those values
deterministically. Missing evidence, malformed structured output, timeout, or
grounding failure activates the deterministic local fallback.

Remote providers are disabled unless `allow_remote: true` and
`local_only: false`. Their endpoint must use HTTPS and match
`endpoint_allowlist`; credentials are read through `api_key_env`, not YAML.
Operators must document `data_region` and `retention_policy` before validation
succeeds.

Versioned provider-neutral sanitized cases run through `saugra-waf ai
evaluate`. The report includes the sanitized explanation and suggestion kinds,
and tracks schema/provider failures, forbidden privacy fields, prompt-injection
resistance, grounding checks, suggestion scope, required and forbidden quality
phrases, and latency.
`saugra-waf ai anomaly-shadow` applies the same sanitized explanation path to
retained unknown-threat events for offline operator review. The report cannot
alter decisions and declares deterministic policy as the only enforcement
authority.

Generated rule drafts use a separate reviewed lifecycle: `rules draft`,
`rules replay --fixtures`, `rules approve`, then `rules publish`. Draft
manifests bind source anomaly IDs, generator metadata, input and replay digests,
reviewer, approval time, and publication state. Publishing requires monitor
mode and never edits configured active rule files automatically.

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
  name: saugra-waf-application-attack-sqli
  version: 0.1.0
  standards:
    - owasp-top-10:2025

rules:
  - id: SAUGRA-SQLI-001
    name: Basic SQL Injection Pattern
    category: sql_injection
    severity: high
    performance_cost: low
    paranoia_level: 1
    targets:
      - query
    transforms:
      - url_decode
      - plus_to_space
    pattern: "(?i)(union\\s+select|or\\s+1\\s*=\\s*1|drop\\s+table)"
    design_intent: Detect common SQL injection markers with bounded normalization.
    explanation: Query data matched a common SQL injection pattern.
    owasp_category: A05:2025-Injection
```

`performance_cost` is optional and accepts `low`, `moderate`, or `high`.
`design_intent` is optional operator-facing documentation. Active metadata can
be inspected with `saugra-waf rules view <saugra-rule-id>`; omitted optional
fields are reported as `not specified` rather than inferred by the runtime.

Native rule packs are split into CRS-style files such as
`REQUEST-941-APPLICATION-ATTACK-XSS.yml` and
`REQUEST-942-APPLICATION-ATTACK-SQLI.yml`. Operators can also import supported
OWASP CRS regex rules with:

```bash
saugra-waf rules convert-crs --input /path/to/coreruleset/rules --output /etc/saugra-waf/rules/converted-crs.yml
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
  -> saugra-waf rules convert-crs
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

For monitor-first CRS-style tuning, Saugra can load and log rules up to
`rules.detection_paranoia_level` while allowing only matches at or below
`rules.blocking_paranoia_level` to contribute to blocking decisions. The legacy
`rules.paranoia_level` remains the default for both values when the split levels
are not configured.

Rule exclusions are applied before anomaly scoring. They are intended for
false-positive tuning and can be scoped by rule ID, category, path prefix,
query parameter, header name, HTTP method, matched target, content type, trusted
header value, and authenticated identity assertion:

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
      methods:
        - POST
      targets:
        - query
      content_types:
        - application/json
      identities:
        - name: X-Authenticated-Role
          values:
            - editor
```

Value and identity conditions are ignored unless the direct peer matches
`forwarded_headers.trusted_proxies`. Identity headers must additionally appear
in `forwarded_headers.identity_assertions`. A front proxy must remove
client-supplied copies before writing an assertion. Sensitive credential
headers cannot be configured as assertions.

Security events retain privacy-safe request evidence: normalized content type,
body size, query parameter names, and header names. Request bodies and trusted
header values are not retained. This supports method, target, content-type,
parameter-name, and header-name replay while making trusted-value replay an
explicitly reported limitation.

Rule-pack validation reports metadata such as pack name, version, standards,
active rule counts, filtered rules, and unsupported CRS imports. Converted CRS
packs can carry `unsupported_imports` entries so operators can see which rules
were skipped and why during `saugra-waf test-config`.

Rule transforms are ordered pipelines. Saugra applies each transform exactly in
the order listed in YAML before evaluating the regex. Supported native
transforms are `url_decode`, `plus_to_space`, and `lowercase`; CRS conversion
currently maps `t:urlDecode`, `t:urlDecodeUni`, and `t:lowercase`, honors
`t:none`, and reports unsupported transform actions as skipped imports.

The CRS import workflow and unsupported feature list are documented in
the [Rule Packs And CRS Import](#rule-packs-and-crs-import) section.

Next rule-engine milestones:

- Add CRS-style data files and `@pmFromFile` matcher support.
- Add fixtures for every imported CRS category before marking that category
  production-supported.
- Keep unsupported CRS features explicitly documented.

### Rule Packs And CRS Import

Saugra runs native YAML rule packs. The CRS converter is an offline migration
tool, not a ModSecurity compatibility layer:

```bash
saugra-waf rules convert-crs \
  --input /path/to/coreruleset/rules \
  --output /etc/saugra-waf/rules/converted-crs.yml
saugra-waf test-config
```

Supported CRS input includes `SecRule` with `@rx` or `@pmFromFile`, mapped
request targets, severity and paranoia tags, and ordered `t:none`,
`t:urlDecode`, `t:urlDecodeUni`, and `t:lowercase` transforms. Unsupported
operators, chained rules, complex selectors, collection updates, phase side
effects, and unknown transforms are reported as `unsupported_imports`.
Converted packs must be reviewed and deployed in monitor mode first.

## Security Model

Saugra is a defense-in-depth control, not a replacement for application
authorization, dependency management, operating-system hardening, or security
testing.

Blocking is deterministic: request rules, rate limits, behavior and bot
thresholds, unknown-threat policy gates, runtime policy, and explicit operator
configuration. AI can explain retained evidence and propose tuning, but cannot
be the sole reason for blocking or activate generated rules.

OWASP Top 10:2025 coverage is layered:

| Layer | Coverage |
| --- | --- |
| Request rules | Injection, traversal, XSS, command execution, suspicious protocol and parser inputs |
| Policy checks | HTTPS, methods, headers, uploads, and forwarded-header assumptions |
| Behavior controls | Scanning, brute force, credential abuse, and distributed campaigns |
| External reports | SBOM, dependency, container, and CI security findings |
| Evidence | Durable events, summaries, explanations, posture, and coverage commands |

This mapping describes Saugra controls; it is not proof that a protected
application is compliant. Sensitive bodies, credentials, cookies, tokens, and
authorization values must be masked or excluded. Forwarded identity is trusted
only from configured proxies, and production state must be durable and bounded.

## API and Dashboard Architecture

The dashboard should provide practical operational visibility.

Possible endpoints:

```txt
GET /_saugra-waf/health
GET /_saugra-waf/events
GET /_saugra-waf/events/:request_id
GET /_saugra-waf/summary
POST /_saugra-waf/explain/:request_id
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

`saugra-waf logs tail` and `saugra-waf explain <request-id>` read across the active and
rotated event files so recent audit and explanation workflows continue after
rotation.

A request ID is available only while its event remains in those files.
Retention is based on bytes and file count rather than event age. The shipped
settings of `100mb` and `10` retain up to one active file and ten rotated files,
or approximately 1.1 GB. They do not guarantee a fixed number of days.

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
