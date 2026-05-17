# OWASP Top 10 Strategy

Saugra should avoid claiming that request regex rules alone can fully solve the
OWASP Top 10. Some OWASP categories are directly visible in HTTP requests, while
others depend on application design, deployment posture, dependency hygiene, or
operational monitoring.

The product claim should be:

```txt
Saugra provides OWASP Top 10:2025 mapped protection through request inspection,
rate limiting, deployment posture checks, durable security events, and optional
external security report ingestion.
```

This keeps Saugra honest while giving operators a clear path from basic WAF
signals to broader application security coverage.

## Layered Model

### 1. Request Rules

Request rules detect attack patterns in HTTP traffic:

- injection payloads
- path traversal
- command injection
- cross-site scripting
- unsafe serialized object markers
- log injection markers
- parser edge-case probes
- suspicious headers, methods, content types, and user agents

Rules are the right layer for categories where an attacker's payload is visible
in the request.

### 2. Policy Checks

Policy checks validate deployment and application-facing security posture:

- expected external scheme is HTTPS
- secure cookie attributes are present where observable
- security headers are present on upstream responses
- allowed methods are explicit
- upload size and extension policies are configured
- upstream hosts and forwarded headers match expectations

Policy checks are the right layer for security misconfiguration, cryptographic
failures, and design assumptions that cannot be reliably solved by matching a
single malicious string.

### 3. Behavior Controls

Behavior controls detect repeated or abusive activity over time:

- global and per-route rate limits
- login and sensitive-route limits
- scanner behavior
- brute-force and credential stuffing signals
- anomaly scoring across multiple low or medium findings

Behavior controls are the right layer for abuse patterns where one request may
look harmless but repeated traffic is suspicious.

### 4. External Report Ingestion

External reports let Saugra reflect risks that are not visible at the proxy:

- SBOM files
- dependency scan reports
- CI security reports
- secrets scanning output
- container image scan output

This is the right layer for software supply chain and integrity risks that need
build-time or deployment-time evidence.

### 5. Evidence And Guidance

Every finding should produce operator-friendly evidence:

- structured security events
- `logs tail` output
- `explain <request-id>`
- future dashboard views
- future `owasp coverage` output

The goal is not just blocking. The goal is to show what Saugra observed, which
OWASP category it maps to, and what tuning or hardening action is appropriate.

## Target CLI Surface

CLI commands should make coverage explicit:

```bash
saugra posture check
saugra owasp coverage
```

`saugra posture check` should validate configured deployment assumptions before
traffic starts or during an operator audit.

`saugra owasp coverage` summarizes how each OWASP category is addressed:

```txt
A01 Broken Access Control: request rules + path policy
A02 Security Misconfiguration: header/content-type/posture checks
A03 Software Supply Chain Failures: SBOM/dependency report integration
A04 Cryptographic Failures: HTTPS/header/cookie posture checks
A05 Injection: request rules
A06 Insecure Design: method policy + rate limits + route policy
A07 Authentication Failures: login route rate limits + credential leakage rules
A08 Integrity Failures: deserialization/prototype pollution rules + CI artifact checks
A09 Logging and Alerting Failures: durable event store + log injection rules
A10 Exceptional Conditions: parser stress rules + body/timeout limits
```

## Proposed Configuration

Posture checks should be configured explicitly so operators understand what
Saugra is validating:

```yaml
posture:
  enabled: true
  expected_external_scheme: https
  require_secure_cookies: true
  require_security_headers: true
  allowed_methods:
    - GET
    - POST
    - PUT
    - PATCH
    - DELETE
  dependency_report_path: ./security/sbom.json
```

The first implementation should keep this local and deterministic. External
integrations can come later once the local report model is stable.

## OWASP Top 10:2025 Coverage Plan

| Category | Saugra Coverage Direction |
|---|---|
| A01 Broken Access Control | Path traversal rules, path policy checks, suspicious direct-object access patterns where observable |
| A02 Security Misconfiguration | Suspicious content types, response security header posture checks, forwarded header validation |
| A03 Software Supply Chain Failures | Supply-chain payload rules, SBOM/dependency report ingestion |
| A04 Cryptographic Failures | HTTPS expectation checks, forwarded protocol validation, secure cookie and HSTS checks |
| A05 Injection | SQLi, XSS, command injection, and future CRS-derived injection rules |
| A06 Insecure Design | Method override rules, allowed method policy, route-specific rate limits, sensitive action controls |
| A07 Authentication Failures | Login brute-force limits, credential stuffing signals, credential leakage rules |
| A08 Software or Data Integrity Failures | Unsafe deserialization and prototype pollution rules, CI artifact integrity report ingestion |
| A09 Security Logging and Alerting Failures | Durable event storage, log injection rules, coverage/audit commands |
| A10 Mishandling of Exceptional Conditions | Parser edge-case rules, body limits, timeout and upstream error observability |

## Implementation Phases

1. Add `saugra owasp coverage`. Done.
   This should report current coverage from loaded rule metadata, rate limiting,
   event storage, and documented planned posture checks.

2. Add a `posture` config section and `saugra posture check`. Initial local
   checks done.
   Start with deterministic local checks: expected scheme, allowed methods,
   security headers, secure cookies, and upload/body policy.

3. Add report ingestion. Initial local ingestion done.
   Start with local files such as SBOM or dependency scan reports. Normalize them
   into Saugra findings mapped to OWASP categories.

4. Add dashboard/log viewer coverage views.
   Operators should see coverage gaps, active controls, and recent events by
   OWASP category.

5. Add upgradeable standard mappings.
   Future OWASP releases, such as `owasp-top-10:2026`, should be shipped as YAML
   metadata and coverage mappings rather than requiring proxy changes.

Saugra stores the active standard catalog in `configs/standards/`. The default
configuration points at `configs/standards/owasp-top-10-2025.yml`, while
production installs should copy the same catalog to `/etc/saugra/standards/`.
When a future OWASP release is adopted, operators should be able to install a new
catalog file and update `standards.owasp_catalog` without changing Rust code.
