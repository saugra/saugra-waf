# Security Model

Saugra is a defense-in-depth control placed between a public reverse proxy and
an application. It reduces exposure to common malicious requests and abuse,
but it cannot correct vulnerabilities in application authorization, business
logic, dependencies, operating systems, or deployment practices.

## Rules First

Blocking decisions come from deterministic controls:

- Request inspection rules
- Rate limits
- Behavior thresholds
- Bot and scanner scores
- Explicit runtime policy
- Operator configuration

AI may explain a stored decision or assist with tuning. It must not be the sole
reason traffic is blocked.

## Monitor Before Block

New deployments should use monitor mode until they have observed representative
traffic. This provides evidence for tuning without interrupting application
requests. Every monitor or block decision should produce a structured,
queryable security event.

## Sensitive Data

Do not log full sensitive request bodies by default. Authorization headers,
cookies, passwords, tokens, session identifiers, and similar values must be
masked or excluded from retained events and troubleshooting material.

## Client Identity

Rate limiting, behavior scoring, runtime policy, and investigation depend on
accurate client IP information. Trust forwarded headers only from explicitly
configured reverse proxies. Keep Saugra's listening address private so clients
cannot bypass the public proxy path.

## Durable State

Production controls must retain the state required for their promises:

- Use Redis-backed rate limiting for restart-safe or multi-instance limits.
- Store security events in bounded persistent storage.
- Protect runtime policy files from unauthorized modification.
- Verify retention, rotation, and cleanup behavior.

## Operational Responsibility

Operators remain responsible for:

- Testing normal and malicious traffic before enforcement
- Reviewing false positives and exclusions
- Monitoring event storage and Redis health
- Applying Saugra and operating system updates
- Protecting configuration files and credentials
- Maintaining application-level security controls

See the [OWASP Top 10 strategy](../OWASP_TOP_10_STRATEGY.md) for the layered
coverage model and the [production deployment guide](../PRODUCTION_DEPLOYMENT.md)
for concrete hardening steps.
