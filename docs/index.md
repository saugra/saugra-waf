# Saugra WAF Documentation

Saugra is a lightweight, self-hosted Web Application Firewall for modern web
applications and APIs. It combines deterministic request rules, rate limiting,
behavior and bot scoring, durable security events, and explainable decisions.

```txt
Client -> Nginx or Apache -> Saugra WAF -> Backend application
```

Saugra is an additional security layer. It does not replace secure application
development, authentication, authorization, dependency management, or host
hardening.

## Start Here

<div class="grid cards" markdown>

-   **Install Saugra**

    ---

    Install from the signed APT repository, a release package, or source.

    [Installation](getting-started/installation.md)

-   **Protect an application**

    ---

    Configure an upstream, start in monitor mode, and verify request forwarding.

    [Quick start](getting-started/quick-start.md)

-   **Deploy to production**

    ---

    Put Nginx or Apache in front of Saugra and use Redis-backed rate limiting.

    [Production deployment](PRODUCTION_DEPLOYMENT.md)

-   **Operate Saugra**

    ---

    Inspect logs, explain decisions, tune false positives, and handle incidents.

    [Administration guide](ADMIN_GUIDE.md)

</div>

## How Saugra Makes Decisions

Every inspected request receives an `allow`, `monitor`, or `block` decision.
The decision can include matched rules, severity, risk score, OWASP mapping,
behavior signals, and an explanation. Blocking remains deterministic and
configuration-driven; AI is limited to explanation and tuning assistance.

New production deployments should begin in `monitor` mode. Review normal
traffic and security events before enabling blocking.

## Documentation Paths

| Goal | Documentation |
| --- | --- |
| Install and test Saugra | [Getting started](getting-started/installation.md) |
| Understand every major YAML section | [Configuration reference](reference/configuration.md) |
| Find a command | [CLI reference](reference/cli.md) |
| Run and troubleshoot a server | [Administration guide](ADMIN_GUIDE.md) |
| Review OWASP coverage | [OWASP Top 10 strategy](OWASP_TOP_10_STRATEGY.md) |

## Current Scope

The current production-oriented foundation includes HTTP and WebSocket
proxying, route-based upstream selection, external YAML rule packs, monitor and
block modes, Redis-backed rate limiting, behavior and bot scoring, structured
JSONL security events, runtime policy controls, and operator CLI workflows.

For release status and planned work, see the
[public roadmap](https://github.com/saugra/saugra-waf/blob/main/ROADMAP.md).
