# Saugra WAF

[![CI](https://github.com/ewanyonyi/saugra/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ewanyonyi/saugra/actions/workflows/ci.yml?query=branch%3Amain)
[![codecov](https://codecov.io/github/ewanyonyi/saugra/graph/badge.svg?token=P6XZ7GGVJ8)](https://codecov.io/github/ewanyonyi/saugra)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](Cargo.toml)

![Saugra WAF Logo](docs/img/saugra-logo.jpeg)

Saugra is a lightweight, self-hosted Web Application Firewall for developers and
small teams who want OWASP-style protection, rate limiting, behavior scoring,
bot scoring, durable security logs, and explainable decisions without adopting a
large enterprise or cloud WAF platform.

The product direction is:

```txt
Rules-first protection + rate limiting + behavior scoring + bot scoring + AI explanations
```

AI is used for explanations and tuning support. Blocking decisions should come
from deterministic rules, rate limits, and explicit configuration.

## The Problem

Many small teams, startups, and self-hosted application owners need protection
against common web attacks, but existing WAF options can be expensive, complex
to tune, hard to explain, or tightly tied to a cloud provider.

Traditional WAFs are powerful, but teams often struggle with false positives,
opaque blocking decisions, and operational complexity. API-first applications
also need protection that fits modern HTTP, JSON APIs, WebSockets, and
developer-led deployment workflows.

## The Solution

Saugra runs between your public proxy and your backend application:

```txt
Client -> Nginx/Apache -> Saugra -> Backend app
```

It inspects requests, applies deterministic security rules, rate limits abusive
traffic, scores repeated suspicious behavior and bot activity, records
structured security events, and explains why a request was monitored or blocked.

Saugra is rules-first: AI helps explain and tune decisions, but blocking comes
from rules, rate limits, behavior scoring, bot scoring, and explicit
configuration.

## Who It Is For

Saugra is built for:

- Small SaaS teams
- API-first startups
- Backend developers
- DevOps engineers
- Self-hosted application owners
- Security learners and students
- Teams that want lightweight protection without full cloud WAF lock-in

## Why Saugra?

Mature WAF platforms are powerful and widely deployed, but many teams find them
expensive, complex to configure, difficult to tune, or hard to explain.

Saugra focuses on a different experience: lightweight, self-hosted protection
that is simple to configure, monitor-first by default, transparent in its
decisions, and friendly to modern API-first applications.

Choose Saugra if you want:

- Simple YAML configuration
- Monitor-first deployment
- Clear JSON security logs
- Explainable rule decisions
- Nginx and Apache compatibility
- A rule-based + AI-assisted self-hosted WAF

## Current Status

This repository now has a production-oriented foundation:

- Rust CLI scaffold
- YAML config loading and validation
- Built-in rule metadata and basic regex inspection
- Monitor/block/off mode model
- Structured logging setup
- Proxies all normal application traffic and exposes `/_saugra/health` for
  checking that the WAF service is alive
- Route-based multi-upstream HTTP and WebSocket forwarding
- WebSocket handshake inspection and upgrade tunneling
- Redis-backed production rate limiting option
- Rotated local JSONL security event storage
- Example config at `configs/saugra.example.yml`

See `ROADMAP.md` for the public development roadmap.

Public docs:

- `docs/ARCHITECTURE.md` — technical architecture
- `docs/PRODUCT_SPEC.md` — product specification
- `docs/PRODUCTION_DEPLOYMENT.md` — Nginx/Apache production deployment guide
- `docs/OWASP_TOP_10_STRATEGY.md` — layered OWASP Top 10 coverage strategy
- `docs/CRS_IMPORT.md` — OWASP CRS conversion support and limitations

Install status:

- Supported today: build from Git/source and run with systemd.
- Planned later: packaged binary releases and Ubuntu apt repository.

## Quick Start

### Prerequisites

- Rust toolchain from [rustup](https://rustup.rs/)
- Redis for production rate limiting
- Nginx or Apache when deploying Saugra in front of a real application

### Run Locally From Source

```bash
git clone https://github.com/ewanyonyi/saugra.git
cd saugra
cargo build
cargo run -- test-config --config configs/saugra.example.yml
cargo run -- rules list --config configs/saugra.example.yml
cargo run -- run --config configs/saugra.example.yml
```

Leave Saugra running, then use another terminal for the checks below.

Check the health endpoint:

```bash
curl http://127.0.0.1:8787/_saugra/health
```

Run the local smoke test:

```bash
scripts/smoke-local.sh
```

The smoke test starts a temporary backend, runs Saugra with a temporary config,
verifies clean traffic is forwarded, verifies an SQL injection payload is
blocked, checks the JSONL event shape, and cleans up.

## Common Commands

Review OWASP Top 10:2025 mapped coverage:

```bash
cargo run -- owasp coverage --config configs/saugra.example.yml
```

Summarize recent security events by action and OWASP category:

```bash
cargo run -- logs summary --config configs/saugra.example.yml --limit 200
```

Explain a recorded request decision:

```bash
cargo run -- explain <request-id> --config configs/saugra.example.yml
```

Run local deployment posture checks:

```bash
cargo run -- posture check --config configs/saugra.example.yml
```

Convert supported OWASP CRS regex rules into Saugra YAML:

```bash
cargo run -- rules convert-crs --input /path/to/coreruleset/rules --output configs/rules/converted-crs.yml
```

See `docs/CRS_IMPORT.md` for supported CRS operators, transform mappings,
data-file import behavior, and unsupported feature reporting.

## Production Deployment

Recommended production shape:

```txt
Client -> Nginx/Apache TLS -> Saugra on 127.0.0.1:8787 -> Backend app
```

Start in `monitor` mode, review real traffic with `logs tail`, `logs summary`,
`explain`, and `posture check`, then switch to `block` mode after tuning.

For production:

- Keep Saugra on a private address such as `127.0.0.1:8787`.
- Put Nginx or Apache in front for public TLS.
- Use `rate_limit.backend: redis`.
- Store events in a durable path such as `/var/log/saugra/saugra-events.jsonl`.
- Configure exact WebSocket `allowed_origins` and `allowed_hosts` before routing
  browser WebSocket traffic through Saugra.

Full production guides and examples:

- `docs/PRODUCTION_DEPLOYMENT.md`
- `configs/saugra.production.example.yml`
- `configs/nginx.production.example.conf`
- `configs/apache.production.example.conf`
- `examples/django-channels-daphne-nginx/`

## Install On A Server

For the full Ubuntu install path, including building from Git, installing the
binary, creating `/etc/saugra/saugra.yml`, and running Saugra with systemd, see
`docs/PRODUCTION_DEPLOYMENT.md`.

Short version:

```bash
git clone https://github.com/ewanyonyi/saugra.git /opt/saugra
cd /opt/saugra
cargo build --release
sudo install -m 0755 target/release/saugra /usr/local/bin/saugra
sudo useradd --system --home /var/lib/saugra --shell /usr/sbin/nologin saugra
sudo mkdir -p /etc/saugra/rules /etc/saugra/standards /var/log/saugra /var/lib/saugra
sudo cp configs/saugra.production.example.yml /etc/saugra/saugra.yml
sudo cp configs/rules/REQUEST-*.yml /etc/saugra/rules/
sudo cp configs/standards/*.yml /etc/saugra/standards/
sudo cp configs/saugra.service.example /etc/systemd/system/saugra.service
sudo chown -R saugra:saugra /var/log/saugra /var/lib/saugra
sudo systemctl daemon-reload
sudo systemctl enable --now redis-server
sudo systemctl enable --now saugra
```

Validate the installed config:

```bash
saugra test-config --config /etc/saugra/saugra.yml
```

Check the service:

```bash
curl -i http://127.0.0.1:8787/_saugra/health
```

## Verify A Deployment

For a staging or production deployment you own:

```bash
scripts/verify-remote-waf.sh https://staging.example.com --yes-i-am-authorized
```

For apps where `/` is not a useful route, choose a harmless GET path:

```bash
scripts/verify-remote-waf.sh https://staging.example.com \
  --path /accounts/login/ \
  --yes-i-am-authorized
```

The remote verifier sends safe GET-only probes for common WAF signals such as
SQL injection, XSS, path traversal, command injection, scanner user agents,
secret-bearing URLs, method override headers, suspicious content types, supply
chain markers, prototype pollution, log injection, and parser edge cases. POST
body probes are opt-in with `--include-post`.

## Tuning

Use exclusions to tune false positives after reviewing logs in monitor mode.
Prefer narrow scoped exclusions:

```yaml
rules:
  exclusions:
    - name: Allow article HTML previews
      rule_ids:
        - SAUGRA-XSS-001
        - SAUGRA-BODY-001
      path_prefixes:
        - /api/articles
      query_params:
        - content
```

Global exclusions reduce protection across the whole application. Use them only
when the rule is intentionally disabled everywhere.

## Licensing

Saugra WAF is licensed under the [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE).


### Saugra Pro
Saugra follows an **Open-Core** model. While the core engine and rules are open-source under AGPL-3.0, we offer an enterprise-grade **Saugra Pro** version with additional features (SSO, SIEM integration, multi-node management, etc.) under a separate commercial license.

For more information on Saugra Pro, please visit our [official website](https://saugra.io).
