<p align="center">
  <img src="docs/img/saugra-waf.svg" width="355" alt="Saugra WAF">
</p>

# Saugra WAF

[![CI](https://github.com/saugra/saugra-waf/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/saugra/saugra-waf/actions/workflows/ci.yml?query=branch%3Amain)
[![codecov](https://codecov.io/github/saugra/saugra-waf/graph/badge.svg)](https://codecov.io/github/saugra/saugra-waf)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](Cargo.toml)

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
- Proxies all normal application traffic and exposes `/_saugra-waf/health` for
  checking that the WAF service is alive
- Route-based multi-upstream HTTP and WebSocket forwarding
- WebSocket handshake inspection and upgrade tunneling
- Redis-backed production rate limiting option
- Rotated local JSONL security event storage
- Example config at `configs/saugra-waf.example.yml`

See `ROADMAP.md` for the public development roadmap.

Documentation is organized by audience:

- [Administration guide](docs/ADMIN_GUIDE.md): installation, configuration,
  Nginx/Apache deployment, AI providers, operations, and troubleshooting.
- [Architecture](docs/ARCHITECTURE.md): request processing, security model,
  rules, CRS conversion, storage, and developer design.
- [Release process](docs/RELEASE_PROCESS.md): package, APT, signing, and release
  procedures for maintainers.
- [Roadmap](ROADMAP.md): completed and planned product work.
- [Contributing](CONTRIBUTING.md): development and verification workflow.
- [Licensing](docs/LICENSING.md) and [trademarks](TRADEMARKS.md): legal and
  branding guidance.

Install status:

- Supported today: install from the signed Saugra Ubuntu/Debian APT repository.
- Supported today: download `.deb` packages from GitHub Releases.
- Supported today: build from Git/source and run with systemd.
- Planned later: official Debian archive submission, then Ubuntu sync where
  possible.

## Quick Start

### Install On Ubuntu Or Debian

Install the HTTPS and signing-key tools:

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
```

Add the Saugra repository signing key:

```bash
curl -fsSL https://saugra.github.io/saugra-waf/saugra-waf.gpg |
  sudo gpg --dearmor --yes -o /usr/share/keyrings/saugra-waf.gpg
```

Add the signed Saugra APT repository and install the package:

```bash
echo "deb [signed-by=/usr/share/keyrings/saugra-waf.gpg] https://saugra.github.io/saugra-waf/apt stable main" |
  sudo tee /etc/apt/sources.list.d/saugra-waf.list

sudo apt update
sudo systemctl mask saugra-waf.service
sudo apt install saugra-waf
sudo apt-mark hold saugra-waf
```

Review the monitor-first production config, validate it, and then start Saugra:

```bash
sudo editor /etc/saugra-waf/saugra-waf.yml
sudo saugra-waf test-config
sudo systemctl unmask saugra-waf.service
sudo systemctl enable --now saugra-waf
```

Future releases should be installed during a planned maintenance window using
the [administration upgrade runbook](docs/ADMIN_GUIDE.md#upgrade-to-the-newest-version):

```bash
sudo apt update
sudo apt-mark unhold saugra-waf
sudo apt install --only-upgrade saugra-waf
sudo apt-mark hold saugra-waf
```

### Prerequisites

- Rust toolchain from [rustup](https://rustup.rs/)
- Redis for production rate limiting
- Nginx or Apache when deploying Saugra in front of a real application

### Run Locally From Source

```bash
git clone https://github.com/saugra/saugra-waf.git
cd saugra-waf
cargo build
cargo run --bin saugra-waf -- test-config --config configs/saugra-waf.example.yml
cargo run --bin saugra-waf -- rules list --config configs/saugra-waf.example.yml
cargo run --bin saugra-waf -- rules view <saugra-rule-id> --config configs/saugra-waf.example.yml
cargo run --bin saugra-waf -- run --config configs/saugra-waf.example.yml
```

Leave Saugra running, then use another terminal for the checks below.

Check the health endpoint:

```bash
curl http://127.0.0.1:8787/_saugra-waf/health
```

Run the local smoke test:

```bash
scripts/smoke-local.sh
```

The smoke test starts a temporary backend, runs Saugra with a temporary config,
verifies clean traffic is forwarded, verifies an SQL injection payload is
blocked, checks the JSONL event shape, and cleans up.

## Common Commands

Installed commands automatically use `/etc/saugra-waf/saugra-waf.yml`. In a
source checkout they use `configs/saugra-waf.example.yml`. Set
`SAUGRA_WAF_CONFIG=/different/path.yml` or pass `--config` to override discovery.

Review OWASP Top 10:2025 mapped coverage:

```bash
cargo run --bin saugra-waf -- owasp coverage --config configs/saugra-waf.example.yml
```

Summarize recent security events by action and OWASP category:

```bash
cargo run --bin saugra-waf -- logs summary --config configs/saugra-waf.example.yml --limit 200
```

Generate a daily security summary from local event logs:

```bash
cargo run --bin saugra-waf -- summary daily --config configs/saugra-waf.example.yml
```

Preview stale generated file and unknown-threat baseline cleanup:

```bash
cargo run --bin saugra-waf -- cleanup run --dry-run --config configs/saugra-waf.example.yml
```

Review unknown-threat shadow candidates:

```bash
cargo run --bin saugra-waf -- unknown-threats report --config configs/saugra-waf.example.yml
```

Explain a recorded request decision:

```bash
cargo run --bin saugra-waf -- explain <request-id> --config configs/saugra-waf.example.yml
```

AI explanations use local llama.cpp with Qwen3 0.6B Q8 by default and fall back
to Saugra's deterministic local explanation when inference is unavailable:

```bash
llama-server \
  -hf Qwen/Qwen3-0.6B-GGUF:Q8_0 \
  --alias saugra-qwen3-0.6b \
  --host 127.0.0.1 --port 8080 \
  --ctx-size 2048 --threads 1 --parallel 1 --jinja --no-webui
```

See the [administration guide](docs/ADMIN_GUIDE.md#ai-explanations) for local
llama.cpp installation, resource limits, model-free operation, Ollama
compatibility, remote adapters, and rollback.

Run local deployment posture checks:

```bash
cargo run --bin saugra-waf -- posture check --config configs/saugra-waf.example.yml
```

Convert supported OWASP CRS regex rules into Saugra YAML:

```bash
cargo run --bin saugra-waf -- rules convert-crs --input /path/to/coreruleset/rules --output configs/rules/converted-crs.yml
```

See [Rule Packs And CRS Import](docs/ARCHITECTURE.md#rule-packs-and-crs-import)
for supported operators, transforms, and limitations.

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
- Configure `forwarded_headers.trusted_proxies` for the proxy addresses that
  are allowed to supply client IP and protocol headers.
- Use `rate_limit.backend: redis`.
- Store events in a durable path such as `/var/log/saugra-waf/saugra-waf-events.jsonl`.
- Configure exact WebSocket `allowed_origins` and `allowed_hosts` before routing
  browser WebSocket traffic through Saugra.

Production references:

- `docs/ADMIN_GUIDE.md`
- `configs/saugra-waf.production.example.yml`
- `configs/nginx.production.example.conf`
- `configs/apache.production.example.conf`
- `examples/django-channels-daphne-nginx/`

## Install On An Ubuntu Or Debian Host

The recommended package installation path is the signed APT repository shown in
[Quick Start](#install-on-ubuntu-or-debian). It installs the binary, systemd
unit, production configuration, rule packs, and runtime directories.

After installation, configure the real upstream application before starting
the service:

```bash
sudo editor /etc/saugra-waf/saugra-waf.yml
saugra-waf test-config
sudo systemctl enable --now saugra-waf
```

Check the service:

```bash
curl -i http://127.0.0.1:8787/_saugra-waf/health
```

See the [administration guide](docs/ADMIN_GUIDE.md) for the complete Nginx,
Apache, Redis, AI, and monitor-first rollout procedure.

## Build A Debian Package

Saugra can be packaged as a `.deb` for Debian and Ubuntu:

```bash
cargo install cargo-deb --version 3.6.0 --locked
cargo test --locked --all-targets --all-features
cargo deb --locked
```

The package artifact is written under `target/debian/`. See the
[release process](docs/RELEASE_PROCESS.md) for install tests and publishing.

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
      methods:
        - POST
      targets:
        - query
      content_types:
        - application/json
```

Global exclusions reduce protection across the whole application. Use them only
when the rule is intentionally disabled everywhere.

Value-based `trusted_headers` and authenticated `identities` scopes match only
when the direct peer is in `forwarded_headers.trusted_proxies`. Identity headers
must also be listed in `forwarded_headers.identity_assertions`; the front proxy
must remove client-supplied copies before setting its authenticated value.
Saugra retains parameter names, header names, normalized content type, and body
size for tuning without retaining request bodies or trusted header values.

Bot and behavior threshold findings produced in monitor mode remain visible in
events and explanations, but do not contribute to the blocking anomaly score.
For scanner-path false positives, use an operator-managed threat-path catalog
or configure `behavior.probe_path_exclusions` and
`bot_protection.scanner_path_exclusions` for legitimate routes. Avoid weakening
unrelated deterministic attack rules or raising the global anomaly threshold.

## Licensing

Saugra WAF is licensed under the [GNU Affero General Public
License v3.0 only (AGPL-3.0-only)](LICENSE).

See [licensing](docs/LICENSING.md) for guidance on AGPL-3.0-only use, modified
network deployments, warranty and liability limits, and trademark policy.

Saugra WAF is a fully open-source, community-based project. It may integrate
with Saugra Console as an optional operations dashboard for managing rules,
policies, and multi-instance deployments across Saugra WAF and Saugra EDR.
