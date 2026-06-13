# Saugra WAF

[![CI](https://github.com/saugra/saugra-waf/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/saugra/saugra-waf/actions/workflows/ci.yml?query=branch%3Amain)
[![codecov](https://codecov.io/github/saugra/saugra-waf/graph/badge.svg)](https://codecov.io/github/saugra/saugra-waf)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](Cargo.toml)

![Saugra WAF Logo](docs/img/saugra-waf-logo.jpeg)

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

Public docs:

- `docs/ARCHITECTURE.md` — technical architecture
- `docs/PRODUCT_SPEC.md` — product specification
- `docs/LICENSING.md` — licensing, commercial use, liability, and trademark
  guidance
- `docs/PRODUCTION_DEPLOYMENT.md` — Nginx/Apache production deployment guide
- `docs/ADMIN_GUIDE.md` — operator commands, troubleshooting, allowlisting,
  blocking, logs, and explanations
- `docs/OWASP_TOP_10_STRATEGY.md` — layered OWASP Top 10 coverage strategy
- `docs/CRS_IMPORT.md` — OWASP CRS conversion support and limitations
- `docs/DEBIAN_PACKAGING.md` — `.deb` build and GitHub Release publishing guide
- `docs/APT_REPOSITORY.md` — signed Ubuntu/Debian APT repository guide
- `docs/OFFICIAL_DEBIAN_RELEASE.md` — official Debian archive release plan
- `docs/RELEASE_PROCESS.md` — maintainer release checklist
- `docs/RUNTIME_ALLOWLIST.md` — no-restart local runtime allowlisting design
- `TRADEMARKS.md` — Saugra name, logo, and branding policy

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
sudo apt install saugra-waf
```

Review the monitor-first production config, validate it, and then start Saugra:

```bash
sudo editor /etc/saugra-waf/saugra-waf.yml
sudo saugra-waf test-config
sudo systemctl enable --now saugra-waf
```

Future releases can be installed through the normal system upgrade flow:

```bash
sudo apt update
sudo apt upgrade
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

Run local deployment posture checks:

```bash
cargo run --bin saugra-waf -- posture check --config configs/saugra-waf.example.yml
```

Convert supported OWASP CRS regex rules into Saugra YAML:

```bash
cargo run --bin saugra-waf -- rules convert-crs --input /path/to/coreruleset/rules --output configs/rules/converted-crs.yml
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
- Configure `forwarded_headers.trusted_proxies` for the proxy addresses that
  are allowed to supply client IP and protocol headers.
- Use `rate_limit.backend: redis`.
- Store events in a durable path such as `/var/log/saugra-waf/saugra-waf-events.jsonl`.
- Configure exact WebSocket `allowed_origins` and `allowed_hosts` before routing
  browser WebSocket traffic through Saugra.

Full production guides and examples:

- `docs/PRODUCTION_DEPLOYMENT.md`
- `configs/saugra-waf.production.example.yml`
- `configs/nginx.production.example.conf`
- `configs/apache.production.example.conf`
- `examples/django-channels-daphne-nginx/`

## Install On A Server

The recommended server install is the signed APT repository shown in
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

See `docs/PRODUCTION_DEPLOYMENT.md` for the complete Nginx, Apache, Redis, and
monitor-first rollout procedure. Source installation remains available for
development and testing.

## Build A Debian Package

Saugra can be packaged as a `.deb` for Debian and Ubuntu:

```bash
cargo install cargo-deb --version 3.6.0 --locked
cargo test --locked --all-targets --all-features
cargo deb --locked
```

The package artifact is written under `target/debian/`. See
`docs/DEBIAN_PACKAGING.md` for the local install test and GitHub Release
publishing flow.

## APT Release Setup

Maintainers must complete this one-time setup before a version tag can publish
the `.deb` package and signed APT repository through
`.github/workflows/release.yml`.

### 1. Enable GitHub Pages

For an organization repository, first open the organization **Settings**, go to
**Member privileges**, and allow members to create public GitHub Pages sites
under **Pages creation**.

Then open the repository Pages settings:

```txt
https://github.com/saugra/saugra-waf/settings/pages
```

Under **Build and deployment**, set **Source** to **GitHub Actions**. Do not
configure a branch-based Pages workflow; the release workflow uploads and
deploys the generated APT repository.

### 2. Allow Release Tags To Deploy

Open:

```txt
https://github.com/saugra/saugra-waf/settings/environments
```

Select the `github-pages` environment. Under **Deployment branches and tags**,
choose **Selected branches and tags**, then add this as a **tag** rule:

```txt
v*.*.*
```

Make sure GitHub reports tags, rather than branches, as allowed by the rule.

### 3. Create A Dedicated Signing Key

Create the APT signing key on a trusted maintainer machine. Use a strong,
dedicated passphrase and keep an encrypted offline backup of this GPG home:

```bash
export GNUPGHOME="$HOME/.saugra-waf-apt-gnupg"
install -d -m 700 "$GNUPGHOME"

gpg --quick-generate-key \
  "Saugra WAF APT Repository <releases@saugra-waf.dev>" \
  rsa4096 sign 2y

gpg --list-secret-keys --with-subkey-fingerprint
```

Use the full hexadecimal primary-key fingerprint printed below the `sec` line
as the signing key ID. Do not include the `rsa4096/` prefix.

Export the private key temporarily:

```bash
gpg --armor --export-secret-keys <FULL-FINGERPRINT> \
  > /tmp/saugra-waf-apt-private.asc
```

Never commit this file or disclose its contents or passphrase.

### 4. Add GitHub Actions Secrets

Open:

```txt
https://github.com/saugra/saugra-waf/settings/secrets/actions
```

Add these repository secrets:

- `SAUGRA_APT_GPG_KEY_ID`: full primary-key fingerprint.
- `SAUGRA_APT_GPG_PRIVATE_KEY`: complete contents of
  `/tmp/saugra-waf-apt-private.asc`, including the BEGIN and END lines.
- `SAUGRA_APT_GPG_PASSPHRASE`: exact signing-key passphrase.

After adding the secrets, securely remove the temporary export:

```bash
shred -u /tmp/saugra-waf-apt-private.asc
```

### 5. Publish A Release

Update `Cargo.toml`, `Cargo.lock`, and `CHANGELOG.md`, commit and push the
release preparation, then create an annotated version tag:

```bash
git tag -a v<version> -m "Saugra WAF v<version>"
git push origin main
git push origin v<version>
```

The tag triggers tests, builds and install-tests the `.deb`, creates the GitHub
Release, signs the APT metadata, and deploys the repository to:

```txt
https://saugra.github.io/saugra-waf/apt
```

Verify the release by following the
[Ubuntu or Debian installation](#install-on-ubuntu-or-debian) steps on a clean
host. See `docs/APT_REPOSITORY.md` and `docs/RELEASE_PROCESS.md` for the full
maintainer checklist, signing policy, and troubleshooting details.

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

Bot and behavior threshold findings produced in monitor mode remain visible in
events and explanations, but do not contribute to the blocking anomaly score.
For scanner-path false positives, use an operator-managed threat-path catalog
or configure `behavior.probe_path_exclusions` and
`bot_protection.scanner_path_exclusions` for legitimate routes. Avoid weakening
unrelated deterministic attack rules or raising the global anomaly threshold.

## Licensing

Saugra WAF Community Edition is licensed under the [GNU Affero General Public
License v3.0 only (AGPL-3.0-only)](LICENSE).

See `docs/LICENSING.md` for guidance on commercial use, modified network
deployments, warranty and liability limits, and trademark policy.

For commercial licensing or support questions, contact the maintainers through
the repository profile.
