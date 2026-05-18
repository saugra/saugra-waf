# Saugra WAF

[![CI](https://github.com/ewanyonyi/saugra/actions/workflows/ci.yml/badge.svg)](https://github.com/ewanyonyi/saugra/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/ewanyonyi/saugra/branch/main/graph/badge.svg)](https://codecov.io/gh/ewanyonyi/saugra)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](Cargo.toml)

![Saugra WAF Logo](docs/img/saugra-logo.jpeg)



Saugra is a lightweight rule-based + AI-assisted Web Application Firewall for
modern web applications and APIs.

The product direction is:

```txt
Rules-first protection + rate limiting + behavior scoring + AI explanations
```

AI is used for explanations and tuning support. Blocking decisions should come
from deterministic rules, rate limits, and explicit configuration.

## Why Saugra?

Saugra is not trying to replace mature, established WAF platforms today. Those
tools are powerful and battle-tested, but they can be complex to configure,
tune, and explain.

Saugra focuses on a different developer experience: a lightweight rule-based + AI-assisted WAF
that is simple to configure, easy to run locally, explainable by default, and
friendly to modern API-first applications.

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
- Catch-all reverse proxy with `/_saugra/health`
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

Validate the example config:

```bash
cargo run -- test-config --config configs/saugra.example.yml
```

List configured rules:

```bash
cargo run -- rules list --config configs/saugra.example.yml
```

Validate rule-pack metadata, versions, active rule counts, exclusions, and any
unsupported CRS imports:

```bash
cargo run -- test-config --config configs/saugra.example.yml
```

`rules list` also shows each active rule's ordered transform pipeline, which is
useful when checking CRS imports or false-positive tuning.

Review OWASP Top 10:2025 mapped coverage:

```bash
cargo run -- owasp coverage --config configs/saugra.example.yml
```

Run local deployment posture checks:

```bash
cargo run -- posture check --config configs/saugra.example.yml
```

Summarize configured SBOM/dependency scan reports:

```bash
cargo run -- reports summary --config configs/saugra.example.yml
```

Summarize recent security events by action and OWASP category:

```bash
cargo run -- logs summary --config configs/saugra.example.yml --limit 200
```

Convert supported OWASP CRS regex rules into Saugra YAML:

```bash
cargo run -- rules convert-crs --input /path/to/coreruleset/rules --output configs/rules/converted-crs.yml
```

Saugra uses native YAML rule packs as its product rule format. OWASP CRS is
treated as an upstream source of maintained detection knowledge that can be
converted into Saugra YAML; Saugra does not try to clone ModSecurity syntax.
The shipped default rule packs declare `owasp-top-10:2025` metadata and include
starter WAF signals for every OWASP Top 10:2025 category. Future Top 10
releases can be adopted by shipping updated YAML packs and changing
`rules.files`, without rewriting the proxy.

```txt
OWASP CRS .conf files
  -> saugra rules convert-crs
  -> Saugra YAML rule packs
  -> Saugra rule engine
```

See `docs/CRS_IMPORT.md` for supported CRS operators, transform mappings,
data-file import behavior, and unsupported feature reporting.

Start the service:

```bash
cargo run -- run --config configs/saugra.example.yml
```

Then check the health endpoint:

```bash
curl http://127.0.0.1:8787/_saugra/health
```

Run the local proxy smoke test:

```bash
scripts/smoke-local.sh
```

The smoke test starts a temporary local backend, starts Saugra with a temporary
config and event log, verifies clean traffic is forwarded, verifies an SQL
injection payload is blocked, checks the JSONL event shape, and then cleans up.

Verify a remote staging or production deployment you own:

```bash
scripts/verify-remote-waf.sh https://staging.example.com --yes-i-am-authorized
```

For apps where `/` is not a useful route, choose a harmless GET path:

```bash
scripts/verify-remote-waf.sh https://staging.example.com \
  --path /accounts/login/ \
  --yes-i-am-authorized
```

The remote verifier sends safe GET-only probes mapped to OWASP Top 10-style
risks plus extra WAF signals: SQL injection, XSS, path traversal, command
injection, scanner user agents, secret-bearing URLs, method override headers,
insecure forwarded protocol headers, suspicious content types, supply-chain
install-script markers, prototype pollution, serialized object markers, log
injection, and parser edge cases. It treats HTTP `403` rule blocks and HTTP
`429` rate-limit blocks as protective by default, and reports broader coverage
probes as advisory warnings unless you pass `--all-required`.

Useful options:

```bash
scripts/verify-remote-waf.sh https://staging.example.com \
  --path /accounts/login/ \
  --block-statuses 403,429,406 \
  --delay 1 \
  --include-post \
  --json-output /tmp/saugra-remote-report.json \
  --yes-i-am-authorized
```

Use `--all-required` for strict staging checks where every advisory vector
should also be blocked. If many probes return `429`, Saugra is protecting the
target through rate limiting, but that can mask which rule would have matched;
use `--delay` or temporarily raise the verifier route limit for rule-specific
staging validation. POST body probes are opt-in with `--include-post` because
POST routes can modify application state; prefer that option on staging.

Forwarded-header probes, such as spoofing `X-Forwarded-Proto: http`, remain
advisory even with `--all-required` because Nginx or Apache may normalize those
headers before Saugra sees them. Use `--require-edge-header-probes` only when
you intentionally want those edge-sensitive probes to fail the run.

## Production Setup Example

Use case: an existing Nginx site already forwards traffic directly to an app.
For example, this staging shape:

```txt
Client -> Nginx TLS -> Rust app on 127.0.0.1:8080
```

To place Saugra in front of the app, keep Nginx as the public TLS entrypoint and
insert Saugra between Nginx and the app:

```txt
Client -> Nginx TLS -> Saugra on 127.0.0.1:8787 -> Rust app on 127.0.0.1:8080
```

That means Nginx proxies to Saugra, and Saugra proxies to the actual app.

Current WebSocket posture: Saugra protects normal HTTP reverse-proxy traffic.
Until upgrade-aware proxying lands in Phase 4, keep WebSocket paths such as
`/ws/` in explicit Nginx or Apache locations that bypass Saugra and proxy
directly to the WebSocket upstream. Harden those paths with edge/application
authentication, `Origin` and `Host` validation, rate limits, and message-level
authorization.

### Install Saugra

For the full Ubuntu install path, including building from Git, installing the
binary, creating `/etc/saugra/saugra.yml`, and running Saugra with systemd, see:

```bash
docs/PRODUCTION_DEPLOYMENT.md
```

Short version:

```bash
git clone https://github.com/<your-org>/saugra.git /opt/saugra-src
cd /opt/saugra-src
cargo build --release
install -m 0755 target/release/saugra /usr/local/bin/saugra
cp configs/saugra.production.example.yml /etc/saugra/saugra.yml
cp configs/saugra.service.example /etc/systemd/system/saugra.service
systemctl daemon-reload
systemctl enable --now redis-server
systemctl enable --now saugra
```

### Saugra Config

Create a production config for the app:

```yaml
server:
  listen: 127.0.0.1:8787
  mode: monitor

upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8080
  - name: ws
    host: example.com
    target: http://127.0.0.1:8002

routes:
  - path_prefix: /ws/
    upstream: ws
  - path_prefix: /
    upstream: app

security:
  max_body_size: 2mb
  enable_rate_limiting: true
  block_suspicious_user_agents: true
  inspect_json_body: true

rate_limit:
  backend: redis
  redis_url: redis://127.0.0.1:6379
  redis_password: null
  requests_per_minute: 120
  burst: 30
  routes:
    - path: /sensitive-action
      requests_per_minute: 10
      burst: 5

rules:
  owasp_crs: true
  paranoia_level: 1
  detection_paranoia_level: 1
  blocking_paranoia_level: 1
  inbound_anomaly_threshold: 5
  files:
    - configs/rules/REQUEST-913-SCANNER-DETECTION.yml
    - configs/rules/REQUEST-914-AUTHENTICATION-ABUSE.yml
    - configs/rules/REQUEST-916-INSECURE-DESIGN.yml
    - configs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.yml
    - configs/rules/REQUEST-921-CRYPTO-TRANSPORT.yml
    - configs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.yml
    - configs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.yml
    - configs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.yml
    - configs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.yml
    - configs/rules/REQUEST-944-SUPPLY-CHAIN.yml
    - configs/rules/REQUEST-945-INTEGRITY.yml
    - configs/rules/REQUEST-949-LOGGING-ALERTING.yml
    - configs/rules/REQUEST-950-EXCEPTIONAL-CONDITIONS.yml
  exclusions:
    - name: Allow article HTML previews
      rule_ids:
        - SAUGRA-XSS-001
      path_prefixes:
        - /api/articles
      query_params:
        - content

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

websocket:
  enabled: true
  allowed_origins:
    - https://example.com
  allowed_hosts:
    - example.com

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
  dependency_report_path: null

reports:
  dependency_report_paths: []

standards:
  owasp_catalog: /etc/saugra/standards/owasp-top-10-2025.yml
```

Start in `monitor` mode. Switch to `block` only after reviewing real traffic
with `logs tail`, `logs summary`, `explain`, and `posture check`.

For monitor-first CRS-style tuning, raise `detection_paranoia_level` before
raising `blocking_paranoia_level`. For example, use detection level `2` and
blocking level `1` to log higher-paranoia findings without letting them block
traffic yet.

### Rule Exclusions

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

If `path_prefixes`, `query_params`, and `headers` are omitted, the exclusion is
global for the listed `rule_ids` or `categories`:

```yaml
rules:
  exclusions:
    - name: Disable noisy XSS rule globally
      rule_ids:
        - SAUGRA-XSS-001
```

Global exclusions reduce protection across the whole application. Use them only
when the rule is intentionally disabled everywhere.

### Nginx Change

Original direct-to-app location:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For "";
    proxy_set_header X-Real-IP "";
    proxy_set_header User-Agent "";
    proxy_read_timeout 30s;
}
```

Change it to proxy to Saugra:

```nginx
location / {
    proxy_pass http://127.0.0.1:8787;
    proxy_http_version 1.1;

    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header User-Agent $http_user_agent;

    proxy_read_timeout 30s;
}
```

Do not clear `X-Forwarded-For`, `X-Real-IP`, or `User-Agent` when using a WAF.
Saugra uses those values for client identity, rate limiting, scanner detection,
and useful security events.

The HTTPS server then looks like this, with the Certbot-managed lines preserved:

```nginx
server {
    server_name example.com;

    access_log off;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header User-Agent $http_user_agent;
        proxy_read_timeout 30s;
    }

    location = /_saugra/health {
        allow 127.0.0.1;
        deny all;

        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    listen [::]:443 ssl ipv6only=on; # managed by Certbot
    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
}
```

The port 80 Certbot redirect block can remain unchanged.

If the application uses WebSockets, keep the upgrade path separate until
Saugra supports upgrade-aware proxying:

```nginx
location /ws/ {
    proxy_pass http://127.0.0.1:8002;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 86400;
}
```

Deployment order:

1. Keep the app running on `127.0.0.1:8080`.
2. Start Redis.
3. Start Saugra on `127.0.0.1:8787`.
4. Change Nginx to proxy to `127.0.0.1:8787`.
5. Run `nginx -t`.
6. Reload Nginx.
7. Review Saugra events before switching to `block`.

## Next Development Step

The next major implementation slice is Phase 4 WebSocket support:

1. Detect WebSocket upgrade handshakes.
2. Apply the existing WAF and rate-limit decision flow to the handshake.
3. Tunnel accepted upgraded connections without breaking long-lived sessions.
4. Add tests and deployment examples for allowed, monitored, blocked, and
   rate-limited handshakes.

Operational polish can continue in parallel with packaged binary release
instructions and live Redis integration tests where Redis is available.

## Licensing

Saugra WAF is licensed under the [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE).


### Saugra Pro
Saugra follows an **Open-Core** model. While the core engine and rules are open-source under AGPL-3.0, we offer an enterprise-grade **Saugra Pro** version with additional features (SSO, SIEM integration, multi-node management, etc.) under a separate commercial license.

For more information on Saugra Pro, please visit our [official website](https://saugra.io).
