# Saugra WAF

Saugra is a lightweight Rust-based, AI-assisted Web Application Firewall for
modern web applications and APIs.

The MVP direction is:

```txt
Rules-first protection + rate limiting + behavior scoring + AI explanations
```

AI is used for explanations and tuning support. Blocking decisions should come
from deterministic rules, rate limits, and explicit configuration.

## Why Saugra?

Saugra is not trying to replace mature, established WAF platforms today. Those
tools are powerful and battle-tested, but they can be complex to configure,
tune, and explain.

Saugra focuses on a different developer experience: a lightweight Rust-based WAF
that is simple to configure, easy to run locally, explainable by default, and
friendly to modern API-first applications.

Choose Saugra if you want:

- Simple YAML configuration
- Monitor-first deployment
- Clear JSON security logs
- Explainable rule decisions
- Nginx and Apache compatibility
- A Rust-based self-hosted WAF

## Current Status

This repository now has a production-oriented MVP foundation:

- Rust CLI scaffold
- YAML config loading and validation
- Built-in rule metadata and basic regex inspection
- Monitor/block/off mode model
- Structured logging setup
- Catch-all reverse proxy with `/_saugra/health`
- Redis-backed production rate limiting option
- Rotated local JSONL security event storage
- Example config at `configs/saugra.example.yml`

See `ROADMAP.md` for the public development roadmap.

Public docs:

- `docs/ARCHITECTURE.md` — technical architecture
- `docs/CAPSTONE_SPEC.md` — capstone product specification
- `docs/PRODUCTION_DEPLOYMENT.md` — Nginx/Apache production deployment guide

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

Convert supported OWASP CRS regex rules into Saugra YAML:

```bash
cargo run -- rules convert-crs --input /path/to/coreruleset/rules --output configs/rules/converted-crs.yml
```

Saugra uses native YAML rule packs as its product rule format. OWASP CRS is
treated as an upstream source of maintained detection knowledge that can be
converted into Saugra YAML; Saugra does not try to clone ModSecurity syntax.

```txt
OWASP CRS .conf files
  -> saugra rules convert-crs
  -> Saugra YAML rule packs
  -> Saugra rule engine
```

Start the service:

```bash
cargo run -- run --config configs/saugra.example.yml
```

Then check the health endpoint:

```bash
curl http://127.0.0.1:8787/_saugra/health
```

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
  - name: jirani-rust
    host: example.com
    target: http://127.0.0.1:8080

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
  files:
    - configs/rules/REQUEST-913-SCANNER-DETECTION.yml
    - configs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.yml
    - configs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.yml
    - configs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.yml
    - configs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.yml
    - configs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.yml

ai:
  enabled: true
  mode: explain_only

logging:
  format: json
  level: info
  event_log_path: /var/log/saugra/saugra-events.jsonl
  event_log_max_size: 100mb
  event_log_max_files: 30
```

Start in `monitor` mode. Switch to `block` only after reviewing real traffic
with `logs tail` and `explain`.

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

Deployment order:

1. Keep the app running on `127.0.0.1:8080`.
2. Start Redis.
3. Start Saugra on `127.0.0.1:8787`.
4. Change Nginx to proxy to `127.0.0.1:8787`.
5. Run `nginx -t`.
6. Reload Nginx.
7. Review Saugra events before switching to `block`.

## Next Development Step

The remaining useful production-readiness slice is operational polish:

1. Add safe local smoke-test scripts.
2. Add more deployment examples for common stacks.
3. Add packaged binary release instructions.
4. Add live Redis integration tests where Redis is available.

## Licensing

Saugra WAF is licensed under the [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE).

### Why AGPL-3.0?
We chose the AGPL-3.0 to ensure that Saugra remains open and collaborative. Specifically:
- **Service Protection**: If you run a modified version of Saugra as a service (SaaS), you must share your source code modifications with the community. This prevents vendors from reselling Saugra without contributing back.
- **Open Source Integrity**: It is a true OSI-approved open-source license that guarantees user freedom.

### Saugra Pro
Saugra follows an **Open-Core** model. While the core engine and rules are open-source under AGPL-3.0, we offer an enterprise-grade **Saugra Pro** version with additional features (SSO, SIEM integration, multi-node management, etc.) under a separate commercial license.

For more information on Saugra Pro, please visit our [official website](https://saugra.io).
