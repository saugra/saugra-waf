# Saugra Production Deployment

This guide shows the intended production shape for a single-node deployment.
For day-to-day commands, troubleshooting, runtime allowlisting, runtime
blocking, logs, and explanations, use `docs/ADMIN_GUIDE.md`.

```txt
Client -> Nginx/Apache -> Saugra on 127.0.0.1:8787 -> Backend app
```

Use `monitor` mode first, review events with `logs tail` and `explain`, then
switch to `block` after tuning.

## Required Services

- Saugra binary or service
- Redis for production rate limiting
- Nginx or Apache as the public web server
- Writable event log directory, for example `/var/log/saugra-waf`

## Install Saugra on Ubuntu or Debian

The recommended production install path is the signed Saugra APT repository.
It supports normal `apt update` and `apt upgrade` workflows. Source installs
remain useful for development and testing.

### Install From The Signed APT Repository

Install the repository prerequisites:

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
```

Add the Saugra signing key and repository:

```bash
curl -fsSL https://saugra.github.io/saugra-waf/saugra-waf.gpg |
  sudo gpg --dearmor --yes -o /usr/share/keyrings/saugra-waf.gpg

echo "deb [signed-by=/usr/share/keyrings/saugra-waf.gpg] https://saugra.github.io/saugra-waf/apt stable main" |
  sudo tee /etc/apt/sources.list.d/saugra-waf.list
```

Install Saugra:

```bash
sudo apt update
sudo apt install saugra-waf
```

### Install From A Downloaded `.deb` As A Fallback

If the package is already on the server, install it with `apt` so dependencies
are handled correctly:

```bash
cd /opt
sudo apt install ./saugra-waf_1.0.6-1_amd64.deb
```

The package installs:

- `/usr/bin/saugra-waf`
- `/lib/systemd/system/saugra-waf.service`
- `/etc/saugra-waf/saugra-waf.yml` when missing
- bundled rule packs under `/etc/saugra-waf/rules/` when missing
- bundled standards data under `/etc/saugra-waf/standards/` when missing
- bundled scanner catalogs under `/etc/saugra-waf/intelligence/` when missing
- writable runtime paths under `/var/log/saugra-waf` and `/var/lib/saugra-waf`

Confirm the binary and generated service are available:

```bash
saugra-waf --help
systemctl status saugra-waf
```

Edit the production config for your real backend and public host:

```bash
editor /etc/saugra-waf/saugra-waf.yml
```

At minimum, set the upstream host and target:

```yaml
server:
  listen: 127.0.0.1:8787
  mode: monitor

upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8080

routes:
  - path_prefix: /
    upstream: app
```

Validate the installed config:

```bash
saugra-waf test-config --config /etc/saugra-waf/saugra-waf.yml
```

Start Redis and Saugra:

```bash
systemctl enable --now redis-server
systemctl enable --now saugra-waf
systemctl status saugra-waf
```

Check Saugra locally before changing Nginx or Apache:

```bash
curl -i http://127.0.0.1:8787/_saugra-waf/health
curl -i -H "Host: example.com" http://127.0.0.1:8787/
```

Watch service logs and security events:

```bash
journalctl -u saugra-waf -f
saugra-waf logs tail --config /etc/saugra-waf/saugra-waf.yml
```

Keep `server.mode: monitor` first. After normal traffic is confirmed and false
positives are tuned, move to `block` mode.

If a trusted administrator is blocked by bot or behavior scoring during rollout,
add a short-lived runtime allowlist entry without restarting Saugra:

```bash
saugra-waf allowlist add ip 203.0.113.10 --duration 2h --reason "admin rollout verification" --config /etc/saugra-waf/saugra-waf.yml
saugra-waf allowlist list --config /etc/saugra-waf/saugra-waf.yml
```

Runtime policy reloads from `/var/lib/saugra-waf/runtime-policy.json` while Saugra
is running. The default effect bypasses bot and behavior threshold blocks for
the matching IP. Use `allowlist_effect: monitor_all` or `allow_all` only when a
trusted rollout policy should also affect deterministic WAF rule blocks.

### Install From Source

Install system dependencies:

```bash
apt update
apt install -y git curl build-essential pkg-config libssl-dev redis-server nginx
```

Install Rust if it is not already installed:

```bash
curl https://sh.rustup.rs -sSf | sh
. "$HOME/.cargo/env"
```

Clone and build Saugra:

```bash
git clone https://github.com/saugra/saugra-waf.git /opt/saugra-waf
cd /opt/saugra-waf
cargo build --release
install -m 0755 target/release/saugra-waf /usr/local/bin/saugra-waf
```

Create the service user and directories:

```bash
useradd --system --home /var/lib/saugra-waf --shell /usr/sbin/nologin saugra-waf
mkdir -p /etc/saugra-waf/rules /etc/saugra-waf/standards /var/log/saugra-waf /var/lib/saugra-waf
chown -R saugra-waf:saugra-waf /var/log/saugra-waf /var/lib/saugra-waf
```

Install the config:

```bash
cp configs/saugra-waf.production.example.yml /etc/saugra-waf/saugra-waf.yml
cp configs/rules/REQUEST-*.yml /etc/saugra-waf/rules/
cp configs/standards/*.yml /etc/saugra-waf/standards/
editor /etc/saugra-waf/saugra-waf.yml
```

For a local backend, set:

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
```

Validate the installed config:

```bash
saugra-waf test-config --config /etc/saugra-waf/saugra-waf.yml
```

Install the systemd service:

```bash
cp configs/saugra-waf.service.example /etc/systemd/system/saugra-waf.service
systemctl daemon-reload
systemctl enable --now redis-server
systemctl enable --now saugra-waf
systemctl status saugra-waf
```

Check Saugra locally before changing Nginx:

```bash
curl -i http://127.0.0.1:8787/_saugra-waf/health
```

## Saugra Config

Start from:

```bash
configs/saugra-waf.production.example.yml
```

Important production defaults:

- `server.listen` should stay private, such as `127.0.0.1:8787`.
- `server.mode` should start as `monitor` until the rules are tuned.
- `security.max_body_size` should match the public proxy body limit.
- `security.enable_rate_limiting` should stay enabled.
- `routes` should include explicit path-prefix mappings when traffic is split
  across HTTP, API, admin, or WebSocket backend processes. The longest matching
  `path_prefix` wins.
- `rate_limit.backend` should be `redis`.
- `rate_limit.routes` should be configured for the application routes that need
  stricter limits.
- `logging.event_log_path` should point to a durable local path.
- `logging.event_log_max_size` and `logging.event_log_max_files` should be set.
- `logging.timezone` should be set to the operator's preferred log timezone,
  for example `Africa/Nairobi`.
- `websocket.allowed_origins` and `websocket.allowed_hosts` should list the
  exact public origins and hosts that may open browser WebSocket connections.

Do not use `backend: memory` for production rate limiting. It is only for local
development and single-process demos.

Validate the config:

```bash
cargo run --bin saugra-waf -- test-config --config configs/saugra-waf.production.example.yml
```

Run Saugra:

```bash
cargo run --bin saugra-waf -- run --config configs/saugra-waf.production.example.yml
```

On a server, prefer the systemd service:

```bash
systemctl restart saugra-waf
journalctl -u saugra-waf -f
```

## Nginx

Use:

```bash
configs/nginx.production.example.conf
```

Install it as a site config, adjust `server_name`, and reload Nginx. The public
server forwards all application traffic to Saugra at `127.0.0.1:8787`.

### WebSocket Paths

Saugra inspects WebSocket upgrade handshakes before tunneling accepted
connections to the upstream. The initial handshake path, query string, headers,
`Origin`, `Host`, user-agent, cookies, and client identity go through the normal
rule, monitor/block, logging, and rate-limit pipeline. After a clean or
monitor-only decision, Saugra preserves the upgrade headers and tunnels the
long-lived connection.

For Nginx, route `/ws/` through Saugra and preserve upgrade semantics:

```nginx
map $http_upgrade $saugra_waf_connection_upgrade {
    default upgrade;
    '' close;
}

location /ws/ {
    proxy_pass http://127.0.0.1:8787;
    proxy_http_version 1.1;

    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $saugra_waf_connection_upgrade;
    proxy_set_header Host $host;
    proxy_set_header Origin $http_origin;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 86400;
}
```

### Forwarded Header Trust

Saugra trusts forwarded client IP and protocol headers only when the direct peer
matches `forwarded_headers.trusted_proxies`. Keep Saugra private and list only
your local reverse proxy or load balancer ranges:

```yaml
forwarded_headers:
  enabled: true
  trusted_proxies:
    - 127.0.0.1/32
    - ::1
  real_ip_header: X-Forwarded-For
  proto_header: X-Forwarded-Proto
  expected_proto: https
  insecure_proto_score: 10
```

If TLS terminates at Nginx or Apache, the public HTTPS virtual host should send
`X-Forwarded-Proto: https`. If another load balancer terminates TLS before
Nginx, do not rely on `$scheme`; set the header from the trusted upstream value
or hard-code `https` on the HTTPS entrypoint.

Configure Saugra with the public browser origins and hosts you expect:

```yaml
websocket:
  enabled: true
  allowed_origins:
    - https://example.com
  allowed_hosts:
    - example.com
```

Saugra validates the handshake, but applications must still authenticate the
user, authorize channel subscriptions, and enforce message-level authorization.
Do not treat handshake protection as authorization for every future message on
the socket.

## Apache

Use:

```bash
configs/apache.production.example.conf
```

Enable required modules before using the reverse-proxy config:

```bash
a2enmod proxy proxy_http proxy_wstunnel headers
```

Adjust `ServerName`, install the virtual host, and reload Apache.

## Smoke Tests

Normal traffic should reach the backend:

```bash
curl -i http://example.com/
```

Attack-shaped traffic should be logged in `monitor` mode and blocked in `block`
mode:

```bash
curl -i "http://example.com/search?q=--"
curl -i "http://example.com/comment?text=%3Cscript%3Ealert(1)%3C/script%3E"
```

Review recent events:

```bash
saugra-waf logs tail --config /etc/saugra-waf/saugra-waf.yml --limit 20
saugra-waf logs summary --config /etc/saugra-waf/saugra-waf.yml --limit 200
```

Explain a request:

```bash
saugra-waf explain <request-id> --config /etc/saugra-waf/saugra-waf.yml
```

The output starts with request context, including the client IP, method, path,
query when present, and upstream when recorded.

## Safe First Rollout

1. Start Redis and confirm Saugra can connect to it.
2. Create the event log directory and assign it to the Saugra service user.
3. Start Saugra with `server.mode: monitor`.
4. Put Nginx or Apache in front of Saugra.
5. Send normal traffic and confirm it reaches the backend.
6. Send attack-shaped test requests and confirm they appear in `logs tail`.
7. Review explanations for matched requests with
   `saugra-waf explain <request-id> --config /etc/saugra-waf/saugra-waf.yml`.
8. Use `logs summary` to check recent event volume by OWASP category.
9. Tune route limits and rule exclusions for false positives.
10. Switch to `server.mode: block` during a low-traffic window.
11. Keep watching `logs tail` and `logs summary` after block mode is enabled.
12. Use short-lived runtime allowlist entries for trusted admin IPs when bot or
    behavior scoring blocks rollout verification traffic.

Recommended first-production defaults:

```yaml
server:
  listen: 127.0.0.1:8787
  mode: monitor

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

runtime_policy:
  enabled: true
  path: /var/lib/saugra-waf/runtime-policy.json
  reload_interval: 5s
  default_duration: 2h
  allowlist_effect: skip_bot_and_behavior_block

logging:
  format: json
  level: info
  event_log_max_size: 100mb
  event_log_max_files: 30
  timezone: Africa/Nairobi
```

## Rollout Checklist

- Redis is running and reachable by Saugra.
- Saugra listens on a private interface.
- Nginx or Apache is the only public entrypoint.
- Event log directory exists and is writable by the Saugra service user.
- The public proxy and Saugra use compatible body-size limits.
- Route-specific rate limits are configured for sensitive application workflows.
- Start in `monitor` mode.
- Review false positives before switching to `block`.

## Upgrade Saugra

For package installs, download the newer `.deb`, then install it with `apt`:

```bash
apt install ./saugra-waf_<version>_amd64.deb
saugra-waf test-config --config /etc/saugra-waf/saugra-waf.yml
systemctl restart saugra-waf
```

The package seeds missing config and rule files, but it does not overwrite
operator-edited files under `/etc/saugra-waf`.

For source installs, upgrade by rebuilding from Git and restarting the service:


```bash
cd /opt/saugra-waf
git pull
cargo build --release
install -m 0755 target/release/saugra-waf /usr/local/bin/saugra-waf
saugra-waf test-config --config /etc/saugra-waf/saugra-waf.yml
systemctl restart saugra-waf
```
