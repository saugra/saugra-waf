# Saugra Production Deployment

This guide shows the intended production shape for a single-node deployment.

```txt
Client -> Nginx/Apache -> Saugra on 127.0.0.1:8787 -> Backend app
```

Use `monitor` mode first, review events with `logs tail` and `explain`, then
switch to `block` after tuning.

## Required Services

- Saugra binary or service
- Redis for production rate limiting
- Nginx or Apache as the public web server
- Writable event log directory, for example `/var/log/saugra`

## Install Saugra on Ubuntu

Today, the supported install path is from Git/source. Packaged binary releases
and Ubuntu apt repositories should be added later when release packaging exists.

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
git clone https://github.com/<your-org>/saugra.git /opt/saugra-src
cd /opt/saugra-src
cargo build --release
install -m 0755 target/release/saugra /usr/local/bin/saugra
```

Create the service user and directories:

```bash
useradd --system --home /var/lib/saugra --shell /usr/sbin/nologin saugra
mkdir -p /etc/saugra/rules /etc/saugra/standards /var/log/saugra /var/lib/saugra
chown -R saugra:saugra /var/log/saugra /var/lib/saugra
```

Install the config:

```bash
cp configs/saugra.production.example.yml /etc/saugra/saugra.yml
cp configs/rules/REQUEST-*.yml /etc/saugra/rules/
cp configs/standards/*.yml /etc/saugra/standards/
editor /etc/saugra/saugra.yml
```

For your staging example, set:

```yaml
server:
  listen: 127.0.0.1:8787
  mode: monitor

upstreams:
  - name: jirani-rust
    host: snf-6731.vlab.ac.ke
    target: http://127.0.0.1:8080
```

Validate the installed config:

```bash
saugra test-config --config /etc/saugra/saugra.yml
```

Install the systemd service:

```bash
cp configs/saugra.service.example /etc/systemd/system/saugra.service
systemctl daemon-reload
systemctl enable --now redis-server
systemctl enable --now saugra
systemctl status saugra
```

Check Saugra locally before changing Nginx:

```bash
curl -i http://127.0.0.1:8787/_saugra/health
```

## Saugra Config

Start from:

```bash
configs/saugra.production.example.yml
```

Important production defaults:

- `server.listen` should stay private, such as `127.0.0.1:8787`.
- `server.mode` should start as `monitor` until the rules are tuned.
- `security.max_body_size` should match the public proxy body limit.
- `security.enable_rate_limiting` should stay enabled.
- `rate_limit.backend` should be `redis`.
- `rate_limit.routes` should be configured for the application routes that need
  stricter limits.
- `logging.event_log_path` should point to a durable local path.
- `logging.event_log_max_size` and `logging.event_log_max_files` should be set.
- `logging.timezone` should be set to the operator's preferred log timezone,
  for example `Africa/Nairobi`.

Do not use `backend: memory` for production rate limiting. It is only for local
development and single-process demos.

Validate the config:

```bash
cargo run -- test-config --config configs/saugra.production.example.yml
```

Run Saugra:

```bash
cargo run -- run --config configs/saugra.production.example.yml
```

On a server, prefer the systemd service:

```bash
systemctl restart saugra
journalctl -u saugra -f
```

## Nginx

Use:

```bash
configs/nginx.production.example.conf
```

Install it as a site config, adjust `server_name`, and reload Nginx. The public
server forwards all application traffic to Saugra at `127.0.0.1:8787`.

## Apache

Use:

```bash
configs/apache.production.example.conf
```

Enable required modules before using the reverse-proxy config:

```bash
a2enmod proxy proxy_http headers
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
cargo run -- logs tail --config configs/saugra.production.example.yml --limit 20
```

Explain a request:

```bash
cargo run -- explain <request-id> --config configs/saugra.production.example.yml
```

## Safe First Rollout

1. Start Redis and confirm Saugra can connect to it.
2. Create the event log directory and assign it to the Saugra service user.
3. Start Saugra with `server.mode: monitor`.
4. Put Nginx or Apache in front of Saugra.
5. Send normal traffic and confirm it reaches the backend.
6. Send attack-shaped test requests and confirm they appear in `logs tail`.
7. Review explanations for matched requests with `explain <request-id>`.
8. Tune route limits and rule exclusions for false positives.
9. Switch to `server.mode: block` during a low-traffic window.
10. Keep watching `logs tail` after block mode is enabled.

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

## Upgrade From Source

Until packaged releases exist, upgrade by rebuilding from Git and restarting the
service:

```bash
cd /opt/saugra-src
git pull
cargo build --release
install -m 0755 target/release/saugra /usr/local/bin/saugra
saugra test-config --config /etc/saugra/saugra.yml
systemctl restart saugra
```
