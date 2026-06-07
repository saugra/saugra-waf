# How to Install and Configure Saugra WAF on Ubuntu with Nginx

**Subtitle:** Put a monitor-first, self-hosted web application firewall in front
of an existing application using Saugra, Redis, and Nginx.

**Suggested Hashnode tags:** `web-security`, `nginx`, `ubuntu`, `rust`, `devops`

**Cover image text:** Protect an Ubuntu Web App with Saugra WAF

Web applications exposed to the internet are routinely tested by scanners,
bots, and automated attack tools. Secure application code remains essential,
but an additional inspection layer can help detect suspicious requests, rate
limit abuse, and provide useful evidence during an incident.

In this tutorial, we will install Saugra WAF on Ubuntu or Debian and place it
between Nginx and an existing backend application:

```text
Internet -> Nginx -> Saugra WAF -> Application
```

We will begin in `monitor` mode. Suspicious requests will be recorded without
being blocked, giving us time to check normal traffic and tune false positives.
Only after verification will we enable blocking.

> A WAF is an additional protection layer, not a replacement for secure
> application development, authentication, patching, or careful infrastructure
> configuration.

## What You Will Need

Before starting, you should have:

- An Ubuntu or Debian server
- Root or `sudo` access
- A backend application listening on a private address such as
  `127.0.0.1:8000`
- A domain name pointing to the server
- Nginx installed or permission to install it

The examples use `example.com` as the public domain and
`http://127.0.0.1:8000` as the backend. Replace both values with your real
deployment details.

## 1. Install Saugra, Nginx, and Redis

Install the tools needed to add the signed Saugra APT repository:

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg nginx redis-server
```

Download the Saugra repository signing key:

```bash
curl -fsSL https://saugra.github.io/saugra-waf/saugra-waf.gpg |
  sudo gpg --dearmor --yes -o /usr/share/keyrings/saugra-waf.gpg
```

Add the signed repository:

```bash
echo "deb [signed-by=/usr/share/keyrings/saugra-waf.gpg] https://saugra.github.io/saugra-waf/apt stable main" |
  sudo tee /etc/apt/sources.list.d/saugra-waf.list
```

Install Saugra:

```bash
sudo apt update
sudo apt install -y saugra-waf
```

Confirm that the CLI is available:

```bash
saugra-waf --version
saugra-waf --help
```

The package installs the main configuration at:

```text
/etc/saugra-waf/saugra-waf.yml
```

It also installs the systemd service, rule packs, standards data, and the
directories used for durable security events and runtime state.

## 2. Configure the Protected Application

Open the Saugra configuration:

```bash
sudo editor /etc/saugra-waf/saugra-waf.yml
```

Find the `server`, `upstreams`, and `routes` sections and configure them for
your application:

```yaml
server:
  listen: 127.0.0.1:8787
  mode: monitor

upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000

routes:
  - path_prefix: /
    upstream: app
```

There are three important details here:

1. Saugra listens only on `127.0.0.1`, so it is not directly exposed to the
   internet.
2. The upstream `host` matches the public HTTP `Host` header.
3. The initial mode is `monitor`, not `block`.

Keep production rate limiting backed by Redis:

```yaml
security:
  max_body_size: 2mb
  enable_rate_limiting: true
  block_suspicious_user_agents: true
  inspect_json_body: true

rate_limit:
  backend: redis
  redis_url: redis://127.0.0.1:6379
  requests_per_minute: 120
  burst: 30
  routes:
    - path: /login
      requests_per_minute: 10
      burst: 5
```

Redis allows rate-limit state to survive Saugra restarts and be shared by
multiple Saugra instances. The in-memory backend is suitable for local
experiments, but it is not a production rate-limiting backend.

Check the event-log configuration as well:

```yaml
logging:
  format: json
  level: info
  event_log_path: /var/log/saugra-waf/saugra-waf-events.jsonl
  event_log_max_size: 100mb
  event_log_max_files: 10
  timezone: Africa/Nairobi
```

Change the timezone to the one your operators use. Avoid storing security
events only in standard output; the JSONL event log supports later review and
request explanations.

## 3. Validate the Configuration

Validate the YAML before restarting anything:

```bash
sudo saugra-waf test-config \
  --config /etc/saugra-waf/saugra-waf.yml
```

If validation fails, Saugra reports the configuration field that needs
attention. Fix the error and run the command again before continuing.

You can also inspect the loaded rules:

```bash
sudo saugra-waf rules list \
  --config /etc/saugra-waf/saugra-waf.yml
```

## 4. Start Redis and Saugra

Enable and start both services:

```bash
sudo systemctl enable --now redis-server
sudo systemctl enable --now saugra-waf
```

Check the Saugra service:

```bash
sudo systemctl status saugra-waf
```

If it does not start, inspect its service logs:

```bash
sudo journalctl -u saugra-waf -n 100 --no-pager
```

Test Saugra locally before changing Nginx:

```bash
curl -i http://127.0.0.1:8787/_saugra-waf/health
curl -i -H "Host: example.com" http://127.0.0.1:8787/
```

The health request confirms that Saugra is running. The second request confirms
that it can match the public host and forward traffic to the backend.

## 5. Put Nginx in Front of Saugra

Create an Nginx site:

```bash
sudo editor /etc/nginx/sites-available/example.com
```

Add this configuration:

```nginx
map $http_upgrade $saugra_waf_connection_upgrade {
    default upgrade;
    '' close;
}

server {
    listen 80;
    server_name example.com;

    client_max_body_size 2m;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $saugra_waf_connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;

        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        proxy_buffering off;
    }

    location = /_saugra-waf/health {
        allow 127.0.0.1;
        deny all;
        proxy_pass http://127.0.0.1:8787;
    }
}
```

This keeps the Saugra health endpoint unavailable to remote clients and
preserves the headers Saugra needs to identify the original client and request
scheme.

Enable the site, validate Nginx, and reload it:

```bash
sudo ln -s /etc/nginx/sites-available/example.com \
  /etc/nginx/sites-enabled/example.com
sudo nginx -t
sudo systemctl reload nginx
```

For a real internet deployment, terminate TLS in a `443` server block and make
sure Nginx sends `X-Forwarded-Proto: https`. Do not expose Saugra's port `8787`
directly to the internet.

## 6. Verify Normal and Suspicious Traffic

First, verify normal traffic through Nginx:

```bash
curl -i http://example.com/
```

Then send a harmless test request containing an SQL-injection-style query:

```bash
curl -i --get http://example.com/search \
  --data-urlencode "q=' OR 1=1--"
```

Because Saugra is in `monitor` mode, it should record the suspicious request
but continue forwarding it. This is intentional during the initial rollout.

Read recent security events:

```bash
sudo saugra-waf logs tail \
  --config /etc/saugra-waf/saugra-waf.yml \
  --limit 20
```

The structured event includes the request ID, action, matched rules, severity,
risk score, and explanation. Copy a request ID from the output and ask Saugra
to explain it:

```bash
sudo saugra-waf explain REQUEST_ID \
  --config /etc/saugra-waf/saugra-waf.yml
```

You can also summarize recent events:

```bash
sudo saugra-waf logs summary \
  --config /etc/saugra-waf/saugra-waf.yml \
  --limit 200
```

## 7. Tune Before Enabling Blocking

Leave Saugra in monitor mode while representative production traffic passes
through it. Review:

- Rules triggered by legitimate application requests
- Login, API, upload, and WebSocket routes
- Request body limits
- Route-specific rate limits
- Trusted proxy and forwarded-header settings
- Bot and behavior score thresholds

Do not disable an entire protection category to fix one false positive. Prefer
a narrow exclusion for the affected rule, path, and parameter.

For example:

```yaml
rules:
  exclusions:
    - name: Allow HTML in article previews
      rule_ids:
        - SAUGRA-XSS-001
      path_prefixes:
        - /api/articles
      query_params:
        - content
```

Validate and restart Saugra after configuration changes:

```bash
sudo saugra-waf test-config \
  --config /etc/saugra-waf/saugra-waf.yml
sudo systemctl restart saugra-waf
```

## 8. Enable Block Mode

After normal traffic has been reviewed and false positives have been tuned,
change the mode:

```yaml
server:
  listen: 127.0.0.1:8787
  mode: block
```

Validate and restart:

```bash
sudo saugra-waf test-config \
  --config /etc/saugra-waf/saugra-waf.yml
sudo systemctl restart saugra-waf
sudo systemctl status saugra-waf
```

Repeat the SQL injection test:

```bash
curl -i --get http://example.com/search \
  --data-urlencode "q=' OR 1=1--"
```

A blocking-eligible request that reaches the configured anomaly threshold
should now be rejected and recorded as a security event. Confirm the decision:

```bash
sudo saugra-waf logs tail \
  --config /etc/saugra-waf/saugra-waf.yml \
  --limit 20
```

## What We Built

The application now has a layered request path:

```text
Client
  -> Nginx for public HTTP/TLS
  -> Saugra for inspection, scoring, rate limiting, and security events
  -> Backend application
```

The important production choices are:

- Saugra remains private on `127.0.0.1`
- New deployments begin in monitor mode
- Redis provides production rate-limit state
- Security events are retained in a rotating JSONL store
- Blocking decisions come from deterministic rules and explicit thresholds
- Explanations help operators understand and tune decisions

Next, we will configure application-specific protection for login routes,
uploads, APIs, and WebSockets, then review how to respond to a blocked request
using Saugra's event logs and explanation command.

## Project Links

- GitHub: [github.com/saugra/saugra-waf](https://github.com/saugra/saugra-waf)
- Production deployment guide:
  [docs/PRODUCTION_DEPLOYMENT.md](https://github.com/saugra/saugra-waf/blob/main/docs/PRODUCTION_DEPLOYMENT.md)
- Administration guide:
  [docs/ADMIN_GUIDE.md](https://github.com/saugra/saugra-waf/blob/main/docs/ADMIN_GUIDE.md)

