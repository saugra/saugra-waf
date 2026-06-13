# Quick Start

This guide configures one backend application and starts Saugra in monitor
mode. Keep Saugra and the backend on private interfaces; place Nginx or Apache
in front before accepting public traffic.

## Configure an Upstream

Open `/etc/saugra-waf/saugra-waf.yml` and set the public host and local backend:

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

Keep the WAF, behavior, and bot protection modes set to `monitor` during the
initial rollout. Configure Redis before relying on rate limiting in production.

## Validate and Start

```bash
sudo saugra-waf test-config
sudo systemctl enable --now redis-server
sudo systemctl enable --now saugra-waf
sudo systemctl status saugra-waf --no-pager
```

If your configuration is outside the installed default path, pass
`--config <path>` or set `SAUGRA_WAF_CONFIG`.

## Verify Request Forwarding

Check the local health endpoint:

```bash
curl -i http://127.0.0.1:8787/_saugra-waf/health
```

Send a normal request using the configured host:

```bash
curl -i -H "Host: example.com" http://127.0.0.1:8787/
```

Send a suspicious request while still in monitor mode:

```bash
curl -i -H "Host: example.com" \
  "http://127.0.0.1:8787/search?q=%27%20OR%201%3D1--"
```

Review the resulting security events:

```bash
saugra-waf logs tail --limit 20
```

Use a request ID from an event to inspect the decision:

```bash
saugra-waf explain <request-id>
```

Request IDs are retained with their security events. By default, Saugra reads
the active event log and ten rotated files of up to 100 MB each. Retention is
volume-based rather than a fixed number of days, so high-traffic deployments
should size and archive event storage according to their audit requirements.

## Put a Public Proxy in Front

The recommended production request path is:

```txt
Internet -> Nginx or Apache -> 127.0.0.1:8787 -> backend
```

Use the supplied Nginx or Apache examples and review trusted proxy settings
before forwarding client IP headers. The
[production deployment guide](../PRODUCTION_DEPLOYMENT.md) covers TLS,
WebSockets, forwarded headers, smoke tests, and rollout checks.

## Move Toward Block Mode

Do not switch immediately. First:

1. Observe representative normal traffic in monitor mode.
2. Review matched rules, bot scores, behavior scores, and rate-limit events.
3. Add narrow exclusions or allowlist entries for confirmed false positives.
4. Verify event retention and the `explain` workflow.
5. Enable block mode during a controlled deployment window.

See [Safe Rollout](../ADMIN_GUIDE.md#safe-rollout) for the operator workflow.
