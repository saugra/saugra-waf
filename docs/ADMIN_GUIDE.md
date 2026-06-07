# Saugra Admin Guide

This guide is the day-to-day operator runbook for installed Saugra servers. It
covers service checks, common commands, troubleshooting, runtime allowlisting,
runtime blocking, logs, and explanations.

## Config Discovery

Commands that need configuration choose it in this order:

1. An explicit `--config <path>` argument.
2. The `SAUGRA_WAF_CONFIG` environment variable.
3. The installed config at `/etc/saugra-waf/saugra-waf.yml`.
4. The source-checkout config at `configs/saugra-waf.example.yml`.

Installed deployments can normally omit `--config`. Use the flag or environment
variable when the active config lives elsewhere.

## Service Basics

Check the installed binary:

```bash
saugra-waf --help
```

Validate the active config:

```bash
saugra-waf test-config
```

Start or restart Saugra:

```bash
systemctl enable --now saugra-waf
systemctl restart saugra-waf
systemctl status saugra-waf --no-pager
```

Watch service logs:

```bash
journalctl -u saugra-waf -f
```

Check the local health endpoint:

```bash
curl -i http://127.0.0.1:8787/_saugra-waf/health
```

## Backend Checks

If the browser shows:

```json
{
  "error": "upstream request failed"
}
```

Saugra is running, but it cannot reach the configured backend.

Check the configured upstreams:

```bash
grep -A12 -n "upstreams:" /etc/saugra-waf/saugra-waf.yml
grep -A8 -n "routes:" /etc/saugra-waf/saugra-waf.yml
```

Check what is listening:

```bash
ss -ltnp
```

Test the backend directly:

```bash
curl -i -H "Host: example.com" http://127.0.0.1:8000/
```

Test through Saugra:

```bash
curl -i -H "Host: example.com" http://127.0.0.1:8787/
```

If the backend direct test fails, start or fix the application service before
debugging Saugra.

## Logs And Explanations

Tail recent security events:

```bash
saugra-waf logs tail --limit 20
```

Summarize recent security events:

```bash
saugra-waf logs summary --limit 200
```

Explain a denied or monitored request:

```bash
saugra-waf explain <request-id>
```

The explanation output includes the request context before the rule analysis:

```txt
Request ID: 40651a2b-057e-41da-a740-23e488ed5752
Client IP: 203.0.113.10
Request: GET /meetings/
```

The browser block response uses `reference` as the request ID:

```json
{
  "message": "Denied",
  "reference": "40651a2b-057e-41da-a740-23e488ed5752"
}
```

Use that value with the production config:

```bash
saugra-waf explain 40651a2b-057e-41da-a740-23e488ed5752 --config /etc/saugra-waf/saugra-waf.yml
```

## Safe Rollout

Start production traffic in monitor mode:

```yaml
server:
  mode: monitor

behavior:
  mode: monitor

bot_protection:
  mode: monitor
```

Then:

```bash
saugra-waf test-config --config /etc/saugra-waf/saugra-waf.yml
systemctl restart saugra-waf
```

Review logs and explanations before switching to `block`.

## Runtime Allowlisting

Runtime allowlisting changes `/var/lib/saugra-waf/runtime-policy.json`. Saugra
reloads this file while running, so these commands do not require a Saugra
restart.

Allow a single IP for the default duration:

```bash
saugra-waf allowlist add ip 203.0.113.10 --reason "admin testing" --config /etc/saugra-waf/saugra-waf.yml
```

Allow a single IP for two hours:

```bash
saugra-waf allowlist add ip 203.0.113.10 --duration 2h --reason "admin testing" --config /etc/saugra-waf/saugra-waf.yml
```

Allow an office CIDR for 30 minutes:

```bash
saugra-waf allowlist add cidr 203.0.113.0/24 --duration 30m --reason "office NAT" --config /etc/saugra-waf/saugra-waf.yml
```

List runtime policy entries:

```bash
saugra-waf allowlist list --config /etc/saugra-waf/saugra-waf.yml
```

Remove an entry by ID:

```bash
saugra-waf allowlist remove <entry-id> --config /etc/saugra-waf/saugra-waf.yml
```

Remove expired entries:

```bash
saugra-waf allowlist prune --config /etc/saugra-waf/saugra-waf.yml
```

Runtime allowlist behavior is controlled by:

```yaml
runtime_policy:
  enabled: true
  path: /var/lib/saugra-waf/runtime-policy.json
  reload_interval: 5s
  default_duration: 2h
  allowlist_effect: skip_bot_and_behavior_block
```

Supported `allowlist_effect` values:

- `skip_bot_and_behavior_block`: bypass bot and behavior blocks only.
- `monitor_all`: downgrade deterministic WAF, bot, and behavior findings to
  monitor for the matching IP.
- `allow_all`: bypass all blocking for the matching IP. Use only for short,
  trusted emergency windows.

## Runtime Blocking

Runtime blocking also reloads without restarting Saugra.

Block an IP for two hours:

```bash
saugra-waf allowlist block add 198.51.100.44 --duration 2h --reason "active scanner" --config /etc/saugra-waf/saugra-waf.yml
```

Block a CIDR:

```bash
saugra-waf allowlist block add 198.51.100.0/24 --duration 30m --reason "scanner burst" --config /etc/saugra-waf/saugra-waf.yml
```

Use `saugra-waf allowlist list` to find the entry ID, then remove it with:

```bash
saugra-waf allowlist remove <entry-id> --config /etc/saugra-waf/saugra-waf.yml
```

## Local State Reset

When a single trusted client accumulates behavior or bot state during rollout,
reset only that client instead of deleting the full state file:

```bash
saugra-waf state reset behavior 203.0.113.10 --config /etc/saugra-waf/saugra-waf.yml
saugra-waf state reset bot 203.0.113.10 --config /etc/saugra-waf/saugra-waf.yml
```

This is for local behavior and bot-protection state. It does not remove durable
security events from `/var/log/saugra-waf/saugra-waf-events.jsonl`.

## Security Summaries

Generate a local summary over the configured lookback window and print JSON:

```bash
saugra-waf summary daily --config /etc/saugra-waf/saugra-waf.yml
```

Write the summary through configured delivery channels:

```bash
saugra-waf summary send --config /etc/saugra-waf/saugra-waf.yml
```

The stable default is file output:

```yaml
security_summary:
  enabled: true
  schedule: daily
  send_time: "08:00"
  timezone: Africa/Nairobi
  lookback: 24h
  output_path: /var/log/saugra-waf/saugra-waf-security-summary-YYYY-MM-DD.json
  channels:
    - type: file
```

`YYYY-MM-DD` is replaced using the configured summary timezone. Email delivery
uses a local sendmail-compatible command when configured. Email summaries are
sent as a formatted HTML body with a plain-text fallback; the local file output
remains JSON for automation and archiving.

```yaml
security_summary:
  channels:
    - type: file
    - type: email
      from: saugra-waf@example.com
      to:
        - security@example.com
      sendmail_path: /usr/sbin/sendmail
```

To schedule summaries with systemd, create a oneshot service:

```ini
[Unit]
Description=Saugra daily security summary

[Service]
Type=oneshot
ExecStart=/usr/bin/saugra-waf summary send --config /etc/saugra-waf/saugra-waf.yml
User=saugra-waf
Group=saugra-waf
```

Then create a timer:

```ini
[Unit]
Description=Run Saugra daily security summary

[Timer]
OnCalendar=*-*-* 08:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable it with:

```bash
systemctl enable --now saugra-waf-summary.timer
systemctl list-timers --all | grep saugra-waf-summary
```

Summary delivery failures are visible in `journalctl -u saugra-waf-summary.service`
or in the terminal when running `saugra-waf summary send` manually. Saugra also
records local summary admin events next to the configured output path:

```bash
tail -n 20 /var/log/saugra-waf/saugra-waf-security-summary-admin-events.jsonl
```

## Storage Cleanup

Saugra can remove stale generated files so `/var/log/saugra-waf` and report
directories do not grow forever. Event logs already rotate with
`logging.event_log_max_size` and `logging.event_log_max_files`; storage cleanup
is for generated summary files, summary admin events, and explicit report
directories you opt in.

Start with a dry run:

```bash
saugra-waf cleanup run --dry-run --config /etc/saugra-waf/saugra-waf.yml
```

After reviewing the JSON report, allow deletion:

```bash
saugra-waf cleanup run --execute --config /etc/saugra-waf/saugra-waf.yml
```

Example policy:

```yaml
storage_cleanup:
  enabled: true
  schedule: daily
  run_time: "02:30"
  dry_run: true
  targets:
    - name: security summary files
      directory: /var/log/saugra-waf
      filename_prefix: saugra-waf-security-summary-
      filename_suffix: .json
      older_than: 90d
    - name: summary admin events
      directory: /var/log/saugra-waf
      filename_prefix: saugra-waf-security-summary-admin-events
      filename_suffix: .jsonl
      older_than: 180d
```

Cleanup only scans the configured target directories, only considers regular
files matching the prefix/suffix pattern, and skips directories and symlinks.
For report cleanup, use predictable file names and narrow patterns:

```yaml
storage_cleanup:
  targets:
    - name: dependency scan reports
      directory: /var/lib/saugra-waf/reports
      filename_prefix: dependency-scan-
      filename_suffix: .json
      older_than: 90d
```

To schedule cleanup with systemd, create a oneshot service:

```ini
[Unit]
Description=Saugra stale file cleanup

[Service]
Type=oneshot
ExecStart=/usr/bin/saugra-waf cleanup run --execute --config /etc/saugra-waf/saugra-waf.yml
User=saugra-waf
Group=saugra-waf
```

Then create a timer:

```ini
[Unit]
Description=Run Saugra stale file cleanup

[Timer]
OnCalendar=*-*-* 02:30:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable it with:

```bash
systemctl enable --now saugra-waf-cleanup.timer
systemctl list-timers --all | grep saugra-waf-cleanup
```

## Incident Workflows

Use these workflows during production triage. Prefer short-lived runtime policy
changes first, then make config or rule-pack changes after the incident is
understood.

### False Positive Blocks

1. Get the request reference from the block response or recent event logs.
2. Explain the decision:

```bash
saugra-waf explain <request-id> --config /etc/saugra-waf/saugra-waf.yml
```

3. If the finding is bot or behavior scoring, add a short runtime allowlist
   entry for the affected trusted IP:

```bash
saugra-waf allowlist add ip 203.0.113.10 --duration 2h --reason "false positive triage" --config /etc/saugra-waf/saugra-waf.yml
```

4. If a deterministic rule is noisy for a valid route or parameter, keep the
   server in monitor mode or add a scoped `rules.exclusions` entry after review.
5. Validate and restart only when changing YAML config:

```bash
saugra-waf test-config --config /etc/saugra-waf/saugra-waf.yml
systemctl restart saugra-waf
```

### Forwarded Protocol Findings

If events show `insecure_forwarded_proto`, confirm the request reached Saugra
through a configured trusted proxy and that the proxy sends the expected
protocol header:

```yaml
forwarded_headers:
  trusted_proxies:
    - 127.0.0.1/32
  proto_header: X-Forwarded-Proto
  expected_proto: https
```

For TLS-terminating Nginx, set the HTTPS server block to send
`X-Forwarded-Proto: https`. After fixing the proxy, reset the affected bot state
or wait for `bot_protection.score_window` to expire:

```bash
saugra-waf state reset bot 203.0.113.10 --config /etc/saugra-waf/saugra-waf.yml
```

### Scanner Bursts

1. Summarize recent events and identify top IPs, paths, and rule IDs:

```bash
saugra-waf logs summary --config /etc/saugra-waf/saugra-waf.yml --limit 500
```

2. Explain a representative blocked or monitored request:

```bash
saugra-waf explain <request-id> --config /etc/saugra-waf/saugra-waf.yml
```

3. Temporarily block clear abusive IPs or CIDRs:

```bash
saugra-waf allowlist block add 198.51.100.44 --duration 2h --reason "scanner burst" --config /etc/saugra-waf/saugra-waf.yml
```

4. Check route-specific rate limits for login, signup, search, and expensive
   API endpoints. Keep broader blocking changes in monitor mode until reviewed.

### Upstream Outages

1. Confirm Saugra is alive:

```bash
curl -i http://127.0.0.1:8787/_saugra-waf/health
```

2. Test the configured backend directly:

```bash
curl -i -H "Host: example.com" http://127.0.0.1:8000/
```

3. Check the application process and listening ports:

```bash
systemctl status YOUR_APP_SERVICE --no-pager
ss -ltnp
```

4. If the backend works directly but fails through Saugra, check `upstreams`,
   `routes`, and recent Saugra logs.

### Redis Outages

1. Check Redis and restart it if needed:

```bash
systemctl status redis-server --no-pager
systemctl restart redis-server
```

2. Restart Saugra after Redis is reachable so the Redis rate-limit store can
   reconnect cleanly:

```bash
systemctl restart saugra-waf
```

3. Watch for rate-limit backend errors:

```bash
journalctl -u saugra-waf -f
```

Do not switch production rate limiting to `memory` as a permanent fix. Memory
state resets on restart and does not coordinate across multiple Saugra
instances.

### WebSocket Routing Failures

1. Confirm the public proxy routes `/ws/` through Saugra if Saugra should
   inspect WebSocket handshakes.
2. Confirm the Saugra route points `/ws/` to the WebSocket upstream.
3. Check `websocket.allowed_origins` and `websocket.allowed_hosts` against the
   browser's public `Origin` and `Host` headers.
4. Tail events and explain a monitored or blocked handshake:

```bash
saugra-waf logs tail --config /etc/saugra-waf/saugra-waf.yml --limit 20
saugra-waf explain <request-id> --config /etc/saugra-waf/saugra-waf.yml
```

5. For Nginx, preserve upgrade headers:

```nginx
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $saugra_waf_connection_upgrade;
```

## Common Problems

### Browser Shows Denied

Run:

```bash
saugra-waf explain <reference> --config /etc/saugra-waf/saugra-waf.yml
```

If the reason is bot or behavior scoring during rollout, add a short-lived
runtime allowlist entry or switch bot/behavior back to monitor mode.

### Admin IP Is Temporarily Blocked

Add your public IP:

```bash
saugra-waf allowlist add ip YOUR_PUBLIC_IP --duration 2h --reason "admin recovery" --config /etc/saugra-waf/saugra-waf.yml
```

If deterministic WAF rules are also blocking your verification traffic, set:

```yaml
runtime_policy:
  allowlist_effect: monitor_all
```

Then validate and restart once for the config change:

```bash
saugra-waf test-config --config /etc/saugra-waf/saugra-waf.yml
systemctl restart saugra-waf
```

The allowlist entries themselves still reload without restart after that.

### Config Is Valid But Site Fails

Test in this order:

```bash
saugra-waf test-config --config /etc/saugra-waf/saugra-waf.yml
curl -i http://127.0.0.1:8787/_saugra-waf/health
curl -i -H "Host: example.com" http://127.0.0.1:8000/
curl -i -H "Host: example.com" http://127.0.0.1:8787/
journalctl -u saugra-waf -n 100 --no-pager
```

If direct backend traffic fails, fix the app service. If direct backend traffic
works but Saugra fails, inspect Saugra logs and the upstream target in
`/etc/saugra-waf/saugra-waf.yml`.

### Redis Problems

Production configs normally use Redis-backed rate limiting:

```bash
systemctl status redis-server --no-pager
systemctl restart redis-server
saugra-waf test-config --config /etc/saugra-waf/saugra-waf.yml
systemctl restart saugra-waf
```

## Useful Files

- `/etc/saugra-waf/saugra-waf.yml`: active config
- `/etc/saugra-waf/rules/`: active rule packs
- `/var/lib/saugra-waf/runtime-policy.json`: runtime allow/block policy
- `/var/lib/saugra-waf/saugra-waf-behavior-state.json`: local behavior state
- `/var/lib/saugra-waf/saugra-waf-bot-state.json`: local bot protection state
- `/var/log/saugra-waf/saugra-waf-events.jsonl`: security events
