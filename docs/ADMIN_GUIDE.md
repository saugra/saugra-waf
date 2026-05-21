# Saugra Admin Guide

This guide is the day-to-day operator runbook for installed Saugra servers. It
covers service checks, common commands, troubleshooting, runtime allowlisting,
runtime blocking, logs, and explanations.

## Service Basics

Check the installed binary:

```bash
saugra --help
```

Validate the active config:

```bash
saugra test-config --config /etc/saugra/saugra.yml
```

Start or restart Saugra:

```bash
systemctl enable --now saugra
systemctl restart saugra
systemctl status saugra --no-pager
```

Watch service logs:

```bash
journalctl -u saugra -f
```

Check the local health endpoint:

```bash
curl -i http://127.0.0.1:8787/_saugra/health
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
grep -A12 -n "upstreams:" /etc/saugra/saugra.yml
grep -A8 -n "routes:" /etc/saugra/saugra.yml
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
saugra logs tail --config /etc/saugra/saugra.yml --limit 20
```

Summarize recent security events:

```bash
saugra logs summary --config /etc/saugra/saugra.yml --limit 200
```

Explain a denied or monitored request:

```bash
saugra explain <request-id> --config /etc/saugra/saugra.yml
```

The browser block response uses `reference` as the request ID:

```json
{
  "message": "Denied",
  "reference": "40651a2b-057e-41da-a740-23e488ed5752"
}
```

Use that value with `saugra explain`.

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
saugra test-config --config /etc/saugra/saugra.yml
systemctl restart saugra
```

Review logs and explanations before switching to `block`.

## Runtime Allowlisting

Runtime allowlisting changes `/var/lib/saugra/runtime-policy.json`. Saugra
reloads this file while running, so these commands do not require a Saugra
restart.

Allow a single IP for the default duration:

```bash
saugra allowlist add ip 203.0.113.10 --reason "admin testing" --config /etc/saugra/saugra.yml
```

Allow a single IP for two hours:

```bash
saugra allowlist add ip 203.0.113.10 --duration 2h --reason "admin testing" --config /etc/saugra/saugra.yml
```

Allow an office CIDR for 30 minutes:

```bash
saugra allowlist add cidr 203.0.113.0/24 --duration 30m --reason "office NAT" --config /etc/saugra/saugra.yml
```

List runtime policy entries:

```bash
saugra allowlist list --config /etc/saugra/saugra.yml
```

Remove an entry by ID:

```bash
saugra allowlist remove <entry-id> --config /etc/saugra/saugra.yml
```

Remove expired entries:

```bash
saugra allowlist prune --config /etc/saugra/saugra.yml
```

Runtime allowlist behavior is controlled by:

```yaml
runtime_policy:
  enabled: true
  path: /var/lib/saugra/runtime-policy.json
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
saugra allowlist block add 198.51.100.44 --duration 2h --reason "active scanner" --config /etc/saugra/saugra.yml
```

Block a CIDR:

```bash
saugra allowlist block add 198.51.100.0/24 --duration 30m --reason "scanner burst" --config /etc/saugra/saugra.yml
```

Use `saugra allowlist list` to find the entry ID, then remove it with:

```bash
saugra allowlist remove <entry-id> --config /etc/saugra/saugra.yml
```

## Common Problems

### Browser Shows Denied

Run:

```bash
saugra explain <reference> --config /etc/saugra/saugra.yml
```

If the reason is bot or behavior scoring during rollout, add a short-lived
runtime allowlist entry or switch bot/behavior back to monitor mode.

### Admin IP Is Temporarily Blocked

Add your public IP:

```bash
saugra allowlist add ip YOUR_PUBLIC_IP --duration 2h --reason "admin recovery" --config /etc/saugra/saugra.yml
```

If deterministic WAF rules are also blocking your verification traffic, set:

```yaml
runtime_policy:
  allowlist_effect: monitor_all
```

Then validate and restart once for the config change:

```bash
saugra test-config --config /etc/saugra/saugra.yml
systemctl restart saugra
```

The allowlist entries themselves still reload without restart after that.

### Config Is Valid But Site Fails

Test in this order:

```bash
saugra test-config --config /etc/saugra/saugra.yml
curl -i http://127.0.0.1:8787/_saugra/health
curl -i -H "Host: example.com" http://127.0.0.1:8000/
curl -i -H "Host: example.com" http://127.0.0.1:8787/
journalctl -u saugra -n 100 --no-pager
```

If direct backend traffic fails, fix the app service. If direct backend traffic
works but Saugra fails, inspect Saugra logs and the upstream target in
`/etc/saugra/saugra.yml`.

### Redis Problems

Production configs normally use Redis-backed rate limiting:

```bash
systemctl status redis-server --no-pager
systemctl restart redis-server
saugra test-config --config /etc/saugra/saugra.yml
systemctl restart saugra
```

## Useful Files

- `/etc/saugra/saugra.yml`: active config
- `/etc/saugra/rules/`: active rule packs
- `/var/lib/saugra/runtime-policy.json`: runtime allow/block policy
- `/var/lib/saugra/saugra-behavior-state.json`: local behavior state
- `/var/lib/saugra/saugra-bot-state.json`: local bot protection state
- `/var/log/saugra/saugra-events.jsonl`: security events
