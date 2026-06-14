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

Installed deployments should normally omit `--config`. The examples in this
guide use automatic discovery. Use the flag or environment variable only when
the active config lives elsewhere.

## Initial Installation

The recommended production installation path for Ubuntu and Debian is the
signed Saugra APT repository.

Install the repository tools and Redis:

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg redis-server
```

Install the Saugra repository signing key:

```bash
curl -fsSL https://saugra.github.io/saugra-waf/saugra-waf.gpg |
  sudo gpg --dearmor --yes -o /usr/share/keyrings/saugra-waf.gpg
```

Add the signed repository and install Saugra:

```bash
echo "deb [signed-by=/usr/share/keyrings/saugra-waf.gpg] https://saugra.github.io/saugra-waf/apt stable main" |
  sudo tee /etc/apt/sources.list.d/saugra-waf.list
sudo apt update
sudo apt install saugra-waf
```

The package installs the CLI, systemd service, monitor-first production config,
rule packs, standards, intelligence catalogs, Ollama model policy and evaluation
fixtures, and writable runtime directories.
Confirm the installation:

```bash
saugra-waf --version
systemctl list-unit-files saugra-waf.service
```

Edit `/etc/saugra-waf/saugra-waf.yml` before starting the service:

```bash
sudo editor /etc/saugra-waf/saugra-waf.yml
```

At minimum, replace the example host and target with the public host and local
backend application:

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

Keep `server.mode`, `behavior.mode`, and `bot_protection.mode` set to `monitor`
during the initial rollout. Also review `forwarded_headers.trusted_proxies`,
rate-limit routes, and the Redis connection settings for the deployment.

When model-backed AI explanations are enabled, install `llama-server` and keep
its API on loopback:

```bash
llama-server \
  -hf Qwen/Qwen3-0.6B-GGUF:Q8_0 \
  --alias saugra-qwen3-0.6b \
  --host 127.0.0.1 --port 8080 \
  --ctx-size 2048 --threads 1 --parallel 1 --jinja --no-webui
```

The model is optional, never blocks traffic, and falls back to the deterministic
explanation. The [AI explanations](#ai-explanations) section covers
installation, resource limits, and evaluation.

On a server with less than 2 GB RAM, use `ai.enabled: false` or
`ai.provider: local`. A 4 GB, 2-core shared server can start with Qwen3 0.6B Q8,
a 2048-token context, and one inference thread. See
the [AI explanations](#ai-explanations) section for sizing and remote adapters.

Validate the configuration, then start Redis and Saugra:

```bash
saugra-waf test-config
sudo systemctl enable --now redis-server
sudo systemctl enable --now saugra-waf
sudo systemctl status saugra-waf --no-pager
```

Verify the health endpoint and request forwarding. Replace `example.com` with
the configured upstream host:

```bash
curl -i http://127.0.0.1:8787/_saugra-waf/health
curl -i -H "Host: example.com" http://127.0.0.1:8787/
```

Finally, configure Nginx, Apache, or another trusted reverse proxy to send
public traffic to `127.0.0.1:8787`. Keep the backend application and Saugra
private; only the public reverse proxy should accept Internet traffic.

If startup or forwarding fails, inspect:

```bash
journalctl -u saugra-waf -n 100 --no-pager
ss -ltnp
```

## AI Explanations

AI is optional and explain-only. Rules, rate limits, behavior scoring,
unknown-threat policy, and campaign correlation remain authoritative.

For model-free operation:

```yaml
ai:
  enabled: false
  mode: explain_only
```

`saugra-waf explain <request-id>` still returns the deterministic explanation.
Use `provider: local` when a configured AI deployment needs an immediate
rollback without disabling its audit settings.

### Lightweight llama.cpp

The default model-backed provider is llama.cpp with Qwen3 0.6B Q8:

```bash
llama-server \
  -hf Qwen/Qwen3-0.6B-GGUF:Q8_0 \
  --alias saugra-qwen3-0.6b \
  --host 127.0.0.1 --port 8080 \
  --ctx-size 2048 --threads 1 --parallel 1 \
  --batch-size 128 --jinja --no-webui
```

```yaml
ai:
  enabled: true
  mode: explain_only
  provider: llama_cpp
  llama_cpp_url: http://127.0.0.1:8080
  model: saugra-qwen3-0.6b
  timeout: 60s
```

The package includes
`/usr/share/saugra-waf/llama-cpp/saugra-waf-llama-cpp.service` as an optional
hardened systemd example. Keep port `8080` private, do not enable llama.cpp
tools, and pre-populate the model cache for production.

| Shared host | Guidance |
| --- | --- |
| Less than 2 GB RAM | Use `enabled: false` or `provider: local`. |
| 2-3 GB RAM, 1-2 cores | Use Qwen3 0.6B Q8 with one thread for occasional explanations. |
| 4 GB RAM, 2 cores | Use Qwen3 0.6B Q8 with a 2048-token context. |
| 8 GB RAM or more | Use a larger model only after measured evaluation. |

### Ollama And Remote Providers

Ollama remains supported:

```yaml
ai:
  enabled: true
  provider: ollama
  ollama_url: http://127.0.0.1:11434
  model: qwen3:4b
```

OpenAI, Gemini, and internal gateways currently use the command adapter:

```yaml
ai:
  enabled: true
  provider: command
  command: /usr/local/bin/saugra-ai-adapter
  command_args: ["--provider", "openai"]
  model: operator-selected-model
```

Keep API credentials in the adapter environment or a secret store, never in
Saugra YAML or command arguments. Model input excludes query values, request
bodies, cookies, authorization data, client addresses, and upstream
credentials. Every failure falls back to the deterministic explanation.

Model-generated rules are untrusted drafts. Keep them outside active rule
directories, run `rules validate` and `rules replay`, require human approval,
and deploy accepted rules in monitor mode first.

## Upgrade To The Newest Version

The signed Saugra APT repository is the recommended upgrade path for Debian and
Ubuntu installations.

Check the currently installed version and the version available from APT:

```bash
saugra-waf --version
sudo apt update
apt-cache policy saugra-waf
```

Back up the active configuration before upgrading:

```bash
sudo cp -a /etc/saugra-waf "/etc/saugra-waf.backup-$(date +%Y%m%d-%H%M%S)"
```

Install the newest published version:

```bash
sudo apt install --only-upgrade saugra-waf
```

The package preserves operator-managed files under `/etc/saugra-waf` and does
not restart the service automatically. It places the newest bundled examples,
rules, standards, and intelligence catalogs under `/usr/share/saugra-waf`.
Review those files when the release notes mention configuration or rule-pack
changes.

Validate the existing configuration before restarting:

```bash
saugra-waf --version
saugra-waf test-config
sudo systemctl restart saugra-waf
sudo systemctl status saugra-waf --no-pager
curl -i http://127.0.0.1:8787/_saugra-waf/health
```

Review startup errors and recent security events after the upgrade:

```bash
journalctl -u saugra-waf -n 100 --no-pager
saugra-waf logs tail --limit 20
```

If the APT repository was not configured during installation, add the signing
key and repository first:

```bash
sudo apt install -y ca-certificates curl gnupg
curl -fsSL https://saugra.github.io/saugra-waf/saugra-waf.gpg |
  sudo gpg --dearmor --yes -o /usr/share/keyrings/saugra-waf.gpg
echo "deb [signed-by=/usr/share/keyrings/saugra-waf.gpg] https://saugra.github.io/saugra-waf/apt stable main" |
  sudo tee /etc/apt/sources.list.d/saugra-waf.list
sudo apt update
sudo apt install saugra-waf
```

As a fallback, download the newest `.deb` from the
[GitHub Releases page](https://github.com/saugra/saugra-waf/releases/latest)
and install it with `apt` so dependencies are handled:

```bash
sudo apt install ./saugra-waf_<version>-1_amd64.deb
saugra-waf test-config
sudo systemctl restart saugra-waf
```

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
saugra-waf explain 40651a2b-057e-41da-a740-23e488ed5752
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
saugra-waf test-config
systemctl restart saugra-waf
```

Review logs and explanations before switching to `block`.

## Runtime Allowlisting

Runtime allowlisting changes `/var/lib/saugra-waf/runtime-policy.json`. Saugra
reloads this file while running, so these commands do not require a Saugra
restart.

Allow a single IP for the default duration:

```bash
saugra-waf allowlist add ip 203.0.113.10 --reason "admin testing"
```

Allow a single IP for two hours:

```bash
saugra-waf allowlist add ip 203.0.113.10 --duration 2h --reason "admin testing"
```

Allow an office CIDR for 30 minutes:

```bash
saugra-waf allowlist add cidr 203.0.113.0/24 --duration 30m --reason "office NAT"
```

List runtime policy entries:

```bash
saugra-waf allowlist list
```

Remove an entry by ID:

```bash
saugra-waf allowlist remove <entry-id>
```

Remove expired entries:

```bash
saugra-waf allowlist prune
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
saugra-waf allowlist block add 198.51.100.44 --duration 2h --reason "active scanner"
```

Block a CIDR:

```bash
saugra-waf allowlist block add 198.51.100.0/24 --duration 30m --reason "scanner burst"
```

Use `saugra-waf allowlist list` to find the entry ID, then remove it with:

```bash
saugra-waf allowlist remove <entry-id>
```

## Local State Reset

When a single trusted client accumulates behavior or bot state during rollout,
reset only that client instead of deleting the full state file:

```bash
saugra-waf state reset behavior 203.0.113.10
saugra-waf state reset bot 203.0.113.10
```

This is for local behavior and bot-protection state. It does not remove durable
security events from `/var/log/saugra-waf/saugra-waf-events.jsonl`.

## Security Summaries

Generate a local summary over the configured lookback window and print JSON:

```bash
saugra-waf summary daily
```

Write the summary through configured delivery channels:

```bash
saugra-waf summary send
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
ExecStart=/usr/bin/saugra-waf summary send
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

Saugra can remove stale generated files and expired local unknown-threat route
baselines so `/var/log/saugra-waf`, `/var/lib/saugra-waf`, and report
directories do not grow forever. Event logs already rotate with
`logging.event_log_max_size` and `logging.event_log_max_files`; file cleanup is
for generated summary files, summary admin events, and explicit report
directories you opt in. Baseline cleanup uses `unknown_threats.retention`.

Request IDs remain available to `saugra-waf explain <request-id>` only while
their security events remain in the active or retained rotated event logs.
Retention is volume-based, not time-based. With the shipped `100mb` size and
`10` rotated-file settings, Saugra retains one active file plus ten rotated
files, for an approximate 1.1 GB ceiling. A busy deployment can therefore lose
old request IDs sooner than a quiet deployment. There is currently no
day-based event-retention setting.

Start with a dry run:

```bash
saugra-waf cleanup run --dry-run
```

After reviewing the JSON report, allow deletion:

```bash
saugra-waf cleanup run --execute
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
For local unknown-threat state, the JSON report includes route counts before
and after cleanup. Dry runs do not modify either files or baseline state.

The proxy and cleanup command coordinate local baseline access with the same
lock and atomic file replacement, so the systemd timer can run while Saugra is
serving traffic.

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
ExecStart=/usr/bin/saugra-waf cleanup run --execute
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

## Unknown-Threat Rollout

Keep unknown-threat policy in `monitor` while the route baselines warm up. Move
to `shadow` only after expected application routes have stable traffic:

```yaml
unknown_threats:
  enabled: true
  mode: shadow
  shadow_review_completed: false
```

Review retained candidates:

```bash
saugra-waf unknown-threats report --limit 1000
saugra-waf explain <sample-request-id>
```

The report highlights would-block volume, gated candidates, single-signal
pressure, new-baseline pressure, top route shapes, and sample request IDs.
Treat these as false-positive review candidates; the report does not claim to
know whether application-specific traffic is legitimate.

Only explicitly configured high-risk routes are eligible for blocking. After
review and tuning, acknowledge the shadow review:

```yaml
server:
  mode: block

unknown_threats:
  mode: block
  shadow_review_completed: true
  routes:
    - path: /admin
      high_risk: true
      block_threshold: 40
```

Saugra still requires the configured baseline age, observation volume, score,
and independent-signal count. Removing `high_risk: true` immediately returns a
route to monitor-only behavior.

## Incident Workflows

Use these workflows during production triage. Prefer short-lived runtime policy
changes first, then make config or rule-pack changes after the incident is
understood.

### False Positive Blocks

1. Get the request reference from the block response or recent event logs.
2. Explain the decision:

```bash
saugra-waf explain <request-id>
```

3. If the finding is bot or behavior scoring, add a short runtime allowlist
   entry for the affected trusted IP:

```bash
saugra-waf allowlist add ip 203.0.113.10 --duration 2h --reason "false positive triage"
```

4. Reset accumulated bot and behavior state after confirming the traffic is
   legitimate:

```bash
saugra-waf state reset bot 203.0.113.10
saugra-waf state reset behavior 203.0.113.10
```

5. If a legitimate application route overlaps a scanner-path entry, add narrow
   path exclusions:

```yaml
behavior:
  probe_path_exclusions:
    - /admin

bot_protection:
  scanner_path_exclusions:
    - /admin
```

   Keep specific high-confidence paths such as `/wp-admin`, `/phpmyadmin`, and
   `/adminer.php`. The bundled catalog intentionally does not classify the
   generic `/admin` prefix as a scanner path.
6. If a deterministic rule is noisy for a valid route or parameter, keep the
   server in monitor mode or add a scoped `rules.exclusions` entry after review.
7. Validate and restart only when changing YAML config:

```bash
saugra-waf test-config
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
saugra-waf state reset bot 203.0.113.10
```

### Scanner Bursts

1. Summarize recent events and identify top IPs, paths, and rule IDs:

```bash
saugra-waf logs summary --limit 500
```

2. Explain a representative blocked or monitored request:

```bash
saugra-waf explain <request-id>
```

3. Temporarily block clear abusive IPs or CIDRs:

```bash
saugra-waf allowlist block add 198.51.100.44 --duration 2h --reason "scanner burst"
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
saugra-waf logs tail --limit 20
saugra-waf explain <request-id>
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
saugra-waf explain <reference>
```

If the reason is bot or behavior scoring during rollout, add a short-lived
runtime allowlist entry or switch bot/behavior back to monitor mode.

### Admin IP Is Temporarily Blocked

Add your public IP:

```bash
saugra-waf allowlist add ip YOUR_PUBLIC_IP --duration 2h --reason "admin recovery"
```

If deterministic WAF rules are also blocking your verification traffic, set:

```yaml
runtime_policy:
  allowlist_effect: monitor_all
```

Then validate and restart once for the config change:

```bash
saugra-waf test-config
systemctl restart saugra-waf
```

The allowlist entries themselves still reload without restart after that.

### Config Is Valid But Site Fails

Test in this order:

```bash
saugra-waf test-config
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
saugra-waf test-config
systemctl restart saugra-waf
```

### llama.cpp Explanation Problems

```bash
systemctl status saugra-waf-llama-cpp --no-pager
curl -s http://127.0.0.1:8080/health
saugra-waf explain <request-id>
tail -n 20 /var/log/saugra-waf/saugra-waf-ai-audit.jsonl
```

Saugra continues with its deterministic explanation when llama.cpp fails. Set
`ai.provider: local` for an explicit rollback while investigating.

## Useful Files

- `/etc/saugra-waf/saugra-waf.yml`: active config
- `/etc/saugra-waf/rules/`: active rule packs
- `/etc/saugra-waf/ollama/`: model policy and sanitized evaluation fixtures
- `/var/lib/saugra-waf/runtime-policy.json`: runtime allow/block policy
- `/var/lib/saugra-waf/saugra-waf-behavior-state.json`: local behavior state
- `/var/lib/saugra-waf/saugra-waf-bot-state.json`: local bot protection state
- `/var/log/saugra-waf/saugra-waf-events.jsonl`: security events
- `/var/log/saugra-waf/saugra-waf-ai-audit.jsonl`: AI explanation audit records
