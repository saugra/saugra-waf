# Saugra WAF Administration Guide

This guide is the day-to-day operator runbook for Saugra WAF deployments. It
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
sudo systemctl mask saugra-waf.service
sudo apt install saugra-waf
sudo apt-mark hold saugra-waf
```

The package installs the CLI, systemd service, monitor-first production config,
rule packs, standards, intelligence catalogs, Ollama model policy and evaluation
fixtures, and writable runtime directories. The package is held after
installation so unattended upgrades cannot replace the WAF during normal
operation. Unhold it only during a planned upgrade window.
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
sudo systemctl unmask saugra-waf.service
sudo systemctl enable --now saugra-waf.service
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

#### Install On Ubuntu

Ubuntu 24.04 does not provide a `llama-server` package in its default
repositories. Install the build dependencies and build the server from the
official llama.cpp source:

```bash
sudo apt update
sudo apt install -y build-essential cmake git libcurl4-openssl-dev libssl-dev

git clone --depth 1 https://github.com/ggml-org/llama.cpp.git ~/llama.cpp

cmake -S ~/llama.cpp -B ~/llama.cpp/build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DLLAMA_BUILD_TESTS=OFF

cmake --build ~/llama.cpp/build --target llama-server -j2
```

For a user-managed development installation, place the binary in
`~/.local/bin`, which must be on `PATH`:

```bash
install -Dm755 ~/llama.cpp/build/bin/llama-server \
  ~/.local/bin/llama-server
llama-server --version
```

For the packaged systemd example, install the binary at the path used by the
service:

```bash
sudo install -Dm755 ~/llama.cpp/build/bin/llama-server \
  /usr/local/bin/llama-server
/usr/local/bin/llama-server --version
```

Production deployments should build a reviewed llama.cpp release or pinned
commit rather than tracking the repository's moving default branch.

If the shell still reports `llama-server: command not found` after a user
installation, start a new shell or confirm that `~/.local/bin` is present in
`PATH`:

```bash
command -v llama-server
printf '%s\n' "$PATH"
```

#### Start And Verify

Start the loopback-only explanation server:

```bash
llama-server \
  -hf Qwen/Qwen3-0.6B-GGUF:Q8_0 \
  --alias saugra-qwen3-0.6b \
  --host 127.0.0.1 --port 8080 \
  --ctx-size 2048 --threads 1 --parallel 1 \
  --batch-size 128 --jinja --no-webui
```

The first launch downloads the selected GGUF model from Hugging Face and caches
it locally. In another terminal, wait for the model to load and then check the
server:

```bash
curl -s http://127.0.0.1:8080/health
```

A ready server returns a JSON response with an `ok` status. Keep port `8080`
bound to loopback; it is an internal inference endpoint, not a public service.

```yaml
ai:
  enabled: true
  mode: explain_only
  provider: llama_cpp
  llama_cpp_url: http://127.0.0.1:8080
  model: saugra-qwen3-0.6b
  timeout: 60s
```

#### Run In Production With systemd

The process shown above is llama.cpp's `llama-server`, not an Ollama server.
Ollama is a separate supported provider that normally listens on port `11434`.

Do not keep `llama-server` attached to an interactive terminal in production.
Use the maintained
[`configs/llama-cpp/saugra-waf-llama-cpp.service`](https://github.com/saugra/saugra-waf/blob/main/configs/llama-cpp/saugra-waf-llama-cpp.service)
unit, which runs under the dedicated `saugra-waf` account, binds only to
`127.0.0.1:8080`, restarts after failures, provides a persistent model cache,
and applies process hardening and resource limits.

When deploying from a source checkout, install and start the unit with:

```bash
sudo install -Dm644 configs/llama-cpp/saugra-waf-llama-cpp.service \
  /etc/systemd/system/saugra-waf-llama-cpp.service
sudo systemctl daemon-reload
sudo systemctl enable --now saugra-waf-llama-cpp
```

Packaged installations provide the same unit at
`/usr/share/saugra-waf/llama-cpp/saugra-waf-llama-cpp.service`. Install that
copy instead:

```bash
sudo install -Dm644 \
  /usr/share/saugra-waf/llama-cpp/saugra-waf-llama-cpp.service \
  /etc/systemd/system/saugra-waf-llama-cpp.service
sudo systemctl daemon-reload
sudo systemctl enable --now saugra-waf-llama-cpp
```

The first service start downloads the model into the persistent
`/var/cache/saugra-waf-llama-cpp` cache. Complete this deployment step before
enabling the `llama_cpp` provider in Saugra, then confirm that the model loaded:

```bash
sudo journalctl -u saugra-waf-llama-cpp -f
```

While following the service log, run the health check in another terminal:

```bash
curl -s http://127.0.0.1:8080/health
```

Stop following the journal with `Ctrl-C` after the log reports `model loaded`
and the health endpoint returns an `ok` status. Then restart Saugra so it uses
the ready provider:

```bash
sudo systemctl restart saugra-waf
sudo systemctl status saugra-waf-llama-cpp saugra-waf --no-pager
```

Keep port `8080` private and do not enable llama.cpp tools. Saugra continues to
use deterministic explanations if the model service becomes unavailable; AI
output never becomes blocking authority.

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

Run the versioned sanitized provider evaluation suite:

```bash
sudo saugra-waf ai evaluate \
  --cases /usr/share/saugra-waf/ai/evaluation-cases.jsonl \
  --output /var/lib/saugra-waf/ai-evaluation.json
```

The command exits unsuccessfully when any case fails. Do not qualify a model for
production explanations by schema validity alone: require every case to pass
privacy, deterministic grounding, prompt-injection resistance, suggestion
scope, and quality checks. Review each case's sanitized `explanation`,
`suggestion_kinds`, failures, and latency in the report.

If evaluation fails, keep deterministic fallback enabled and either tune the
prompt/model offline or select another model. Do not weaken grounding or privacy
checks merely to make a small model pass. Repeat the suite after every model,
quantization, prompt, llama.cpp, or hardware change.

Review retained unknown-threat events in advisory-only AI shadow mode:

```bash
sudo saugra-waf ai anomaly-shadow \
  --limit 100 \
  --output /var/lib/saugra-waf/ai-anomaly-shadow.json
```

This command cannot change monitor or block decisions. Its report records
`authority: deterministic_policy_only` and `enforcement_changes: 0`.

For native remote providers, set `allow_remote: true`, `local_only: false`, use
an allowlisted HTTPS endpoint, and place the API key in the environment variable
named by `api_key_env`. Record the provider's contractual data region and
retention policy in configuration.

Create and publish a reviewed repeated-anomaly draft:

```bash
sudo saugra-waf rules draft \
  --request-id <request-id-1> \
  --request-id <request-id-2> \
  --output /var/lib/saugra-waf/drafts/reviewed-route.yml

sudo saugra-waf rules replay \
  --input /var/lib/saugra-waf/drafts/reviewed-route.yml \
  --fixtures /usr/share/saugra-waf/ai/rule-replay-cases.jsonl \
  --output /var/lib/saugra-waf/drafts/replay.json

sudo saugra-waf rules approve \
  --input /var/lib/saugra-waf/drafts/reviewed-route.yml \
  --reviewer security@example.com \
  --replay-report /var/lib/saugra-waf/drafts/replay.json

sudo saugra-waf rules publish \
  --input /var/lib/saugra-waf/drafts/reviewed-route.yml \
  --destination /etc/saugra-waf/rules/reviewed-route.yml
```

Publication fails unless the draft is approved and `server.mode` is `monitor`.
Add the published destination to `rules.files` only after reviewing the staged
monitor results.

To inspect one active signature's baseline severity, performance-cost tier,
targets, transforms, pattern, and design intent, pass its rule identifier:

```bash
sudo saugra-waf rules view <saugra-rule-id>
```

The command reads the active rules from the configured Saugra YAML file. Pass
`--config <path>` when the service does not use the default configuration path.
For example:

```bash
sudo saugra-waf rules view SAUGRA-SQLI-001
```

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

Stop and mask Saugra before replacing package files. The mask prevents package
hooks, dependency starts, or operator error from starting the service before
the upgraded configuration has been reviewed:

```bash
sudo systemctl stop saugra-waf.service
sudo systemctl mask saugra-waf.service
```

Unhold the package only for the maintenance window, then install the newest
published version:

```bash
sudo apt-mark unhold saugra-waf
sudo apt update
sudo apt install --only-upgrade saugra-waf
```

The package preserves operator-managed files under `/etc/saugra-waf` and does
not restart the service automatically. It places the newest bundled examples,
rules, standards, and intelligence catalogs under `/usr/share/saugra-waf`.
Review those files when the release notes mention configuration or rule-pack
changes.

Validate the existing configuration before unmasking and starting the service:

```bash
saugra-waf --version
saugra-waf test-config
sudo systemctl unmask saugra-waf.service
sudo systemctl start saugra-waf.service
sudo systemctl status saugra-waf.service --no-pager
curl -i http://127.0.0.1:8787/_saugra-waf/health
```

Hold the package again after validation so future unattended upgrades cannot
replace the running WAF outside a planned maintenance window:

```bash
sudo apt-mark hold saugra-waf
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
sudo systemctl mask saugra-waf.service
sudo apt install saugra-waf
sudo apt-mark hold saugra-waf
```

As a fallback, download the newest `.deb` from the
[GitHub Releases page](https://github.com/saugra/saugra-waf/releases/latest)
and install it with `apt` so dependencies are handled:

```bash
sudo systemctl stop saugra-waf.service
sudo systemctl mask saugra-waf.service
sudo apt-mark unhold saugra-waf
sudo apt install ./saugra-waf_<version>-1_amd64.deb
saugra-waf test-config
sudo systemctl unmask saugra-waf.service
sudo systemctl start saugra-waf.service
sudo apt-mark hold saugra-waf
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
6. If a deterministic rule is noisy for a valid route or parameter, keep Saugra
   WAF in monitor mode and add the narrowest practical `rules.exclusions`
   entry after request-ID review. Prefer method, target, content type, route,
   and parameter scopes over a global rule exclusion.
7. For identity-aware tuning, configure the assertion header under
   `forwarded_headers.identity_assertions`, allow only known
   `trusted_proxies`, and make the front proxy remove client-supplied copies
   before setting the authenticated value. Never trust a role header received
   directly from a client.
8. Validate the configuration and replay an inactive copy of the affected rule
   pack against retained events:

```bash
saugra-waf test-config
saugra-waf rules replay \
  --input /etc/saugra-waf/rules/reviewed-pack.yml \
  --config /etc/saugra-waf/saugra-waf.yml
```

   Review `matches_before_exclusions`, `matches_after_exclusions`, and
   `excluded_events`. Retained events contain names and sizes, not request
   bodies or trusted header values, so the replay report calls out targets and
   value conditions it cannot reproduce.
9. Exercise labeled legitimate and attack-case requests in staging, then
   activate the exclusion in monitor mode and verify new events before enabling
   block mode.
10. Restart only after validation when changing YAML config:

```bash
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

## Saugra Console Enrollment

Console integration is optional and does not replace local inspection, blocking,
event retention, or explanation workflows. Configure a stable external node ID
and a protected credential location:

```yaml
console:
  enabled: true
  management_url: https://console.example.com
  external_id: waf-example-com
  display_name: Example.com WAF
  credential_path: /var/lib/saugra-waf/console-credential.json
  outbox_path: /var/lib/saugra-waf/console-outbox.jsonl
  heartbeat_interval_secs: 60
  delivery_interval_secs: 5
  batch_size: 100
  policy_poll_interval_secs: 30
  policy_cache_path: /var/lib/saugra-waf/console-policy.json
  policy_transition_path: /var/lib/saugra-waf/console-policy-transitions.json
  trusted_signing_keys:
    console-key-id: base64url-ed25519-public-key
```

Create a one-time token for product **WAF** under Console's node enrollment
screen. On packaged installations, enroll as the same `saugra-waf` account used
by the systemd service. The package creates `/var/lib/saugra-waf` for this
account:

```bash
sudo -u saugra-waf /usr/bin/saugra-waf console enroll \
  --config /etc/saugra-waf/saugra-waf.yml \
  --enrollment-token '<one-time-token>'
```

For source installations or custom service units, substitute the account that
runs `saugra-waf run`. Do not enroll as `root` when the runtime uses an
unprivileged account: the protected credential is intentionally created with
mode `0600`, so only the account that created it can read it.

Alternatively, provide the token through `SAUGRA_CONSOLE_ENROLLMENT_TOKEN` to
avoid placing it in shell history. The command sends `POST /api/v1/nodes/enroll`
with the one-time token as a bearer credential. It validates that Console
returns a WAF credential and atomically stores it with mode `0600` on Unix.
Never put an enrollment token or returned node credential in YAML.

When `console.enabled` is true, `saugra-waf run` loads the enrolled node
credential, sends periodic health heartbeats, and delivers every locally
recorded allow, monitor, and block decision in bounded batches. Events are
first committed to the configured durable Console outbox. Accepted, duplicate,
and permanently rejected records leave the outbox; retryable records remain for
the next delivery attempt. Local inspection, blocking, JSONL logging, and
explanation continue if Console is unavailable.

Configure `console.outbox_path` on durable local storage writable by the WAF
service account. `heartbeat_interval_secs`, `delivery_interval_secs`, and
`batch_size` default to `60`, `5`, and `100`; batch size must remain between 1
and Console's 500-record limit. Console policy synchronization remains a
separate, explicitly trusted capability. Copy the policy key ID and public key
shown in Console's **Policy library** into `trusted_signing_keys`. When the map
is empty, the WAF continues reporting inventory and telemetry but does not fetch
or activate managed policy.

With a trusted key configured, the WAF polls the assigned signed policy every
`policy_poll_interval_secs` (default `30`). It verifies the Ed25519 signature,
SHA-256 digest, signed payload, tenant, product, policy key, and revision before
locally validating exclusions. Valid policies are stored atomically at
`policy_cache_path` and activated without restarting request handling. The
verified cached policy is restored after restart; invalid or unavailable
Console policy leaves the last-known-good policy or local YAML configuration
active.

Each heartbeat includes the managed-policy lifecycle state and its update
timestamp. Operators can distinguish policy resolution, download, activation,
rejection, rollback, and an unassigned policy. Transition records include the
policy key, revision, digest, reason, and timestamp when applicable. They are
kept in the protected journal at `policy_transition_path` until Console
acknowledges the heartbeat, so restarts or temporary network failures do not
lose audit evidence. Rejections include an operational reason while the WAF
continues using its last verified policy (or local YAML when no verified policy
has ever been activated). These inventory fields never contain signing keys,
node credentials, or policy bodies.

For an emergency false-positive or unsafe managed-policy rollout, suspend
Console policy locally without deleting the last verified cache:

```bash
sudo -u saugra-waf saugra-waf console policy-override enable \
  --config /etc/saugra-waf/saugra-waf.yml \
  --reason "production checkout false positive under incident INC-1042"
sudo -u saugra-waf saugra-waf console policy-override status \
  --config /etc/saugra-waf/saugra-waf.yml
```

The protected marker is checked before network policy retrieval, so it rolls
back to local YAML even while Console or Relay is unreachable. The heartbeat
reports `rolled_back` and Console audits the node-reported transition. After
the managed revision is corrected and signed, remove the override; the next
successful policy poll revalidates and atomically activates the verified
revision:

```bash
sudo -u saugra-waf saugra-waf console policy-override disable \
  --config /etc/saugra-waf/saugra-waf.yml
```

Set `console.transport: relay` when `management_url` points to Saugra Relay.
Direct Console connections use `direct`, the default. Enrollment, telemetry,
heartbeats, policy retrieval, response commands, and results all follow the
selected transport while local protection remains independent.

Console response operations are limited to temporary IPv4/CIDR blocks,
temporary IPv4/CIDR allows, and removal of a Console-created runtime entry.
Durations must be between 60 seconds and 30 days. Temporary allows and entry
removal require second approval in Console. The WAF rejects expired commands,
unsupported actions, malformed targets, and all response commands when local
runtime policy is disabled. Request UUIDs become runtime-entry UUIDs, making
delivery replay idempotent after a crash or acknowledgement failure.

The initial managed WAF rule schema is:

```yaml
mode: monitor
rules:
  disabled_rule_ids:
    - SAUGRA-XSS-001
  disabled_categories: []
  exclusions:
    - name: Allow HTML in the trusted preview route
      rule_ids: [SAUGRA-XSS-001]
      path_prefixes: [/articles/preview]
      methods: [POST]
```

Create an immutable WAF policy revision in Console, sign it, assign it to a
tenant, group, or node, and begin in monitor or canary rollout. The WAF treats
disabled rules and categories as explicit global exclusions and validates all
scoped exclusions through the same local configuration and rule-loader checks
used at startup.

Re-enroll only if the node credential is lost, expired, or revoked, or if the
node must deliberately receive a new identity. Revoke the old Console node
credential first, preserve it only as required by your audit policy, generate a
fresh one-time WAF token, and rerun the enrollment command.

### Console Offline Attack Map Basemap

The Console Attack Geography page can render a fully local MapLibre basemap
without contacting Google, OpenStreetMap tile servers, a CDN, or another
Internet service. MapLibre, the PMTiles browser protocol, and the dark map style
are included with Console. The operator supplies the map dataset as a local
PMTiles archive.

Perform this procedure on the **Console host**, not on each WAF host.

#### Basemap Requirements

Use a Protomaps-compatible PMTiles archive containing the vector source layers
used by Console's bundled style:

- `earth`
- `landuse`
- `water`
- `buildings`
- `roads`
- `boundaries`

The archive may cover the whole world or only the regions needed by the
deployment. A low-zoom global archive is suitable for attack-origin overviews;
a regional archive with higher zoom levels provides street and building
detail. Full-world, high-detail archives can be several gigabytes and are
intentionally not included in the Console Debian package.

Obtain or generate the archive through an approved map-data workflow. Record
its source, generation date, geographic coverage, maximum zoom, checksum, and
licence. OpenStreetMap-derived archives must retain the attribution required by
their data licence.

#### Install the Archive

The Console package creates `/var/lib/saugra-console/maps` for operator-managed
map data. Copy the archive into place with ownership readable by the
unprivileged `saugra` service account:

```bash
sudo install -d \
  -o saugra \
  -g saugra \
  -m 0750 \
  /var/lib/saugra-console/maps

sudo install \
  -o saugra \
  -g saugra \
  -m 0640 \
  basemap.pmtiles \
  /var/lib/saugra-console/maps/basemap.pmtiles
```

Record a checksum for later integrity checks:

```bash
sha256sum /var/lib/saugra-console/maps/basemap.pmtiles |
  sudo tee /var/lib/saugra-console/maps/basemap.pmtiles.sha256
sudo chown saugra:saugra \
  /var/lib/saugra-console/maps/basemap.pmtiles.sha256
sudo chmod 0640 \
  /var/lib/saugra-console/maps/basemap.pmtiles.sha256
```

Confirm that the service account can read the archive:

```bash
sudo -u saugra test -r \
  /var/lib/saugra-console/maps/basemap.pmtiles \
  && echo "Offline basemap is readable"
```

#### Configure and Restart Console

Add the archive path to `/etc/saugra/console.env`:

```env
SAUGRA_OFFLINE_MAP_ARCHIVE=/var/lib/saugra-console/maps/basemap.pmtiles
```

Do not also configure `SAUGRA_MAP_STYLE_URL` unless the deployment deliberately
uses a custom style. When only `SAUGRA_OFFLINE_MAP_ARCHIVE` is set, Console
automatically selects its bundled offline style and does not require
`SAUGRA_MAP_CONNECT_ORIGINS`.

Restart and inspect Console:

```bash
sudo systemctl restart saugra-console
sudo systemctl status saugra-console --no-pager
sudo journalctl -u saugra-console -n 100 --no-pager
```

A missing, unreadable, or non-file archive path prevents Console startup so the
configuration failure is observable rather than silently falling back to an
external service.

#### Verify Byte-Range Delivery

PMTiles reads only the portions of the archive required for the current
viewport. Console provides a same-origin endpoint with HTTP byte-range support.
Verify it from the Console host:

```bash
curl -sS -D - -o /dev/null \
  -H 'Range: bytes=0-126' \
  http://127.0.0.1:8000/map-data/basemap.pmtiles
```

The response should include:

```text
HTTP/1.1 206 Partial Content
Accept-Ranges: bytes
Content-Range: bytes 0-126/<archive-size>
Content-Length: 127
Content-Type: application/vnd.pmtiles
```

A `404` response means the archive is not configured or cannot be opened. A
`416` response means the requested range starts beyond the end of the file.

#### Configure Each WAF Destination

The basemap supplies geographic context, but Console still needs the protected
location of each WAF. In Console:

1. Open **Estate → WAF Operations**.
2. Select a WAF instance.
3. Find **Attack map destination**.
4. Enter a map label, latitude, and longitude.
5. Save the location.
6. Repeat for every WAF shown on the tenant-wide map.

When **All WAF instances** is selected, Console displays each configured WAF as
a separate color-coded destination and routes every animated attack path to the
WAF that received that event. Events for a WAF without coordinates remain in
the source summary but do not receive a misleading trajectory.

#### Verify in the Browser

Open **Security Operations → Attack Geography** and confirm:

- roads, borders, water, and land are rendered from the local archive;
- browser developer tools show requests only to the Console origin;
- map archive requests return `206 Partial Content`;
- source markers appear at their telemetry- or GeoIP-derived locations;
- configured WAF destinations appear in the legend;
- animated paths terminate at the correct WAF;
- zoom, pan, reset, pause, and popups operate normally.

If Console shows the simplified polygon map instead, check:

```bash
sudo journalctl -u saugra-console -n 100 --no-pager
sudo -u saugra test -r \
  /var/lib/saugra-console/maps/basemap.pmtiles
grep '^SAUGRA_OFFLINE_MAP_ARCHIVE=' /etc/saugra/console.env
curl -sS -D - -o /dev/null \
  -H 'Range: bytes=0-126' \
  http://127.0.0.1:8000/map-data/basemap.pmtiles
```

Also inspect the browser console for WebGL, style-layer, Content Security
Policy, or PMTiles errors. A readable archive can still render incompletely if
it does not contain the Protomaps-compatible source layers expected by the
bundled style.

#### Refresh or Replace the Basemap

Prepare replacements beside the active archive and switch them atomically:

```bash
sudo install \
  -o saugra \
  -g saugra \
  -m 0640 \
  basemap-new.pmtiles \
  /var/lib/saugra-console/maps/basemap.pmtiles.new

sudo mv \
  /var/lib/saugra-console/maps/basemap.pmtiles.new \
  /var/lib/saugra-console/maps/basemap.pmtiles

sudo systemctl restart saugra-console
```

Re-run the checksum, byte-range, and browser verification steps after every
replacement. Keep the previous validated archive until the new map has passed
verification, according to the deployment's storage and rollback policy.

### Console Credential Permission Denied

The Console can show an enrolled WAF while the local service repeatedly exits
with this error:

```text
Error: Console is enabled but its node credential could not be loaded; run `saugra-waf console enroll`
Caused by:
    Permission denied (os error 13)
```

This means enrollment succeeded, but the runtime account cannot read
`console.credential_path`. A common cause is running enrollment with `sudo` as
`root`, which creates a root-owned credential with the required `0600` mode,
while the packaged systemd service runs as `saugra-waf`. Do not re-enroll or
revoke the node when the credential is present; repair its ownership instead:

```bash
sudo systemctl stop saugra-waf

sudo install -d \
  -o saugra-waf \
  -g saugra-waf \
  -m 0750 \
  /var/lib/saugra-waf

sudo chown saugra-waf:saugra-waf \
  /var/lib/saugra-waf/console-credential.json
sudo chmod 0600 \
  /var/lib/saugra-waf/console-credential.json

sudo -u saugra-waf test -r \
  /var/lib/saugra-waf/console-credential.json \
  && echo "Credential is readable"

sudo systemctl reset-failed saugra-waf
sudo systemctl start saugra-waf
sudo journalctl -u saugra-waf -f -o cat
```

Successful recovery produces both of these messages:

```text
Console heartbeat acknowledged
Saugra listening on http://127.0.0.1:8787
```

If the read test still fails, verify the configured path and permissions on
every parent directory:

```bash
sudo namei -l /var/lib/saugra-waf/console-credential.json
sudo stat /var/lib/saugra-waf/console-credential.json
sudo systemctl cat saugra-waf
```

The credential should be owned by the runtime account with mode `0600`; its
parent directory must allow that account to traverse it. Custom systemd units
must also permit the credential path through any `ProtectSystem`,
`ProtectHome`, or `ReadOnlyPaths` restrictions.

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
- `/etc/saugra-waf/ai/`: provider-neutral sanitized evaluation and replay fixtures
- `/etc/saugra-waf/ollama/`: optional Ollama model policy
- `/var/lib/saugra-waf/runtime-policy.json`: runtime allow/block policy
- `/var/lib/saugra-waf/saugra-waf-behavior-state.json`: local behavior state
- `/var/lib/saugra-waf/saugra-waf-bot-state.json`: local bot protection state
- `/var/log/saugra-waf/saugra-waf-events.jsonl`: security events
- `/var/log/saugra-waf/saugra-waf-ai-audit.jsonl`: AI explanation audit records
