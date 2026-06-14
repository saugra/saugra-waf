# Saugra Public Roadmap

This roadmap tracks public community-edition development for Saugra. Saugra is
developed as a production-oriented WAF for real web applications.

This public repository focuses on the self-hosted WAF engine, reverse proxy,
rules, local logs, CLI, local visibility, deployment examples, and basic
explain-only AI summaries. Private planning, if any, is tracked outside this
repository.

## Current Status

Current phase: **Phase 7 complete — Operator workflows and scheduled security summaries**

The repository has a working Rust foundation:

- CLI scaffold
- YAML config loading and validation
- YAML rule packs with validation and anomaly scoring
- WAF decision model
- Basic AI-style explanation helper
- Structured logging setup
- Catch-all reverse proxy service
- Rotated local JSONL security event store
- Redis-backed distributed rate limiter for production use
- Local-only in-memory rate limiter for development and tests
- `logs tail`, `explain`, `owasp coverage`, `posture check`, and report
  summary CLI workflows
- Local and remote verification scripts
- WebSocket handshake inspection with upgrade tunneling
- Route-based multi-upstream HTTP and WebSocket forwarding
- No-restart runtime allow/block policy for local IP and CIDR entries
- Operator admin guide for commands, troubleshooting, allowlisting, blocking,
  logs, explanations, and rollout recovery
- Example config at `configs/saugra-waf.example.yml`
- Debian package metadata for GitHub Release `.deb` artifacts
- APT repository dry-run tooling for the Saugra-owned package repository

## Verified Commands

```bash
cargo fmt --check
cargo check --all-targets
cargo test --locked --all-targets --all-features
cargo run --bin saugra-waf -- test-config --config configs/saugra-waf.example.yml
cargo run --bin saugra-waf -- rules list --config configs/saugra-waf.example.yml
```

Current test status:

```txt
288 tests pass in a normal local/CI environment, including the two WebSocket
raw-socket tunnel tests.
```

## Production-Ready Product Principle

Saugra should avoid throwaway implementations for security-critical features.
Each feature should be built as a production-oriented foundation that can be
improved without rewriting call sites or changing the operator workflow.

Required implications:

- Rate limiting must use a stable storage abstraction and support a
  production-safe backend such as Redis before it is considered complete.
  In-memory rate limiting is only a local-only backend.
- Security events must be written to durable, queryable storage suitable for
  `logs tail`, `explain <request-id>`, and basic audit workflows.
- Monitor-first rollout remains the default recommendation, but block mode must
  be deterministic, observable, tested, and safe for production use after tuning.
- Features should be marked done only when they are usable in the documented
  deployment path without being replaced later.

## Community Edition Scope

The public edition should remain useful by itself:

- Reverse proxy runtime
- Request inspection
- Built-in OWASP-style rules
- Monitor and block modes
- Structured JSON security logs
- Local CLI tools
- Local dashboard or log viewer
- Nginx and Apache integration examples
- Docker and deployment examples
- Basic explain-only AI summaries

## Public Edition Scope

The public edition should provide real security value without requiring a paid
or hosted service.

Public development should prioritize:

- Reliable local protection
- Transparent rule-based decisions
- Clear monitor and block behavior
- Safe structured logs
- Practical deployment examples
- Explainable findings

## Next Public Development Work

- [x] Replace the placeholder root route with a catch-all proxy route.
- [x] Accept all HTTP methods and paths.
- [x] Normalize request path, query, headers, user-agent, and body.
- [x] Run built-in rules before forwarding traffic.
- [x] Log a structured security event when rules match.
- [x] In `monitor` mode, allow suspicious traffic after logging.
- [x] In `block` mode, return a safe block response.
- [x] Forward allowed traffic to the configured upstream.
- [x] Add tests for monitor and block behavior.

## Phase 8 — Package Distribution and Official Archive Preparation

Saugra's near-term production install channel is a Saugra-owned signed APT
repository. The long-term public distribution goal is official Debian archive
inclusion, with Ubuntu sync where possible.

- [x] Add production-oriented Debian package metadata for `cargo-deb`.
- [x] Add maintainer scripts that preserve operator configuration and avoid
      automatic service start.
- [x] Add GitHub Release workflow for `.deb` artifacts.
- [x] Add unsigned APT repository dry-run tooling.
- [x] Add release CI install tests for standalone `.deb` packages.
- [x] Add release CI install test coverage for the generated APT repository.
- [x] Choose hosting for the Saugra-owned signed APT repository: GitHub Pages.
- [x] Document creation and secure handling of a dedicated APT repository
      signing key.
- [x] Add GitHub Pages publishing for signed APT repository metadata.
- [x] Enable GitHub Pages with GitHub Actions as the Pages source.
- [x] Add APT repository signing secrets to GitHub Actions.
- [ ] Optionally configure `repo.saugra-waf.dev` as the Pages custom domain.
- [ ] Add `arm64` package builds and install tests.
- [ ] Run a Debian Rust dependency audit for official archive readiness.
- [ ] Create Debian source packaging under `debian/`.
- [ ] Build the official Debian source package without network access.
- [ ] Run `lintian`, `sbuild` or `pbuilder`, and Debian policy checks.
- [ ] File a Debian WNPP Intent to Package bug.
- [ ] Upload to mentors.debian.net and request sponsorship.
- [ ] Track Debian NEW review and Ubuntu sync after Debian acceptance.

## Phase 3 — Production-Ready Proxy Verification + Abuse Controls

- [x] Add JSON decision output shape tests.
- [x] Add initial in-memory per-client rate limiting for local-only use.
- [x] Introduce a `RateLimitStore` abstraction.
- [x] Add Redis-backed distributed rate limiting for production use.
- [x] Support configurable per-route limits with burst settings.
- [x] Treat in-memory rate limiting as `backend: memory` for local-only use.
- [x] Add a Redis-backed production config example.
- [x] Return safe `429` JSON responses for blocked rate-limit abuse.
- [x] Add proxy handler tests for rule blocking and rate-limit blocking.
- [x] Add local JSONL request-decision storage.
- [x] Add `logs tail` and `explain <request-id>` CLI groundwork.
- [x] Validate JSONL event storage as durable enough for single-node production.
- [x] Add configurable external/durable event storage path and retention policy.
- [x] Add forwarding tests with a fake upstream transport.
- [x] Add structured JSON security event shape tests.
- [x] Add safer end-to-end scripts for local proxy smoke tests.
- [x] Add comprehensive remote staging/production WAF verification script.

## Phase 3.5 — External Rule Packs and CRS-Style Tuning

Saugra should scale beyond hardcoded Rust rules. The community rule engine will
load validated YAML rule packs at startup, compile rule regexes before accepting
traffic, and expose the same rules through `saugra-waf rules list`.

The rule-pack design is inspired by OWASP CRS operational concepts while
remaining native to Saugra instead of copying ModSecurity syntax directly:

- [x] Define Saugra YAML as the product rule format; CRS is an upstream rule
      source that can be converted into Saugra YAML, not a runtime syntax Saugra
      must clone.
- [x] Move the current public rules into CRS-style modular files under
      `configs/rules/`.
- [x] Support multiple configured rule files through `rules.files`.
- [x] Compile and validate all rule regexes at startup.
- [x] Support rule metadata: id, name, category, severity, targets,
      paranoia level, OWASP category, transforms, and explanation.
- [x] Add an initial `saugra-waf rules convert-crs` command for supported CRS
      `@rx` rules.
- [x] Support monitor-first rollout with CRS-style detection and blocking
      paranoia levels.
- [x] Add anomaly scoring thresholds so multiple lower-severity findings can
      combine into a block decision instead of relying only on first-match
      blocking.
- [x] Add local tuning controls: disable rules by ID, disable categories, and
      exclude specific rules by path, parameter, header, and rule ID.
- [x] Add `saugra-waf rules view <saugra-rule-id>` for active signature severity,
      performance-cost metadata, targets, transforms, pattern, and design intent.
- [x] Add context-aware exclusion scopes for HTTP method, matched rule target,
      content type, and trusted header values.
- [x] Record privacy-safe matched-evidence metadata that helps operators locate
      false positives without retaining sensitive full payloads by default.
- [x] Add exclusion validation and operator warnings for global, contradictory,
      spoofable, or otherwise overly broad exclusion policies.
- [x] Extend inactive rule-pack replay to evaluate proposed exclusions against
      retained traffic, report prior outcomes and unavailable evidence, and
      require separate labeled legitimate and attack-case staging verification
      before activation.
- [x] Support authenticated identity or role exclusion scopes only through
      explicitly configured and validated trusted proxy or upstream identity
      assertions; never trust arbitrary client-supplied role headers.
- [x] Document a monitor-first context-aware tuning workflow covering request ID
      review, narrow exclusion selection, validation, replay, activation, and
      post-deployment verification.
- [x] Add rule-pack validation output so operators can see loaded files, rule
      counts, disabled rules, configured exclusions, and warnings before
      starting traffic.
- [x] Add rule-pack versioning and unsupported-import reporting to validation
      output.
- [x] Treat transforms as first-class ordered pipelines with tests for
      URL-decoding, plus-to-space handling, lowercasing, and future CRS
      transform equivalents.
- [x] Expand CRS conversion and unsupported-reporting coverage for chains, operators such as
      `@pmFromFile`, data files, and engine-specific features such as
      libinjection.
- [x] Add support for CRS-style data files and `@pmFromFile` matchers.
- [x] Add test fixtures for every imported CRS category, including SQLi, XSS,
      LFI/path traversal, RCE/command injection, scanner detection, protocol
      enforcement, and file upload rules.
- [x] Document unsupported CRS features clearly so operators understand which
      converted rules are active, skipped, or partially represented.
- [x] Document the import flow as `OWASP CRS .conf -> saugra-waf rules convert-crs
      -> Saugra YAML rule packs -> Saugra rule engine`.
- [x] Keep bad rule files as clear startup/config errors, not silent weak
      protection.

## Phase 4 — WebSocket and Upgrade-Aware Proxying

Saugra currently protects normal HTTP request paths that are routed through the
Saugra reverse proxy. WebSocket locations such as `/ws/` often remain proxied
directly from Nginx to an ASGI server such as Daphne, which means those upgrade
requests are not inspected by Saugra yet.

Production posture until upgrade-aware proxying is implemented: route normal
HTTP traffic through Saugra, and keep WebSocket paths explicitly protected by
Nginx/Apache and the application layer. Operators should validate `Origin`,
`Host`, authentication, rate limits, and message-level authorization outside
Saugra for those paths.

- [x] Detect HTTP upgrade requests for WebSocket handshakes.
- [x] Inspect the initial WebSocket handshake path, query string, headers,
      origin, user-agent, cookies, and client identity before upgrade.
- [x] Apply existing allow, monitor, block, and rate-limit decisions to the
      handshake request.
- [x] Preserve required upgrade semantics, including `Upgrade`,
      `Connection`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version`, and
      `Sec-WebSocket-Protocol` headers.
- [x] Tunnel accepted upgraded connections between client and upstream without
      breaking long-lived WebSocket sessions.
- [x] Add WebSocket-specific logging fields for upgrade decisions, upstream
      target, close/error outcomes, and request ID correlation.
- [x] Add configurable origin and host validation guidance for WebSocket
      deployments.
- [x] Add Nginx and Django Channels/Daphne deployment examples that route
      `/ws/` through Saugra.
- [x] Add tests for allowed, monitored, blocked, and rate-limited WebSocket
      handshake requests.
- [x] Document the temporary deployment posture: `/ws/` should be hardened at
      Nginx and the application layer until Saugra supports upgrade tunneling.

## Phase 4.5 — OWASP Top 10 Layered Coverage

Default request rules provide starter signals for every OWASP Top 10:2025
category, but Saugra should not claim that regex inspection alone solves
deployment, supply chain, cryptographic, authentication, design, or operational
risks. The implementation target is layered OWASP coverage:

- request rules for visible payloads
- rate limits and anomaly scoring for abusive behavior
- deployment posture checks for configuration and transport assumptions
- external report ingestion for SBOM, dependency, CI, and integrity evidence
- durable events, explanations, and coverage reporting for operators

Planned work:

- [x] Document the layered OWASP Top 10 strategy.
- [x] Add `saugra-waf owasp coverage` to report active controls and gaps by OWASP
      category.
- [x] Add a `posture` config section for deployment assumptions.
- [x] Add `saugra-waf posture check` for local deterministic checks such as
      expected external scheme, allowed methods, response security headers,
      secure cookies, and upload/body policy.
- [x] Add normalized local report ingestion for SBOM and dependency scan
      outputs.
- [x] Show OWASP category coverage in structured logs, security events, block
      responses, and explanations.
- [x] Show OWASP category coverage in the local log viewer through
      `saugra-waf logs summary`.
- [x] Support future standard mappings, such as `owasp-top-10:2026`, through
      YAML metadata and coverage mappings rather than proxy rewrites.

## Phase 5 — Multi-Upstream HTTP and WebSocket Routing

Saugra supports route-based forwarding to multiple named upstreams. Production
applications often split normal web traffic, APIs, admin surfaces, file
services, and WebSocket endpoints across different backend processes. Saugra
should route each accepted request to the right upstream while keeping one
shared WAF decision pipeline.

The implementation target is route-based upstream selection:

- explicit route entries in YAML
- longest path-prefix match wins
- named upstream references with startup validation
- one deterministic fallback route
- shared inspection, rate limiting, logging, and explanation behavior before
  forwarding
- selected upstream context recorded in security events
- WebSocket handshakes and tunnels using the same route selection model

Planned work:

- [x] Add a `routes` config section for path-prefix to upstream mappings.
- [x] Validate that every route has a non-empty path prefix and references an
      existing upstream name.
- [x] Support a deterministic fallback route, either explicit `/` or the first
      upstream for backward compatibility.
- [x] Implement longest-prefix upstream selection for HTTP requests.
- [x] Apply the same upstream selection to accepted WebSocket handshakes and
      tunnels.
- [x] Include selected upstream name, host, and target in security events and
      structured decision logs.
- [x] Preserve existing WAF, monitor/block, anomaly scoring, and rate-limit
      behavior before forwarding to the selected upstream.
- [x] Add tests for default routing, longest-prefix routing, invalid route
      config, HTTP forwarding, WebSocket tunneling, blocked requests, monitored
      requests, and rate-limited requests.
- [x] Update example configs and production deployment docs for multi-upstream
      HTTP and WebSocket deployments.

## Phase 6 — Behavior Scoring and Threshold-Based Blocking

Saugra already supports per-request rule anomaly scoring. The next public phase
adds community-edition behavior scoring so repeated probing, suspicious path
enumeration, scanner-like request patterns, and route-specific abuse can raise
risk even when an individual request does not match a blocking rule.

This phase should keep Saugra rules-first: behavior scores augment deterministic
rule decisions and rate limits, but AI remains explain-only and must not become
the blocking mechanism.

The community-edition target is local, transparent, and production-usable for a
single Saugra node:

- [x] Add a `behavior` config section with monitor-first defaults, scoring
      windows, decay, per-client thresholds, and route/category overrides.
- [x] Add a stable behavior-state abstraction so local durable storage can be
      replaced by Redis or another distributed backend without changing proxy
      decision call sites.
- [x] Implement local durable behavior state suitable for single-node
      production, restart survival, `explain <request-id>`, and audit
      workflows.
- [x] Score repeated suspicious requests from the same client, including
      scanner paths, development/internal endpoint probes, repeated 404-style
      enumeration, authentication abuse, and repeated low-severity rule matches.
- [x] Add configurable behavior thresholds for `monitor` and `block`, separate
      from per-request anomaly thresholds.
- [x] Preserve monitor-first rollout: new behavior rules should log and explain
      before operators enable threshold-based blocking.
- [x] Emit behavior score, score contributors, threshold, window, and storage
      backend in structured security events.
- [x] Include behavior contributors in `saugra-waf explain <request-id>` and
      `saugra-waf logs summary`.
- [x] Add tests for score accumulation, decay/window expiry, restart behavior,
      monitor thresholds, block thresholds, route overrides, and event shape.
- [x] Document how behavior scoring differs from rule anomaly scoring and rate
      limiting.

### Bot Protection and Traffic Abuse Defense

Bot protection should be built on top of the Phase 6 behavior-scoring and
rate-limit foundations instead of becoming a separate black-box blocker. The
community edition goal is deterministic, explainable bot and automation defense
that can start in monitor mode, produce useful evidence for tuning, and then
block only after operators enable tuned thresholds.

Initial scope:

- [x] Add a `bot_protection` config section with `enabled`, `mode`,
      `score_window`, `monitor_threshold`, `block_threshold`,
      `temporary_block_duration`, allowlists, and route overrides.
- [x] Support production-safe local state for single-node deployments, with
      Redis or another durable/distributed backend documented as required for
      future multi-instance deployments.
- [x] Combine deterministic bot signals such as known scanner user agents,
      suspicious automation headers, missing or malformed browser-like headers,
      configured scanner path probes, development/internal endpoint probes,
      login abuse, and repeated low-severity WAF matches.
- [x] Keep CAPTCHA out of scope. Saugra bot protection should rely on
      deterministic request signals, rate limits, behavior scoring, allowlists,
      blocklists, and temporary blocking rather than interactive user
      challenges.
- [x] Keep JavaScript challenges and browser fingerprinting out of the first
      public implementation unless they are added behind explicit, documented,
      monitor-first controls.
- [x] Add allowlist and blocklist support for trusted crawlers, internal IP
      ranges, service accounts, user-agent patterns, and high-risk clients.
- [x] Add configurable temporary blocking that emits a security event and
      records the score contributors, threshold, duration, storage backend, and
      route policy that caused the block.
- [x] Include bot-protection contributors in `saugra-waf explain <request-id>`,
      `saugra-waf logs tail`, and `saugra-waf logs summary`.
- [x] Document a production rollout path: monitor first, review events, tune
      allowlists and route thresholds, then enable blocking for selected routes.
- [x] Add tests for monitor-only bot scoring, threshold blocking, temporary
      block expiry, allowlist bypass, blocklist enforcement, route overrides,
      durable state restart behavior, and structured event shape.

Example target configuration:

```yaml
bot_protection:
  enabled: true
  mode: monitor
  backend: local
  state_path: /var/lib/saugra-waf/saugra-waf-bot-state.json
  score_window: 10m
  monitor_threshold: 40
  block_threshold: 80
  temporary_block_duration: 15m
  allowlists:
    user_agents:
      - Googlebot
    ip_ranges: []
  routes:
    - path: /login
      block_threshold: 60
```

Future behavior scoring work should extend the public behavior scoring model
rather than replace it.

### Runtime Allowlisting Without Restart

Runtime allowlisting is a community-edition operational safety feature. It
allows administrators to recover from false positives and temporary bot or
behavior blocks without restarting Saugra.

Initial scope:

- [x] Add a `runtime_policy` config section with an enabled flag, policy path,
      reload interval, default duration, and allowlist effect.
- [x] Store local runtime policy in `/var/lib/saugra-waf/runtime-policy.json`.
- [x] Add `saugra-waf allowlist add/list/remove/prune` commands for IP and CIDR
      entries.
- [x] Add runtime blocklist support with `saugra-waf allowlist block add`.
- [x] Reload the runtime policy file without restarting Saugra.
- [x] Apply runtime IP/CIDR allowlists before bot and behavior threshold
      blocking.
- [x] Support runtime policy effects that can keep deterministic WAF rules
      active, downgrade them to monitor, or bypass them for trusted rollout
      cases.
- [x] Emit runtime allowlist match metadata in security events and
      `saugra-waf explain`.
- [x] Add tests for expiry, atomic CLI writes, bot/behavior bypass,
      deterministic WAF downgrade, and runtime blocklist enforcement.
- [x] Add explicit malformed-policy reload test that keeps the last known good
      policy.
- [x] Add explicit no-restart reload integration test that mutates the policy
      file after Saugra starts.
- [x] Add optional reset commands for local behavior and bot state by client ID.

The implemented design is documented in `docs/ADMIN_GUIDE.md` and
`docs/ARCHITECTURE.md`.

### Admin Guide and Operator Runbooks

- [x] Add a single admin guide for service commands, troubleshooting,
      allowlisting, blocking, logs, explanations, rollout recovery, Redis
      checks, and useful production file paths.
- [x] Link the admin guide from README and production deployment docs.
- [x] Add example incident workflows for common false positives, scanner bursts,
      upstream outages, Redis outages, and WebSocket routing failures.

## Phase 7 — Scheduled Security Summaries

Saugra should help small teams review security activity without requiring them
to watch logs continuously. The community edition should support local scheduled
summary generation from durable WAF event logs.

Initial scope:

- [x] Add a `security_summary` config section with enabled flag, schedule time,
      timezone, lookback window, recipients, and delivery channel.
- [x] Support a local daily summary over the last 24 hours by default.
- [x] Summarize total security events, blocked events, monitored events,
      allowed runtime-policy events, top attack categories, top matched rules,
      top source IPs, top targeted paths, rate-limit events, bot events, and
      behavior-threshold events.
- [x] Include sample request IDs for the most important blocked events so admins
      can run `saugra-waf explain <request-id>`.
- [x] Add `saugra-waf summary daily --config /etc/saugra-waf/saugra-waf.yml` to generate a
      summary on demand.
- [x] Add `saugra-waf summary send --config /etc/saugra-waf/saugra-waf.yml` for manual
      delivery testing.
- [x] Add a scheduler loop or documented systemd timer path for sending the
      report at a configured time, for example 08:00 local time.
- [x] Support file output first, for example
      `/var/log/saugra-waf/saugra-waf-security-summary-YYYY-MM-DD.json`.
- [x] Add email delivery after file output is stable. Email config should avoid
      hard-coded secrets and support environment variables or secret files.
- [x] Make failures observable in journald and local admin events.
- [x] Add tests for 24-hour filtering, summary shape, empty-day summaries, top
      category/rule/path/IP aggregation, timezone handling, and delivery
      failure reporting.

Example target config:

```yaml
security_summary:
  enabled: true
  schedule: daily
  send_time: "08:00"
  timezone: Africa/Nairobi
  lookback: 24h
  output_path: /var/log/saugra-waf/saugra-waf-security-summary.json
  channels:
    - type: file
    # Future:
    # - type: email
      #   to:
      #     - security@example.com
```

## Phase 9 — Unknown-Threat Detection and AI Assistance

Saugra should describe this capability as unknown-threat detection, not as a
guarantee that every zero-day exploit will be stopped. Known attack patterns
remain the responsibility of deterministic rules. Statistical and AI-assisted
features add evidence, explanations, correlation, and tuning support.

The request path remains:

```txt
request
  -> deterministic rules
  -> rate limiting and behavior controls
  -> route-aware unknown-threat signals
  -> deterministic risk policy
  -> allow / monitor / block
  -> asynchronous explanation and tuning workflows
```

An external LLM must never sit in the synchronous forwarding path or become the
only reason Saugra blocks a request.

### Route-Aware Request Baselines

- [x] Add an `unknown_threats` configuration boundary.
- [x] Add a stable baseline-store interface with memory and durable local
      implementations.
- [x] Normalize dynamic path segments into route shapes.
- [x] Learn methods, content types, query parameter names, and body-size ranges
      from requests that have no deterministic rule matches.
- [x] Require a minimum number of observations before emitting anomaly signals.
- [x] Attach explainable anomaly signals to decisions and security events.
- [x] Keep the first implementation monitor-only.
- [x] Add focused tests for learning, persistence, route normalization, and
      anomaly detection.
- [ ] Add a Redis or equivalent shared baseline backend before supporting
      multi-instance enforcement.
- [x] Add bounded baseline retention and route cardinality limits.
- [x] Add scheduled cleanup for inactive local baseline stores through the
      existing cleanup command and documented systemd timer.
- [x] Add explicit route exclusions and route-specific learning policies.

### Deterministic Unknown-Threat Policy

- [x] Add independently configurable signal weights through a validated data
      file rather than hard-coded production policy.
- [x] Require at least two independent anomaly signals for automatic blocking.
- [x] Add observation-age and traffic-volume requirements before a baseline can
      become blocking-eligible.
- [x] Prevent automatic blocking on newly observed routes.
- [x] Add route-specific thresholds and high-risk route policies.
- [x] Add shadow evaluation and false-positive reports before enabling block
      mode.
- [x] Add baseline poisoning defenses, including trusted-learning traffic,
      bounded updates, and quarantine of anomalous observations.

### Campaign Correlation

- [x] Correlate low-severity events across clients, sessions, routes, and time
      windows.
- [x] Detect distributed scanning, endpoint discovery, credential attacks, and
      multi-step attack progression.
- [x] Store correlation state in a durable distributed backend.
- [x] Produce campaign IDs and include them in events and explanations.
- [x] Add deterministic campaign thresholds with monitor-first rollout.

### AI Explanations and Tuning

- [x] Define a provider-neutral asynchronous explanation interface.
- [x] Redact secrets and minimize payload data before any external model call.
- [x] Explain route-baseline deviations, rule matches, behavior history, and
      campaign context.
- [x] Generate narrow tuning suggestions such as route exclusions or threshold
      changes.
- [x] Record model, prompt version, input digest, output, latency, and failure
      state for auditability.
- [x] Keep deterministic local explanations available when AI is disabled or
      unavailable.
- [x] Add native OpenAI-compatible remote provider configuration with secret
      references, endpoint allowlisting, TLS enforcement, and rate-limit tests.
- [x] Add native Gemini provider configuration with the same sanitization,
      audit, timeout, and deterministic-fallback guarantees.
- [ ] Benchmark `llama.cpp` with a small quantized model such as Qwen3 0.6B
      against Ollama using the same sanitized explanation and rule-drafting
      evaluation cases. Complete production sizing guidance only after schema
      validity, grounding, latency, peak memory, and deployment measurements
      confirm the expected advantage.
      - 2026-06-14 local llama.cpp baseline: Qwen3 0.6B Q8, 2048-token context,
        one inference thread, 1.17 GiB peak RSS, and 7.8-11.2 second case
        latency. The strict provider-neutral suite passed 0/6 cases because the
        model restated scores and omitted required deterministic identifiers.
        Keep deterministic fallback enabled; Ollama comparison and model
        qualification remain open.
- [x] Add a loopback-only `llama.cpp` provider with schema-constrained bounded
      output, audit records, timeouts, and deterministic fallback.
- [x] Add versioned model evaluation and replay tooling for sanitized security
      cases, including schema, privacy, grounding, suggestion-scope, quality,
      and latency regression checks.
- [x] Add remote-provider privacy and residency controls, including explicit
      provider enablement, data-region policy, retention disclosure, auditable
      secret references, and a local-only deployment mode.
- [x] Research model-assisted anomaly analysis in shadow mode with offline
      evaluation and operator review; deterministic policy must remain the
      authority for monitor and block decisions.

### Rule Drafting and Replay

- [x] Convert repeated, reviewed anomalies into draft Saugra YAML rules.
- [x] Require human approval before publishing generated rules.
- [x] Validate and compile an inactive rule pack with
      `saugra-waf rules validate --input <draft.yml>`.
- [x] Replay path and query targets from retained security events with
      `saugra-waf rules replay --input <draft.yml>`. Report unavailable retained
      targets instead of implying complete replay coverage.
- [x] Report false-positive impact and attack-case coverage.
- [x] Deploy accepted rules in monitor mode before block mode.
- [x] Add a versioned draft manifest containing source anomaly IDs, generator
      provider and model, prompt version, input digest, reviewer, approval
      timestamp, replay report digest, and publication state.
- [x] Keep generated drafts outside configured active rule directories and
      require an explicit publish command after validation, replay, and human
      approval.
- [x] Add labeled sanitized replay fixtures so legitimate-traffic impact and
      attack-case coverage are measured separately from unlabeled historical
      event overlap.

### Security and Privacy Guardrails

- Do not train on requests already matched by deterministic attack rules.
- Do not store full request bodies in baseline state.
- Store request shapes and bounded metadata, not credentials or tokens.
- Treat local state as single-node production support, not distributed support.
- Fail open for unknown-threat analysis errors while logging the failure.
- Never silently block; every enforced decision must produce a security event.
- Keep monitor-first defaults and make enforcement an explicit operator choice.

## Production Readiness Gate

Before Saugra is recommended for production use, complete:

- [x] Redis-backed distributed rate limiting.
- [x] Rate-limit store abstraction with memory and Redis backends.
- [x] Configurable per-route and global rate-limit policies.
- [x] Durable security event retention with documented rotation.
- [x] Nginx and Apache production deployment examples.
- [x] End-to-end tests for forwarding, monitor mode, block mode, rate limiting,
      event persistence, and `explain <request-id>`.
- [x] Safe defaults documented for first production rollout.
- [x] Source install and systemd service documented.
- [x] Clear production documentation for routing WebSocket paths through Saugra
      with edge and application-layer hardening.
- [x] WebSocket upgrade support.

## Public Built-In Rules

- `SAUGRA-SQLI-001` — basic SQL injection pattern
- `SAUGRA-XSS-001` — basic cross-site scripting pattern
- `SAUGRA-PATH-001` — path traversal pattern
- `SAUGRA-CMD-001` — command injection pattern
- `SAUGRA-BOT-001` — suspicious scanner user agent
- `SAUGRA-AUTH-001` — credential stuffing tool user agent
- `SAUGRA-AUTH-002` — credential exposure in URL
- `SAUGRA-DESIGN-001` — dangerous method override header
- `SAUGRA-CT-001` — suspicious content type
- `SAUGRA-CRYPTO-001` — insecure forwarded protocol
- `SAUGRA-BODY-001` — suspicious body script pattern
- `SAUGRA-SC-001` — package install script injection
- `SAUGRA-INTEGRITY-001` — unsafe serialized object marker
- `SAUGRA-LOG-001` — log injection sequence
- `SAUGRA-EXC-001` — exceptional parser stress sequence
- `SAUGRA-RATE-001` — per-client request rate limit
