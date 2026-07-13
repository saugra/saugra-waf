# Changelog

All notable changes to Saugra are documented here.

## Unreleased

## 1.1.4 - 2026-07-13

### Fixed

- Make release CI fail before Rust setup with actionable guidance when the
  private Console contracts dependency or its pinned tag cannot be accessed.
- Configure authenticated Cargo fetching for the pinned private Console
  contracts dependency after the release access check succeeds.

### Documentation

- Document least-privilege generation, secure repository-secret setup,
  verification, approval, failure handling, and rotation for
  `SAUGRA_CONTRACTS_TOKEN`.

## 1.1.3 - 2026-07-13

### Added

- Add optional Saugra Console enrollment configuration with stable WAF node
  identity, Console URL, display name, and protected credential path.
- Add `saugra-waf console enroll` using one-time WAF enrollment tokens and the
  shared Saugra Console enrollment contract.
- Validate Console enrollment responses as WAF credentials and atomically
  persist returned node credentials with owner-only permissions on Unix.

### Security

- Keep one-time enrollment tokens outside YAML, with optional delivery through
  `SAUGRA_CONSOLE_ENROLLMENT_TOKEN` to avoid shell-history exposure.
- Reject credentials issued for another Saugra product and avoid printing the
  returned node credential in normal CLI output.

### Verified

- `cargo fmt --all -- --check`
- `cargo check --locked --all-targets --all-features`
- `cargo clippy --locked --all-targets --all-features -- -D warnings`
- `cargo test --locked --test console_integration --test cli`
- `cargo test --locked --all-targets --all-features` passed with 263 library
  tests, 10 CLI tests, 4 Console integration tests, and 27 proxy integration
  tests.
- `cargo deb --locked` built `saugra-waf_1.1.3-1_amd64.deb`; package metadata
  and contents were inspected with `dpkg-deb`.

## 1.1.2 - 2026-06-28

### Fixed

- Prevent disabled or off campaign correlation from opening Redis or local
  state during startup.
- Add path-specific context to campaign state and lock-file errors, and add
  listener bind context for startup failures.

### Verified

- `cargo fmt --check`
- `cargo check --locked --all-targets --all-features`
- `cargo clippy --locked --all-targets --all-features -- -D warnings`
- `cargo audit`
- `cargo test --lib campaign::tests::disabled_store_does_not_touch_local_state_path`
- `cargo test --locked --all-targets --all-features` passed with 261 library
  tests, 10 CLI tests, and 27 proxy integration tests.

## 1.1.1 - 2026-06-28

### Fixed

- Prevent disabled or off behavior, bot-protection, and unknown-threat stores
  from opening local state files during startup, avoiding systemd permission
  failures when optional local state paths are not writable.
- Add path-specific context to local behavior, bot-protection, and
  unknown-threat state-file errors so startup journals identify the failing
  file or directory.

### Verified

- `cargo fmt --check`
- `cargo check`
- `cargo test --lib unknown_threats::tests::disabled_store_does_not_touch_local_state_path`
- `cargo clippy --locked --all-targets --all-features -- -D warnings`
- `cargo audit`
- `cargo test --locked --all-targets --all-features` passed with 260 library
  tests, 10 CLI tests, and 27 proxy integration tests.

## 1.1.0 - 2026-06-15

### Added

- Add monitor-first unknown-threat learning with bounded baselines, guarded
  high-risk route enforcement, shadow review, cleanup, reporting, and durable
  local state.
- Add campaign correlation for multi-step and distributed activity, with
  configurable policy catalogs and Redis-backed production state.
- Add explain-only AI providers for local llama.cpp, Ollama, command, and
  explicitly opted-in remote endpoints.
- Add sanitized provider evaluation, anomaly review, rule drafting, replay,
  approval, and publication workflows while keeping deterministic policy
  authoritative.
- Add context-aware rule exclusions scoped by route, method, target, content
  type, query parameter, header, and trusted identity assertion.
- Add Codecov-backed pull-request coverage and dependency audit checks.

### Changed

- Upgrade Redis support from `0.27` to `1.2`, Axum from `0.7` to `0.8`, and
  thiserror from `1` to `2`.
- Upgrade maintained GitHub Actions and documentation dependencies.
- Consolidate public documentation into the README and canonical admin,
  architecture, and release guides.
- Expand packaged production assets with threat-intelligence catalogs, AI
  evaluation fixtures, and local provider service templates.

### Fixed

- Preserve URL-derived Redis connection settings when applying a separately
  configured password through the Redis 1.x public connection API.
- Restore pull-request CI checks and add focused coverage for Redis connection
  compatibility and callers.

### Upgrade Notes

- New unknown-threat and campaign-correlation controls remain monitor-first or
  disabled unless explicitly configured for enforcement.
- Review the updated production example before enabling AI providers,
  unknown-threat blocking, or campaign correlation.
- Production Redis deployments should verify credentials, selected database,
  rate-limit behavior, and campaign-state persistence after upgrading.

### Verified

- `cargo fmt --check`
- `cargo check --locked --all-targets --all-features`
- `cargo clippy --locked --all-targets --all-features -- -D warnings`
- 256 library tests, 10 CLI tests, and 25 proxy integration tests pass locally.
  Three HTTP-provider tests and two raw-socket WebSocket tests require loopback
  bind permission and remain covered by GitHub CI.
- `saugra-waf 1.1.0` builds as
  `target/debian/saugra-waf_1.1.0-1_amd64.deb`; package metadata and contents
  were inspected with `dpkg-deb`.
- The unsigned APT repository dry run contains Release and package-index
  metadata for `saugra-waf 1.1.0-1`.
- The portable source example passes `saugra-waf test-config`; release CI
  validates the production example after package installation seeds its
  operator-managed catalogs.

## 1.0.7 - 2026-06-09

### Added

- Add `behavior.probe_path_exclusions` and
  `bot_protection.scanner_path_exclusions` for narrowly tuning legitimate
  application routes without weakening deterministic attack rules.
- Record contributor paths in behavior and bot state, security events, and
  explanations while preserving compatibility with existing local state files.

### Fixed

- Prevent monitor-only bot and behavior threshold findings from contributing to
  the blocking anomaly score.
- Stop behavior scoring from counting the synthetic bot threshold finding a
  second time.
- Remove the overly broad `/admin` prefix from the bundled scanner-path catalog.
- Clarify explanations by reporting both total anomaly score and
  blocking-eligible score.

### Changed

- Update the admin runbook to use installed configuration discovery by default
  and reserve `--config` for explicit overrides.

### Documentation

- Document the live signed Ubuntu/Debian APT repository as the recommended
  installation and upgrade path.
- Record the public APT repository signing-key fingerprint.
- Add the GitHub Pages, deployment-tag rule, signing-key secret, and release-tag
  setup procedure to the README.

### Verified

- `cargo fmt --check`
- `cargo check --locked --all-targets --all-features`
- `cargo clippy --locked --all-targets --all-features -- -D warnings`
- 179 library tests, 8 CLI tests, and 25 proxy integration tests pass,
  including both raw-socket WebSocket tunnel tests.

## 1.0.6 - 2026-06-07

### Added

- Add APT repository dry-run tooling, GitHub Pages publishing, release
  install-test coverage, and an official Debian archive release plan.
- Build release packages on an Ubuntu 22.04 glibc baseline and install-test
  them on Ubuntu 22.04, Ubuntu 24.04, and Debian 12.
- Discover configuration from `--config`, `SAUGRA_WAF_CONFIG`, the installed
  `/etc/saugra-waf/saugra-waf.yml`, or the source-checkout example, in that
  precedence order.

### Changed

- Complete the runtime rename to `saugra-waf` across release install tests,
  package paths, service checks, APT artifacts, templates, verifier identifiers,
  the health endpoint, and repository asset names.
- Shorten plain-text and HTML security-summary email guidance to
  `saugra-waf explain <request-id>` now that installed config discovery is
  automatic.

### Verified

- `cargo fmt --check`
- `cargo check --locked --all-targets`
- `cargo clippy --locked --all-targets --all-features -- -D warnings`
- 176 library tests and 8 CLI integration tests pass.
- Debian package and APT repository metadata build locally.

## 1.0.5 - 2026-05-23

### Changed

- `saugra-waf explain` now prints request context before the rule explanation,
  including request ID, client IP, method, path, query when present, and
  upstream metadata when recorded.
- Summary email footer and production documentation now use the full
  production command:
  `saugra-waf explain <request-id> --config /etc/saugra-waf/saugra-waf.yml`.

### Verified

- `cargo fmt --check`
- Focused CLI explain regression test passes locally.

## 1.0.4 - 2026-05-22

### Added

- Professional HTML daily security summary emails with plain-text fallback.
- App hostname branding in summary emails, for example `Saugra WAF -
  EXAMPLE.COM`.
- Optional `app_hostname` field in generated summary JSON when summaries are
  produced from a configured upstream.

### Changed

- Security summary email delivery now sends the report in the email body
  instead of sending raw JSON as the message content.
- Summary email headers are centered for a cleaner operator-facing report.
- Admin documentation clarifies that email summaries are HTML while file output
  remains JSON for archiving and automation.

### Verified

- `cargo fmt --check`
- `cargo check --all-targets`
- Focused security summary email rendering test passes locally.

## 1.0.2 - 2026-05-22

### Added

- Scheduled local security summaries generated from durable JSONL event logs.
- `saugra-waf summary daily` and `saugra-waf summary send` commands for operator
  reporting workflows.
- File-based summary output with optional local sendmail-compatible email
  delivery.
- Local summary delivery failure events for operator troubleshooting.
- `security_summary` configuration in example and production configs.
- `saugra-waf state reset behavior` and `saugra-waf state reset bot` commands for
  clearing one client's local scoring state without deleting all state.
- Runtime policy reload regression tests for malformed JSON and no-restart
  policy mutation.
- `storage_cleanup` configuration and `saugra-waf cleanup run` for removing stale
  generated summary/admin/report files after a configured retention window.
- Production admin workflows for false positives, scanner bursts, upstream
  outages, Redis outages, WebSocket routing failures, summary scheduling, and
  stale-file cleanup.

### Verified

- Formatting and clippy pass locally.
- Example config validates with `saugra-waf test-config`.
- Focused tests for security summaries, runtime policy reloads, state reset,
  and storage cleanup pass locally.
- Full local test run passes all unit tests and all non-raw-socket proxy e2e
  tests; two WebSocket tunnel tests are blocked in this sandbox by loopback bind
  permissions and are expected to run in normal CI.

## 1.0.1 - 2026-05-21

### Added

- Production-oriented Debian package metadata for `cargo-deb`.
- Debian maintainer scripts that create the `saugra-waf` service user, seed
  `/etc/saugra-waf`, and preserve operator-managed state and logs.
- Packaged systemd unit for `/usr/bin/saugra-waf`.
- Bundled package assets for production config, rule packs, standards data,
  scanner intelligence catalogs, and deployment documentation.
- GitHub Release workflow that runs tests, builds the `.deb`, and uploads it to
  the tagged release.
- Debian packaging and release process documentation.

### Verified

- Full Rust test suite passes with `cargo test --locked --all-targets --all-features`.
- Debian package builds with `cargo deb --locked`.
- Package contents include the binary, systemd unit, docs, config seed assets,
  rules, standards catalog, scanner catalog, maintainer scripts, and AGPL
  license text.
