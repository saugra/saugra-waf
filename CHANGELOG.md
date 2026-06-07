# Changelog

All notable changes to Saugra are documented here.

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
