# Changelog

All notable changes to Saugra are documented here.

## Unreleased

- Add follow-up changes here before tagging the next release.

## 1.0.4 - 2026-05-22

### Added

- Professional HTML daily security summary emails with plain-text fallback.
- App hostname branding in summary emails, for example `Saugra WAF -
  CONFERENCE.KE`.
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
- `saugra summary daily` and `saugra summary send` commands for operator
  reporting workflows.
- File-based summary output with optional local sendmail-compatible email
  delivery.
- Local summary delivery failure events for operator troubleshooting.
- `security_summary` configuration in example and production configs.
- `saugra state reset behavior` and `saugra state reset bot` commands for
  clearing one client's local scoring state without deleting all state.
- Runtime policy reload regression tests for malformed JSON and no-restart
  policy mutation.
- `storage_cleanup` configuration and `saugra cleanup run` for removing stale
  generated summary/admin/report files after a configured retention window.
- Production admin workflows for false positives, scanner bursts, upstream
  outages, Redis outages, WebSocket routing failures, summary scheduling, and
  stale-file cleanup.

### Verified

- Formatting and clippy pass locally.
- Example config validates with `saugra test-config`.
- Focused tests for security summaries, runtime policy reloads, state reset,
  and storage cleanup pass locally.
- Full local test run passes all unit tests and all non-raw-socket proxy e2e
  tests; two WebSocket tunnel tests are blocked in this sandbox by loopback bind
  permissions and are expected to run in normal CI.

## 1.0.1 - 2026-05-21

### Added

- Production-oriented Debian package metadata for `cargo-deb`.
- Debian maintainer scripts that create the `saugra` service user, seed
  `/etc/saugra`, and preserve operator-managed state and logs.
- Packaged systemd unit for `/usr/bin/saugra`.
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
