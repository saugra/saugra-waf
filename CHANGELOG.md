# Changelog

All notable changes to Saugra are documented here.

## Unreleased

- Add follow-up changes here before tagging the next release.

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
