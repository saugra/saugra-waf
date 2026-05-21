# Release Process

This checklist is for maintainers publishing Saugra releases.

## Prepare

1. Confirm the version in `Cargo.toml`.
2. Update `CHANGELOG.md` with the release date and notable changes.
3. Run formatting, linting, and tests:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
```

4. Build and inspect the Debian package:

```bash
cargo install cargo-deb --version 3.6.0 --locked
cargo deb --locked
dpkg-deb -I target/debian/saugra_*.deb
dpkg-deb -c target/debian/saugra_*.deb
```

5. On a Debian or Ubuntu host, install-test the package:

```bash
sudo apt install ./target/debian/saugra_*.deb
saugra test-config --config /etc/saugra/saugra.yml
```

## Publish

Commit the release changes:

```bash
git add Cargo.toml README.md CHANGELOG.md docs/DEBIAN_PACKAGING.md docs/RELEASE_PROCESS.md .github/workflows/release.yml packaging
git commit -m "Prepare v1.0.1 release"
```

Create and push an annotated tag:

```bash
git tag -a v1.0.1 -m "Saugra v1.0.1"
git push origin main
git push origin v1.0.1
```

The release workflow creates or updates the GitHub Release, generates release
notes from GitHub commit and pull request metadata, and uploads the `.deb`
artifact from `target/debian/`.

## After Publishing

1. Download the `.deb` from the GitHub Release.
2. Install it on a clean Debian or Ubuntu host.
3. Validate `/etc/saugra/saugra.yml`.
4. Confirm the service can start after configuring the upstream application:

```bash
sudo systemctl enable --now saugra
curl -i http://127.0.0.1:8787/_saugra/health
```

5. Attach any manually curated release notes from `CHANGELOG.md` to the GitHub
   Release if the generated notes need security or operator context.
