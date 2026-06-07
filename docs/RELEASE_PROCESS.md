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
dpkg-deb -I target/debian/saugra-waf_*.deb
dpkg-deb -c target/debian/saugra-waf_*.deb
sudo apt install apt-utils dpkg-dev
scripts/build-apt-repository.sh --output apt-repo target/debian/saugra-waf_*.deb
```

5. On a Debian or Ubuntu host, install-test the package:

```bash
sudo apt install ./target/debian/saugra-waf_*.deb
saugra-waf test-config --config /etc/saugra-waf/saugra-waf.yml
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
notes from GitHub commit and pull request metadata, install-tests the package on
Ubuntu and Debian containers, builds and install-tests an unsigned APT
repository dry-run artifact, publishes the signed APT repository to GitHub
Pages, and uploads the `.deb` artifact from `target/debian/`.

## After Publishing

1. Verify the GitHub Pages APT repository:

```bash
curl -fsSL https://ewanyonyi.github.io/saugra-waf/saugra-waf.gpg | sudo gpg --dearmor -o /usr/share/keyrings/saugra-waf.gpg
echo "deb [signed-by=/usr/share/keyrings/saugra-waf.gpg] https://ewanyonyi.github.io/saugra-waf/apt stable main" | sudo tee /etc/apt/sources.list.d/saugra-waf.list
sudo apt update
sudo apt install saugra-waf
saugra-waf test-config --config /etc/saugra-waf/saugra-waf.yml
```

2. Download the `.deb` from the GitHub Release as fallback verification.
3. Install it on a clean Debian or Ubuntu host.
4. Validate `/etc/saugra-waf/saugra-waf.yml`.
5. Confirm the service can start after configuring the upstream application:

```bash
sudo systemctl enable --now saugra-waf
curl -i http://127.0.0.1:8787/_saugra-waf/health
```

6. Attach any manually curated release notes from `CHANGELOG.md` to the GitHub
   Release if the generated notes need security or operator context.
