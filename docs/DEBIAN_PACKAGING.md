# Debian Packaging

Saugra can be built as a `.deb` package with `cargo-deb`. The package installs
the `saugra-waf` binary, a systemd unit, production example configuration, bundled
rule packs, standards data, and scanner intelligence catalogs.

## Local Build

Install the packaging tool:

```bash
cargo install cargo-deb --version 3.6.0 --locked
```

Run the normal test suite before packaging:

```bash
cargo test --locked --all-targets --all-features
```

Build the package:

```bash
cargo deb --locked
```

The `.deb` artifact is written under `target/debian/`.

## Local Install Test

Install the package on a Debian or Ubuntu host:

```bash
sudo apt install ./target/debian/saugra-waf_*.deb
```

Validate the seeded production config:

```bash
saugra-waf test-config --config /etc/saugra-waf/saugra-waf.yml
```

The package does not start or enable Saugra automatically. Configure the
upstream application first, keep the default monitor-first posture during
rollout, then start the service explicitly:

```bash
sudo systemctl enable --now saugra-waf
```

## GitHub Release Publishing

Pushing a version tag builds and uploads the `.deb` artifact to the matching
GitHub Release:

```bash
git tag v1.0.6
git push origin v1.0.6
```

The release workflow runs tests, installs `cargo-deb`, builds the package, and
uploads `target/debian/*.deb` as release assets.

## Signed APT Repository

GitHub Release assets are the fallback `.deb` distribution path. The production
package channel is a signed APT repository published with GitHub Pages so
operators can install and upgrade Saugra with normal `apt` workflows.

Release CI builds an unsigned APT repository dry-run artifact to validate the
Debian archive layout before publishing. Maintainers can run the same check
locally:

```bash
sudo apt install apt-utils dpkg-dev
scripts/build-apt-repository.sh --output apt-repo target/debian/saugra-waf_*.deb
```

See `docs/APT_REPOSITORY.md` for the repository layout, signing requirements,
maintainer workflow, and CI publishing plan.
