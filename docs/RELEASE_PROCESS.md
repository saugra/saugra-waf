# Release Process

This is the canonical maintainer guide for local `.deb` packaging, GitHub
Releases, the signed Saugra APT repository, and future official Debian work.

## One-Time Repository Setup

Enable GitHub Pages with **GitHub Actions** as the source and restrict the
`github-pages` environment to version tags matching `v*.*.*`.

Create a dedicated APT signing key in an isolated GPG home:

```bash
export GNUPGHOME="$HOME/.saugra-waf-apt-gnupg"
install -d -m 700 "$GNUPGHOME"
gpg --quick-generate-key \
  "Saugra WAF APT Repository <releases@saugra-waf.dev>" \
  rsa4096 sign 2y
gpg --list-secret-keys --with-subkey-fingerprint
```

Configure `SAUGRA_APT_GPG_KEY_ID`, `SAUGRA_APT_GPG_PRIVATE_KEY`, and
`SAUGRA_APT_GPG_PASSPHRASE` as GitHub Actions secrets. Keep an encrypted
offline backup and never commit exported private keys.

### Console Contracts Dependency Token

Release builds fetch the private `saugra/saugra-console-contracts` repository.
Create a dedicated fine-grained personal access token instead of reusing a
maintainer token with broad organization or account permissions:

1. In GitHub, open **Settings**, **Developer settings**, **Personal access
   tokens**, **Fine-grained tokens**, then select **Generate new token**.
2. Use a recognizable name such as `saugra-waf-contracts-read` and choose the
   shortest practical expiration allowed by the organization.
3. Select `saugra` as the resource owner. If the organization requires token
   approval, enter a release-build justification and wait for approval before
   tagging a release.
4. Under **Repository access**, select **Only select repositories**, then choose
   only `saugra-console-contracts`.
5. Under **Repository permissions**, grant **Contents: Read-only**. Leave all
   other optional repository and organization permissions unset.
6. Generate the token and copy it once. Never paste it into issues, chat, shell
   history, YAML, logs, commits, or release notes.

Store the token as an Actions secret on the WAF repository. This command reads
the value interactively; paste the token and press `Ctrl+D`:

```bash
gh secret set SAUGRA_CONTRACTS_TOKEN --repo saugra/saugra-waf
```

Alternatively, open the `saugra/saugra-waf` repository in GitHub and use
**Settings**, **Secrets and variables**, **Actions**, **New repository secret**.
Name the secret exactly `SAUGRA_CONTRACTS_TOKEN`.

Confirm that the secret name is present without exposing its value:

```bash
gh secret list --repo saugra/saugra-waf
```

Release CI verifies that this token can read the pinned contracts tag before
installing Rust or running Cargo. A missing, expired, unapproved, or
under-scoped token fails immediately with an error naming
`SAUGRA_CONTRACTS_TOKEN` and `saugra/saugra-console-contracts`. Rotate the token
before expiration by generating a replacement with the same minimal access and
running `gh secret set` again; GitHub replaces the stored value atomically.

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

The release workflow builds on Ubuntu 22.04 as the binary compatibility
baseline, then install-tests on Ubuntu 22.04, Ubuntu 24.04, and Debian 12.

## Publish

Commit the release changes:

```bash
git add Cargo.toml README.md CHANGELOG.md docs/RELEASE_PROCESS.md .github/workflows/release.yml packaging
git commit -m "Prepare v1.1.0 release"
```

Create and push an annotated tag:

```bash
git tag -a v1.1.0 -m "Saugra v1.1.0"
git push origin main
git push origin v1.1.0
```

The release workflow creates or updates the GitHub Release, generates release
notes from GitHub commit and pull request metadata, install-tests the package on
Ubuntu and Debian containers, builds and install-tests an unsigned APT
repository dry-run artifact, publishes the signed APT repository to GitHub
Pages, and uploads the `.deb` artifact from `target/debian/`.

## After Publishing

1. Verify the GitHub Pages APT repository:

```bash
curl -fsSL https://saugra.github.io/saugra-waf/saugra-waf.gpg | sudo gpg --dearmor -o /usr/share/keyrings/saugra-waf.gpg
echo "deb [signed-by=/usr/share/keyrings/saugra-waf.gpg] https://saugra.github.io/saugra-waf/apt stable main" | sudo tee /etc/apt/sources.list.d/saugra-waf.list
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

## APT Repository

Release CI publishes signed metadata and packages to:

```txt
https://saugra.github.io/saugra-waf/apt
```

Production instructions must use `signed-by=` with a key under
`/usr/share/keyrings`; never use the deprecated global `apt-key` flow.

Build an unsigned local archive for verification:

```bash
sudo apt install apt-utils dpkg-dev
scripts/build-apt-repository.sh \
  --output apt-repo \
  target/debian/saugra-waf_*.deb
```

`trusted=yes` is acceptable only for a local dry run. Release tags must use the
dedicated signing key and trusted CI. Package upgrades must preserve
operator-owned configuration, seed bundled files only when missing, and never
start Saugra before the upstream and monitor-first configuration are reviewed.
Public upgrade instructions must keep installed packages on hold by default,
unhold them only during a planned maintenance window, and mask
`saugra-waf.service` while package files are being replaced.

## Official Debian Archive

The `cargo-deb` artifact is for GitHub Releases and the Saugra APT repository.
Official Debian inclusion requires source packaging under `debian/`,
Debian-packaged Rust dependencies, network-free builds, machine-readable
copyright metadata, `lintian`, clean `sbuild` or `pbuilder` builds, an ITP,
mentors upload, and sponsor review. Track that long-term work in `ROADMAP.md`.
