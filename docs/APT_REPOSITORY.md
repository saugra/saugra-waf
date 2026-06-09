# Saugra APT Repository

This guide describes the signed APT repository for Saugra packages on Ubuntu
and Debian.

The current release path publishes `.deb` artifacts to GitHub Releases. A signed
APT repository is published with GitHub Pages so operators can install and
upgrade Saugra with normal `apt` workflows.

```txt
Git tag -> CI build -> .deb package -> signed APT repository -> apt install saugra-waf
```

## Goals

- Publish Saugra packages through a signed repository.
- Support Ubuntu LTS releases and current Debian stable releases.
- Keep install and upgrade commands simple for production operators.
- Preserve monitor-first deployment defaults after install.
- Make package provenance clear with repository signing.
- Keep GitHub Release `.deb` artifacts as a fallback install path.

## User Install Flow

Install the required HTTPS and signing-key tools:

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
```

Add the public signing key, configure the signed repository, and install Saugra:

```bash
curl -fsSL https://saugra.github.io/saugra-waf/saugra-waf.gpg |
  sudo gpg --dearmor --yes -o /usr/share/keyrings/saugra-waf.gpg

echo "deb [signed-by=/usr/share/keyrings/saugra-waf.gpg] https://saugra.github.io/saugra-waf/apt stable main" |
  sudo tee /etc/apt/sources.list.d/saugra-waf.list

sudo apt update
sudo apt install saugra-waf
```

The published signing-key fingerprint is:

```txt
8992 2EB2 4DFF 0CF9 E29F 6048 5C90 F14F C121 4E24
```

After installation, operators should edit the generated config before starting
the service:

```bash
sudo editor /etc/saugra-waf/saugra-waf.yml
sudo saugra-waf test-config --config /etc/saugra-waf/saugra-waf.yml
sudo systemctl enable --now saugra-waf
```

The package must not enable or start Saugra automatically. The upstream
application, proxy headers, event logging, and rollout mode need to be reviewed
first.

## Repository Layout

The repository should follow the standard Debian archive layout:

```txt
apt/
├── dists/
│   └── stable/
│       ├── InRelease
│       ├── Release
│       ├── Release.gpg
│       └── main/
│           ├── binary-amd64/
│           │   ├── Packages
│           │   └── Packages.gz
│           └── binary-arm64/
│               ├── Packages
│               └── Packages.gz
└── pool/
    └── main/
        └── s/
            └── saugra-waf/
                └── saugra-waf_<version>_<arch>.deb
```

Start with `amd64`. Add `arm64` when CI builds and install tests are available
for that architecture.

The `amd64` package is built on Ubuntu 22.04 to keep its glibc requirement
compatible with Debian 12 and newer supported Ubuntu releases. Release CI then
install-tests the same package on Ubuntu 22.04, Ubuntu 24.04, and Debian 12.

## Maintainer Release Flow

1. Confirm the version in `Cargo.toml`.
2. Update `CHANGELOG.md` and release notes.
3. Run the normal verification suite:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
```

4. Build the package:

```bash
cargo deb --locked
```

5. Inspect the package:

```bash
dpkg-deb -I target/debian/saugra-waf_*.deb
dpkg-deb -c target/debian/saugra-waf_*.deb
```

6. Build and inspect the repository metadata:

```bash
sudo apt install apt-utils dpkg-dev
scripts/build-apt-repository.sh --output apt-repo target/debian/saugra-waf_*.deb
find apt-repo/dists/stable -maxdepth 3 -type f -print
```

7. Test installation through the generated repository:

```bash
echo "deb [trusted=yes] file:$PWD/apt-repo stable main" | sudo tee /etc/apt/sources.list.d/saugra-waf-local.list
sudo apt update
sudo apt install saugra-waf
saugra-waf test-config --config /etc/saugra-waf/saugra-waf.yml
```

The `trusted=yes` form is only for local unsigned dry runs. Production
repositories must use the signed-by flow shown above.

8. Install-test the standalone package on clean Ubuntu and Debian hosts:

```bash
sudo apt install ./target/debian/saugra-waf_*.deb
saugra-waf test-config --config /etc/saugra-waf/saugra-waf.yml
systemctl status saugra-waf
```

9. Tag and publish the GitHub Release:

```bash
git tag -a v1.0.7 -m "Saugra v1.0.7"
git push origin main
git push origin v1.0.7
```

10. Release CI publishes the signed APT repository to GitHub Pages.
11. Run an end-to-end install from the repository:

```bash
curl -fsSL https://saugra.github.io/saugra-waf/saugra-waf.gpg | sudo gpg --dearmor -o /usr/share/keyrings/saugra-waf.gpg
echo "deb [signed-by=/usr/share/keyrings/saugra-waf.gpg] https://saugra.github.io/saugra-waf/apt stable main" | sudo tee /etc/apt/sources.list.d/saugra-waf.list
sudo apt update
sudo apt install saugra-waf
saugra-waf test-config --config /etc/saugra-waf/saugra-waf.yml
```

## GitHub Pages Publishing

Release tags publish the APT repository as a GitHub Pages artifact. The Pages
site contains:

```txt
site/
├── .nojekyll
├── saugra-waf.gpg
└── apt/
    ├── dists/
    └── pool/
```

The public repository URL is:

```txt
https://saugra.github.io/saugra-waf/apt
```

If the `repo.saugra-waf.dev` custom domain is configured for GitHub Pages, the same
repository is available at:

```txt
https://repo.saugra-waf.dev/apt
```

Required repository settings:

- Enable GitHub Pages for the repository.
- Set Pages source to GitHub Actions.
- Optionally configure `repo.saugra-waf.dev` as the custom domain.

Required GitHub Actions secrets:

- `SAUGRA_APT_GPG_KEY_ID`: dedicated APT repository signing key ID.
- `SAUGRA_APT_GPG_PRIVATE_KEY`: ASCII-armored private key for the dedicated APT
  repository signing key.
- `SAUGRA_APT_GPG_PASSPHRASE`: passphrase for the dedicated APT
  repository signing key.

The workflow exports the matching public key to `saugra-waf.gpg`, signs the
repository metadata, uploads the Pages artifact, and deploys it with
`actions/deploy-pages`.

## Repository Tooling

Use one repository tool and keep the release workflow reproducible. Saugra's
current APT repository tooling is `scripts/build-apt-repository.sh`, published
through GitHub Pages.

Future options if repository management needs grow:

- `reprepro`: simple, widely used, suitable for a small signed repository.
- `aptly`: stronger snapshot and promotion workflows.
- Hosted package registry: useful if repository signing, hosting, and retention
  are delegated to a trusted service.

The repository builder in `scripts/build-apt-repository.sh` provides the first
reproducible archive layout for release dry runs and CI validation. It generates
`Packages`, `Packages.gz`, and `Release` metadata from built `.deb` artifacts.
When a dedicated release key is available in the current GPG home, pass
`--signing-key <key-id>` or set `SAUGRA_APT_SIGNING_KEY_ID` to produce
`Release.gpg` and `InRelease`.

## Signing Requirements

The APT repository must be signed with a dedicated release key.

Requirements:

- Do not reuse a personal developer GPG key.
- Store the private key only in CI secrets or an equivalent secure release
  environment.
- Publish the public key at a stable HTTPS URL.
- Sign repository metadata, not only package files.
- Rotate keys with a documented overlap period.

The user install instructions should always use `signed-by=` with a key stored
under `/usr/share/keyrings/`. Do not instruct users to add repository keys with
global `apt-key`.

### Create The Dedicated Signing Key

Create the key on a trusted maintainer machine, preferably using a temporary
isolated GPG home:

```bash
export GNUPGHOME="$PWD/.release-gnupg"
install -d -m 700 "$GNUPGHOME"
gpg --quick-generate-key \
  "Saugra WAF APT Repository <releases@saugra-waf.dev>" \
  rsa4096 sign 2y
gpg --list-secret-keys --keyid-format long
```

Record the signing-key ID shown after `rsa4096/`. Export the CI secret and
public key:

```bash
gpg --armor --export-secret-keys <KEY-ID> > saugra-waf-apt-private.asc
gpg --armor --export <KEY-ID> > saugra-waf.gpg
```

Store `saugra-waf-apt-private.asc` only in the GitHub Actions secret
`SAUGRA_APT_GPG_PRIVATE_KEY`, set `<KEY-ID>` as `SAUGRA_APT_GPG_KEY_ID`, and
store the key's strong, dedicated passphrase as `SAUGRA_APT_GPG_PASSPHRASE`.
Securely delete the exported private-key file after the secrets are configured.
Keep an encrypted offline backup of the original GPG home. The release workflow
publishes the exported public key as `saugra-waf.gpg`.

## CI Publishing Requirements

The release workflow:

1. Run tests.
2. Build `.deb` artifacts.
3. Install-test the package in clean Ubuntu and Debian containers.
4. Build an unsigned APT repository dry-run artifact.
5. Install-test the unsigned APT repository dry run in an Ubuntu container.
6. Upload the package to the GitHub Release.
7. Import the dedicated repository signing key from trusted release secrets.
8. Generate a signed APT repository under `site/apt`.
9. Export the public key to `site/saugra-waf.gpg`.
10. Publish the repository with GitHub Pages.

The release workflow should eventually verify installation using the public
GitHub Pages URL after deployment completes.

Repository publishing should run only for trusted release tags.

## Package Behavior Requirements

The APT package must preserve the current production behavior:

- Install `/usr/bin/saugra-waf`.
- Install the systemd unit.
- Create the `saugra-waf` service user and group.
- Seed `/etc/saugra-waf/saugra-waf.yml` only when missing.
- Seed bundled rules, standards, and intelligence catalogs only when missing.
- Create `/var/log/saugra-waf` and `/var/lib/saugra-waf`.
- Leave existing operator config untouched during upgrades.
- Avoid starting or enabling the service automatically.

Operators should explicitly start Saugra after configuration has been reviewed.

## Relationship To Other Channels

GitHub Releases are the immediate binary distribution channel. They are useful
for manual installs, testing, and rollback.

The signed Saugra APT repository is the recommended production channel. It
gives operators normal `apt update` and `apt upgrade` workflows.

Ubuntu PPAs are useful for Ubuntu-specific testing and discovery, but they are
not a Debian distribution channel.

Official Debian and Ubuntu archive inclusion is a separate long-term process.
That path requires source packaging, Debian policy compliance, copyright
metadata, and maintainer or sponsor review.

See `docs/OFFICIAL_DEBIAN_RELEASE.md` for the official Debian archive release
plan. The Saugra-owned signed APT repository remains the near-term production
install channel while that longer process is prepared.

## Open Work

- Optionally configure `repo.saugra-waf.dev` as the Pages custom domain.
- Add post-deploy public repository install verification.
- Add `arm64` package builds and install tests.
- Document repository key rotation.
- Add rollback and package retention policy.
