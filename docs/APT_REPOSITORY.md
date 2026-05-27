# Saugra APT Repository

This guide describes the signed APT repository for Saugra packages on Ubuntu
and Debian.

The current release path publishes `.deb` artifacts to GitHub Releases. A signed
APT repository is published with GitHub Pages so operators can install and
upgrade Saugra with normal `apt` workflows.

```txt
Git tag -> CI build -> .deb package -> signed APT repository -> apt install saugra
```

## Goals

- Publish Saugra packages through a signed repository.
- Support Ubuntu LTS releases and current Debian stable releases.
- Keep install and upgrade commands simple for production operators.
- Preserve monitor-first deployment defaults after install.
- Make package provenance clear with repository signing.
- Keep GitHub Release `.deb` artifacts as a fallback install path.

## User Install Flow

The intended user-facing install flow for the custom repository domain is:

```bash
curl -fsSL https://repo.saugra.dev/saugra.gpg | sudo gpg --dearmor -o /usr/share/keyrings/saugra.gpg
echo "deb [signed-by=/usr/share/keyrings/saugra.gpg] https://repo.saugra.dev/apt stable main" | sudo tee /etc/apt/sources.list.d/saugra.list
sudo apt update
sudo apt install saugra
```

Before `repo.saugra.dev` is configured as a custom domain, the GitHub Pages URL
is:

```bash
curl -fsSL https://ewanyonyi.github.io/saugra/saugra.gpg | sudo gpg --dearmor -o /usr/share/keyrings/saugra.gpg
echo "deb [signed-by=/usr/share/keyrings/saugra.gpg] https://ewanyonyi.github.io/saugra/apt stable main" | sudo tee /etc/apt/sources.list.d/saugra.list
sudo apt update
sudo apt install saugra
```

After installation, operators should edit the generated config before starting
the service:

```bash
sudo editor /etc/saugra/saugra.yml
sudo saugra test-config --config /etc/saugra/saugra.yml
sudo systemctl enable --now saugra
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
            └── saugra/
                └── saugra_<version>_<arch>.deb
```

Start with `amd64`. Add `arm64` when CI builds and install tests are available
for that architecture.

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
dpkg-deb -I target/debian/saugra_*.deb
dpkg-deb -c target/debian/saugra_*.deb
```

6. Build and inspect the repository metadata:

```bash
sudo apt install apt-utils dpkg-dev
scripts/build-apt-repository.sh --output apt-repo target/debian/saugra_*.deb
find apt-repo/dists/stable -maxdepth 3 -type f -print
```

7. Test installation through the generated repository:

```bash
echo "deb [trusted=yes] file:$PWD/apt-repo stable main" | sudo tee /etc/apt/sources.list.d/saugra-local.list
sudo apt update
sudo apt install saugra
saugra test-config --config /etc/saugra/saugra.yml
```

The `trusted=yes` form is only for local unsigned dry runs. Production
repositories must use the signed-by flow shown above.

8. Install-test the standalone package on clean Ubuntu and Debian hosts:

```bash
sudo apt install ./target/debian/saugra_*.deb
saugra test-config --config /etc/saugra/saugra.yml
systemctl status saugra
```

9. Tag and publish the GitHub Release:

```bash
git tag -a v1.0.5 -m "Saugra v1.0.5"
git push origin main
git push origin v1.0.5
```

10. Release CI publishes the signed APT repository to GitHub Pages.
11. Run an end-to-end install from the repository:

```bash
curl -fsSL https://ewanyonyi.github.io/saugra/saugra.gpg | sudo gpg --dearmor -o /usr/share/keyrings/saugra.gpg
echo "deb [signed-by=/usr/share/keyrings/saugra.gpg] https://ewanyonyi.github.io/saugra/apt stable main" | sudo tee /etc/apt/sources.list.d/saugra.list
sudo apt update
sudo apt install saugra
saugra test-config --config /etc/saugra/saugra.yml
```

## GitHub Pages Publishing

Release tags publish the APT repository as a GitHub Pages artifact. The Pages
site contains:

```txt
site/
├── .nojekyll
├── saugra.gpg
└── apt/
    ├── dists/
    └── pool/
```

The public repository URL is:

```txt
https://ewanyonyi.github.io/saugra/apt
```

If the `repo.saugra.dev` custom domain is configured for GitHub Pages, the same
repository is available at:

```txt
https://repo.saugra.dev/apt
```

Required repository settings:

- Enable GitHub Pages for the repository.
- Set Pages source to GitHub Actions.
- Optionally configure `repo.saugra.dev` as the custom domain.

Required GitHub Actions secrets:

- `SAUGRA_APT_GPG_KEY_ID`: dedicated APT repository signing key ID.
- `SAUGRA_APT_GPG_PRIVATE_KEY`: ASCII-armored private key for the dedicated APT
  repository signing key.
- `SAUGRA_APT_GPG_PASSPHRASE`: optional passphrase for the dedicated APT
  repository signing key.

The workflow exports the matching public key to `saugra.gpg`, signs the
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
9. Export the public key to `site/saugra.gpg`.
10. Publish the repository with GitHub Pages.

The release workflow should eventually verify installation using the public
GitHub Pages URL after deployment completes.

Repository publishing should run only for trusted release tags.

## Package Behavior Requirements

The APT package must preserve the current production behavior:

- Install `/usr/bin/saugra`.
- Install the systemd unit.
- Create the `saugra` service user and group.
- Seed `/etc/saugra/saugra.yml` only when missing.
- Seed bundled rules, standards, and intelligence catalogs only when missing.
- Create `/var/log/saugra` and `/var/lib/saugra`.
- Leave existing operator config untouched during upgrades.
- Avoid starting or enabling the service automatically.

Operators should explicitly start Saugra after configuration has been reviewed.

## Relationship To Other Channels

GitHub Releases are the immediate binary distribution channel. They are useful
for manual installs, testing, and rollback.

The signed Saugra APT repository is the recommended production channel once it
exists. It gives operators normal `apt update` and `apt upgrade` workflows.

Ubuntu PPAs are useful for Ubuntu-specific testing and discovery, but they are
not a Debian distribution channel.

Official Debian and Ubuntu archive inclusion is a separate long-term process.
That path requires source packaging, Debian policy compliance, copyright
metadata, and maintainer or sponsor review.

See `docs/OFFICIAL_DEBIAN_RELEASE.md` for the official Debian archive release
plan. The Saugra-owned signed APT repository remains the near-term production
install channel while that longer process is prepared.

## Open Work

- Create a dedicated repository signing key.
- Enable GitHub Pages with GitHub Actions as the Pages source.
- Add `SAUGRA_APT_GPG_KEY_ID` and `SAUGRA_APT_GPG_PRIVATE_KEY` repository
  secrets.
- Optionally configure `repo.saugra.dev` as the Pages custom domain.
- Add post-deploy public repository install verification.
- Add `arm64` package builds and install tests.
- Document repository key rotation.
- Add rollback and package retention policy.
