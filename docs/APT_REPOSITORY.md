# Saugra APT Repository

This guide describes the planned signed APT repository for Saugra packages on
Ubuntu and Debian.

The current release path publishes `.deb` artifacts to GitHub Releases. A signed
APT repository is the next distribution step so operators can install and
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

The intended user-facing install flow is:

```bash
curl -fsSL https://repo.saugra.dev/saugra.gpg | sudo gpg --dearmor -o /usr/share/keyrings/saugra.gpg
echo "deb [signed-by=/usr/share/keyrings/saugra.gpg] https://repo.saugra.dev/apt stable main" | sudo tee /etc/apt/sources.list.d/saugra.list
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

6. Install-test on clean Ubuntu and Debian hosts:

```bash
sudo apt install ./target/debian/saugra_*.deb
saugra test-config --config /etc/saugra/saugra.yml
systemctl status saugra
```

7. Tag and publish the GitHub Release:

```bash
git tag -a v1.0.5 -m "Saugra v1.0.5"
git push origin main
git push origin v1.0.5
```

8. Publish the `.deb` artifact to the signed APT repository.
9. Run an end-to-end install from the repository:

```bash
sudo apt update
sudo apt install saugra
saugra test-config --config /etc/saugra/saugra.yml
```

## Repository Tooling Options

Use one repository tool and keep the release workflow reproducible.

Recommended options:

- `reprepro`: simple, widely used, suitable for a small signed repository.
- `aptly`: stronger snapshot and promotion workflows.
- Hosted package registry: useful if repository signing, hosting, and retention
  are delegated to a trusted service.

For Saugra, `reprepro` is a good first implementation because the repository
can start small and remain easy to inspect.

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

The release workflow should eventually:

1. Run tests.
2. Build `.deb` artifacts.
3. Install-test the package in clean Ubuntu and Debian containers.
4. Upload the package to the GitHub Release.
5. Add the package to the APT repository.
6. Regenerate repository metadata.
7. Sign the repository metadata.
8. Publish the repository to the hosting target.
9. Verify installation using the public repository URL.

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

## Open Work

- Choose repository hosting.
- Create a dedicated repository signing key.
- Add CI jobs for clean install tests.
- Add CI publishing for the signed repository.
- Add `arm64` package builds and install tests.
- Document repository key rotation.
- Add rollback and package retention policy.
