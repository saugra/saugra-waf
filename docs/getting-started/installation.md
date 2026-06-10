# Installation

The recommended installation path for Ubuntu and Debian is the signed Saugra
APT repository. It provides normal package upgrades and installs the binary,
systemd service, example configuration, and bundled security data.

## Ubuntu or Debian

Install repository prerequisites:

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg redis-server
```

Add the signing key and repository:

```bash
curl -fsSL https://saugra.github.io/saugra-waf/saugra-waf.gpg |
  sudo gpg --dearmor --yes -o /usr/share/keyrings/saugra-waf.gpg

echo "deb [signed-by=/usr/share/keyrings/saugra-waf.gpg] https://saugra.github.io/saugra-waf/apt stable main" |
  sudo tee /etc/apt/sources.list.d/saugra-waf.list
```

Install Saugra:

```bash
sudo apt update
sudo apt install saugra-waf
```

Confirm the installation:

```bash
saugra-waf --version
sudo systemctl status saugra-waf --no-pager
```

The service may remain stopped until its configuration is valid. Continue with
the [quick start](quick-start.md) before exposing traffic.

## Release Package

Download the appropriate `.deb` from the
[GitHub Releases page](https://github.com/saugra/saugra-waf/releases/latest),
then install it with APT so dependencies are resolved:

```bash
sudo apt install ./saugra-waf_<version>-1_amd64.deb
```

## Build From Source

Install a current Rust toolchain using [rustup](https://rustup.rs/), then:

```bash
git clone https://github.com/saugra/saugra-waf.git
cd saugra-waf
cargo build --release --locked
```

Validate the repository example configuration:

```bash
cargo run --release --locked --bin saugra-waf -- \
  test-config --config configs/saugra-waf.example.yml
```

Run Saugra from the checkout:

```bash
cargo run --release --locked --bin saugra-waf -- \
  run --config configs/saugra-waf.example.yml
```

Source builds are useful for development and evaluation. For a production
service installation, follow the complete
[production deployment guide](../PRODUCTION_DEPLOYMENT.md).

## Installed Paths

Typical package installations use:

| Path | Purpose |
| --- | --- |
| `/usr/bin/saugra-waf` | CLI and proxy binary |
| `/etc/saugra-waf/saugra-waf.yml` | Active configuration |
| `/etc/saugra-waf/rules/` | Installed rule packs |
| `/var/log/saugra-waf/` | Structured security events |
| `/var/lib/saugra-waf/` | Runtime policy and local state |
| `/lib/systemd/system/saugra-waf.service` | systemd service |
