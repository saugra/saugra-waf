#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: build-apt-repository.sh [options] <package.deb>...

Build a minimal Debian/Ubuntu APT repository from one or more Saugra .deb
artifacts.

Options:
  --output <dir>        Repository output directory. Default: apt-repo
  --codename <name>     Distribution codename/suite. Default: stable
  --component <name>    Repository component. Default: main
  --arch <arch>         Package architecture. Default: amd64
  --signing-key <id>    Optional GPG key id used to sign Release metadata
  -h, --help            Show this help

The script requires dpkg-scanpackages and apt-ftparchive. Signing additionally
requires gpg and a private key in the current GPG home. If the key has a
passphrase, set SAUGRA_APT_GPG_PASSPHRASE.
USAGE
}

output_dir="apt-repo"
codename="stable"
component="main"
arch="amd64"
signing_key="${SAUGRA_APT_SIGNING_KEY_ID:-}"
packages=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      output_dir="${2:?missing value for --output}"
      shift 2
      ;;
    --codename)
      codename="${2:?missing value for --codename}"
      shift 2
      ;;
    --component)
      component="${2:?missing value for --component}"
      shift 2
      ;;
    --arch)
      arch="${2:?missing value for --arch}"
      shift 2
      ;;
    --signing-key)
      signing_key="${2:?missing value for --signing-key}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      packages+=("$1")
      shift
      ;;
  esac
done

if [ "${#packages[@]}" -eq 0 ]; then
  echo "at least one .deb package is required" >&2
  usage >&2
  exit 2
fi

for tool in dpkg-scanpackages apt-ftparchive gzip; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool" >&2
    exit 1
  fi
done

if [ -n "$signing_key" ] && ! command -v gpg >/dev/null 2>&1; then
  echo "required tool not found for signing: gpg" >&2
  exit 1
fi

if [ -e "$output_dir" ]; then
  if [ ! -d "$output_dir" ] || [ ! -f "$output_dir/.saugra-waf-apt-repository" ]; then
    echo "refusing to overwrite unmarked output path: $output_dir" >&2
    echo "remove it manually or choose a different --output directory" >&2
    exit 1
  fi
  find "$output_dir" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
fi

pool_dir="$output_dir/pool/main/s/saugra-waf"
binary_dir="$output_dir/dists/$codename/$component/binary-$arch"
release_dir="$output_dir/dists/$codename"

install -d "$pool_dir" "$binary_dir"
touch "$output_dir/.saugra-waf-apt-repository"

for package in "${packages[@]}"; do
  if [ ! -f "$package" ]; then
    echo "package not found: $package" >&2
    exit 1
  fi
  case "$package" in
    *.deb) ;;
    *)
      echo "package does not end in .deb: $package" >&2
      exit 1
      ;;
  esac
  cp "$package" "$pool_dir/"
done

(
  cd "$output_dir"
  dpkg-scanpackages --arch "$arch" pool /dev/null > "dists/$codename/$component/binary-$arch/Packages"
)

gzip -9 -c "$binary_dir/Packages" > "$binary_dir/Packages.gz"

release_config="$(mktemp)"
release_tmp="$(mktemp)"
cleanup() {
  rm -f "$release_config" "$release_tmp"
}
trap cleanup EXIT

cat > "$release_config" <<EOF
APT::FTPArchive::Release {
  Origin "Saugra";
  Label "Saugra";
  Suite "$codename";
  Codename "$codename";
  Architectures "$arch";
  Components "$component";
  Description "Saugra Web Application Firewall packages";
};
EOF

(
  cd "$release_dir"
  apt-ftparchive -c "$release_config" release . > "$release_tmp"
)
mv "$release_tmp" "$release_dir/Release"

if [ -n "$signing_key" ]; then
  gpg_sign_args=(--batch --yes --local-user "$signing_key")
  if [ -n "${SAUGRA_APT_GPG_PASSPHRASE:-}" ]; then
    gpg_sign_args+=(--pinentry-mode loopback --passphrase "$SAUGRA_APT_GPG_PASSPHRASE")
  fi

  gpg "${gpg_sign_args[@]}" --detach-sign --armor \
    --output "$release_dir/Release.gpg" "$release_dir/Release"
  gpg "${gpg_sign_args[@]}" --clearsign \
    --output "$release_dir/InRelease" "$release_dir/Release"
else
  echo "repository metadata was generated unsigned; pass --signing-key to sign Release metadata" >&2
fi

echo "APT repository written to $output_dir"
