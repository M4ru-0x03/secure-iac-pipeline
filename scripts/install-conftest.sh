#!/usr/bin/env bash
# Install a pinned Conftest release after verifying its SHA256 checksum.
# Usage: bash scripts/install-conftest.sh <version> [install-dir]
set -euo pipefail

version="${1:?usage: install-conftest.sh <version> [install-dir]}"
install_dir="${2:-$HOME/.local/bin}"
archive="conftest_${version}_Linux_x86_64.tar.gz"
base_url="https://github.com/open-policy-agent/conftest/releases/download/v${version}"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
cd "$work_dir"

curl -fsSLO "${base_url}/${archive}"
curl -fsSLO "${base_url}/checksums.txt"
grep " ${archive}\$" checksums.txt | sha256sum -c -

mkdir -p "$install_dir"
tar -xzf "$archive" conftest
install -m 0755 conftest "${install_dir}/conftest"
"${install_dir}/conftest" --version
