#!/usr/bin/env bash
# One-command installer for the Kryptkeeper Hub / Agent binaries.
#
#   curl -fsSL https://raw.githubusercontent.com/kryptkeeper/kryptkeeper/main/packaging/install.sh | bash
#
# Downloads the release binary + SHA256SUMS.txt for this host's OS/arch,
# verifies the checksum, and installs the binary. Fails closed: a checksum
# mismatch removes the download and exits non-zero rather than installing
# an unverified binary.
#
# Env overrides (all optional):
#   KRYPTKEEPER_COMPONENT       hub|agent (default: hub)
#   KRYPTKEEPER_VERSION         release tag, e.g. v1.2.3 (default: latest
#                                release per the GitHub API)
#   KRYPTKEEPER_INSTALL_DIR     install directory (default: /usr/local/bin)
#   KRYPTKEEPER_INSTALL_BASE_URL
#                                override the release-asset base URL --
#                                used by packaging/install_test.go to point
#                                this script at a local fixture server
#                                instead of GitHub, so tests need no network.
#
# Linux and macOS only (amd64/arm64). Windows agent installs are documented
# separately in docs/deployment.md.
set -euo pipefail

component="${KRYPTKEEPER_COMPONENT:-hub}"
case "$component" in
  hub|agent) ;;
  *)
    echo "install.sh: KRYPTKEEPER_COMPONENT must be 'hub' or 'agent', got '$component'" >&2
    exit 1
    ;;
esac

case "$(uname -s)" in
  Linux) os="linux" ;;
  Darwin) os="darwin" ;;
  *)
    echo "install.sh: unsupported OS '$(uname -s)' (linux and darwin only)" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *)
    echo "install.sh: unsupported architecture '$(uname -m)' (amd64 and arm64 only)" >&2
    exit 1
    ;;
esac

base_url="${KRYPTKEEPER_INSTALL_BASE_URL:-https://github.com/bpmforge/kryptkeeper/releases/download}"
install_dir="${KRYPTKEEPER_INSTALL_DIR:-/usr/local/bin}"

version="${KRYPTKEEPER_VERSION:-}"
if [ -z "$version" ]; then
  echo "install.sh: resolving latest release..." >&2
  version="$(curl -fsSL https://api.github.com/repos/kryptkeeper/kryptkeeper/releases/latest \
    | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
  if [ -z "$version" ]; then
    echo "install.sh: could not resolve latest release; set KRYPTKEEPER_VERSION explicitly" >&2
    exit 1
  fi
fi

if [ "$component" = "agent" ]; then
  asset="kryptkeeper-agent-${os}-${arch}"
else
  asset="kryptkeeper-${os}-${arch}"
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

echo "install.sh: downloading ${asset} (${version})..." >&2
curl -fsSL "${base_url}/${version}/${asset}" -o "${work_dir}/${asset}"
curl -fsSL "${base_url}/${version}/SHA256SUMS.txt" -o "${work_dir}/SHA256SUMS.txt"

sums_line="$(grep -E "  ${asset}\$|  \\./${asset}\$" "${work_dir}/SHA256SUMS.txt" || true)"
if [ -z "$sums_line" ]; then
  echo "install.sh: no checksum entry for ${asset} in SHA256SUMS.txt -- refusing to install an unverified binary" >&2
  exit 1
fi

echo "install.sh: verifying checksum..." >&2
if command -v sha256sum >/dev/null 2>&1; then
  if ! (cd "$work_dir" && echo "$sums_line" | sha256sum -c - >/dev/null 2>&1); then
    echo "install.sh: checksum verification FAILED for ${asset} -- refusing to install" >&2
    exit 1
  fi
elif command -v shasum >/dev/null 2>&1; then
  expected_hash="$(echo "$sums_line" | awk '{print $1}')"
  actual_hash="$(shasum -a 256 "${work_dir}/${asset}" | awk '{print $1}')"
  if [ "$expected_hash" != "$actual_hash" ]; then
    echo "install.sh: checksum verification FAILED for ${asset} -- refusing to install" >&2
    exit 1
  fi
else
  echo "install.sh: neither sha256sum nor shasum found -- cannot verify integrity, refusing to install" >&2
  exit 1
fi

mkdir -p "$install_dir"
chmod +x "${work_dir}/${asset}"
target="${install_dir}/kryptkeeper"
if [ "$component" = "agent" ]; then
  target="${install_dir}/kryptkeeper-agent"
fi

if [ -w "$install_dir" ]; then
  cp "${work_dir}/${asset}" "$target"
else
  echo "install.sh: ${install_dir} is not writable, retrying with sudo..." >&2
  sudo cp "${work_dir}/${asset}" "$target"
fi

echo "install.sh: installed ${target} (${version})" >&2
