#!/usr/bin/env bash
# One-command installer for the Kryptkeeper Hub / Agent binaries.
#
#   curl -fsSL https://github.com/bpmforge/kryptkeeper/releases/latest/download/install.sh | bash
#
# install.sh is itself a release asset: its sha256 is a line of the release's
# cosign-signed checksums.txt (there is no separate install.sh.sig).
#
# Downloads the release archive, checksums.txt, checksums.txt.sig and
# checksums.txt.pem for this host's OS/arch, then in order:
#   1. cosign verify-blob of checksums.txt against the release workflow's
#      keyless identity (the trust root);
#   2. sha256 of the archive against its line in the verified checksums.txt;
#   3. extracts and installs the binary.
# Fails closed: any verification failure exits non-zero and installs nothing.
#
# Env overrides (all optional):
#   KRYPTKEEPER_COMPONENT       hub|agent (default: hub)
#   KRYPTKEEPER_VERSION         release tag, e.g. v1.2.3 (default: latest
#                                release per the GitHub API)
#   KRYPTKEEPER_INSTALL_DIR     install directory (default: /usr/local/bin)
#   KRYPTKEEPER_INSTALL_COSIGN  cosign executable (default: cosign on PATH)
#   KRYPTKEEPER_INSTALL_SKIP_COSIGN
#                                set to 1 to proceed WITHOUT signature
#                                verification when cosign is not installed
#                                (checksum-only; checksums.txt is then
#                                unauthenticated). Never set it in
#                                automation you do not control.
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
  version="$(curl -fsSL https://api.github.com/repos/bpmforge/kryptkeeper/releases/latest \
    | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
  if [ -z "$version" ]; then
    echo "install.sh: could not resolve latest release; set KRYPTKEEPER_VERSION explicitly" >&2
    exit 1
  fi
fi

ver="${version#v}"
if [ "$component" = "agent" ]; then
  bin_name="kryptkeeper-agent"
else
  bin_name="kryptkeeper"
fi
archive="${bin_name}_${ver}_${os}_${arch}.tar.gz"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

echo "install.sh: downloading ${archive} (${version})..." >&2
for f in "$archive" checksums.txt checksums.txt.sig checksums.txt.pem; do
  curl -fsSL "${base_url}/${version}/${f}" -o "${work_dir}/${f}"
done

# Verify the signature before trusting anything inside checksums.txt.
cosign_bin="${KRYPTKEEPER_INSTALL_COSIGN:-cosign}"
if command -v "$cosign_bin" >/dev/null 2>&1; then
  echo "install.sh: verifying cosign signature of checksums.txt..." >&2
  if ! "$cosign_bin" verify-blob \
    --certificate "${work_dir}/checksums.txt.pem" \
    --signature "${work_dir}/checksums.txt.sig" \
    --certificate-identity-regexp '^https://github\.com/bpmforge/kryptkeeper/\.github/workflows/release\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "${work_dir}/checksums.txt" >/dev/null 2>&1; then
    echo "install.sh: cosign verification of checksums.txt FAILED -- refusing to install" >&2
    exit 1
  fi
elif [ "${KRYPTKEEPER_INSTALL_SKIP_COSIGN:-}" = "1" ]; then
  echo "install.sh: WARNING: cosign not found and KRYPTKEEPER_INSTALL_SKIP_COSIGN=1 -- checksums.txt is NOT authenticated; only the archive checksum is verified" >&2
else
  echo "install.sh: cosign not found -- refusing to install an unauthenticated release." >&2
  echo "install.sh: install cosign (https://docs.sigstore.dev/cosign/system_config/installation/) and retry," >&2
  echo "install.sh: or set KRYPTKEEPER_INSTALL_SKIP_COSIGN=1 to accept checksum-only verification." >&2
  exit 1
fi

sums_line="$(grep -E "  ${archive}\$|  \\./${archive}\$" "${work_dir}/checksums.txt" || true)"
if [ -z "$sums_line" ]; then
  echo "install.sh: no checksum entry for ${archive} in checksums.txt -- refusing to install an unverified binary" >&2
  exit 1
fi

echo "install.sh: verifying checksum..." >&2
if command -v sha256sum >/dev/null 2>&1; then
  if ! (cd "$work_dir" && echo "$sums_line" | sha256sum -c - >/dev/null 2>&1); then
    echo "install.sh: checksum verification FAILED for ${archive} -- refusing to install" >&2
    exit 1
  fi
elif command -v shasum >/dev/null 2>&1; then
  expected_hash="$(echo "$sums_line" | awk '{print $1}')"
  actual_hash="$(shasum -a 256 "${work_dir}/${archive}" | awk '{print $1}')"
  if [ "$expected_hash" != "$actual_hash" ]; then
    echo "install.sh: checksum verification FAILED for ${archive} -- refusing to install" >&2
    exit 1
  fi
else
  echo "install.sh: neither sha256sum nor shasum found -- cannot verify integrity, refusing to install" >&2
  exit 1
fi

# Extract only the one binary we expect, never the whole archive.
extract_dir="${work_dir}/extract"
mkdir -p "$extract_dir"
if ! tar -xzf "${work_dir}/${archive}" -C "$extract_dir" "$bin_name"; then
  echo "install.sh: ${archive} does not contain ${bin_name} -- refusing to install" >&2
  exit 1
fi

mkdir -p "$install_dir"
chmod +x "${extract_dir}/${bin_name}"
target="${install_dir}/${bin_name}"

if [ -w "$install_dir" ]; then
  cp "${extract_dir}/${bin_name}" "$target"
else
  echo "install.sh: ${install_dir} is not writable, retrying with sudo..." >&2
  sudo cp "${extract_dir}/${bin_name}" "$target"
fi

echo "install.sh: installed ${target} (${version})" >&2
