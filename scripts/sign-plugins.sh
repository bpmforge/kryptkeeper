#!/usr/bin/env bash
# Sign the first-party delivery plugins with the Kryptkeeper plugin key
# (W20-24, D-117). Run by the release owner on their own machine: cosign asks
# for the key's password, which never passes through this script.
#
#   scripts/sign-plugins.sh            # builds with `make plugins`, then signs
#   KK_PLUGIN_KEY=/path/kk-plugin.key scripts/sign-plugins.sh
#
# Writes dist/plugins/<name>/manifest.json.bundle beside each manifest, then
# verifies every bundle against the public key compiled into the hub.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY="${KK_PLUGIN_KEY:-$HOME/.config/kryptkeeper-signing/kk-plugin.key}"
[ -f "$KEY" ] || { echo "no plugin key at $KEY (set KK_PLUGIN_KEY)" >&2; exit 1; }
command -v cosign >/dev/null || { echo "cosign is not installed" >&2; exit 1; }
# Go stamps the git state into each module, so a build from a tree with
# uncommitted changes differs from the commit's and cannot be rebuilt to
# check the signature. This also stops a stray run from overwriting
# dist/plugins/ that was already signed from a clean tree.
if [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]; then
  echo "refusing to sign: the working tree has uncommitted changes (commit or stash them)" >&2
  exit 1
fi

make -C "$ROOT" plugins
PUB="$(mktemp)"; trap 'rm -f "$PUB"' EXIT
sed -n '/-----BEGIN PUBLIC KEY-----/,/-----END PUBLIC KEY-----/p' "$ROOT/internal/bootstrap/plugin_signing_keys.txt" >"$PUB"
for dir in "$ROOT"/dist/plugins/*/; do
  m="$dir/manifest.json"
  [ -f "$m" ] || continue
  echo "signing $(basename "$dir")"
  # cosign-signing-config.json names no transparency log or timestamp
  # authority: the hub never consults Rekor, and the repo is private, so the
  # signature stays off the public log. (It replaces the deprecated
  # --tlog-upload=false.)
  cosign sign-blob --yes --key "$KEY" --bundle "$m.bundle" \
    --signing-config "$ROOT/scripts/cosign-signing-config.json" "$m" >/dev/null
  cosign verify-blob --key "$PUB" --bundle "$m.bundle" --insecure-ignore-tlog=true "$m"
done
echo "done: each dist/plugins/<name>/ has plugin.wasm, manifest.json and manifest.json.bundle (built from $(git -C "$ROOT" rev-parse --short HEAD))"
