#!/usr/bin/env bash
# W37-01: package charts/kryptkeeper at the release version, push it to an OCI
# registry, sign the chart digest keyless with cosign, then verify it from a
# clean directory (cosign verify, helm pull, helm template).
#
# The chart version and appVersion both come from the tag (v1.2.3 -> 1.2.3) via
# `helm package --version --app-version`; Chart.yaml is never edited per release.
#
# Usage: helm-oci.sh [--dry-run] <tag>
#   --dry-run  lint, package and helm template locally; no push, sign or verify.
# Environment:
#   CHART_DIR        chart source (default charts/kryptkeeper)
#   OCI_REPO         push target (default oci://ghcr.io/bpmforge/charts)
#   IDENTITY_REGEXP  cosign certificate identity regexp (default: this repo's release.yml on a v* tag)
#   OIDC_ISSUER      cosign OIDC issuer (default GitHub Actions)
#   OUT_DIR          where the packaged .tgz goes (default: a fresh temp dir)
set -euo pipefail

CHART_DIR="${CHART_DIR:-charts/kryptkeeper}"
OCI_REPO="${OCI_REPO:-oci://ghcr.io/bpmforge/charts}"
IDENTITY_REGEXP="${IDENTITY_REGEXP:-^https://github\\.com/bpmforge/kryptkeeper/\\.github/workflows/release\\.yml@refs/tags/v}"
OIDC_ISSUER="${OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

dry_run=0
tag=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=1 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    -*) echo "unknown flag: $arg" >&2; exit 2 ;;
    *) tag="$arg" ;;
  esac
done
[ -n "$tag" ] || { echo "usage: helm-oci.sh [--dry-run] <tag>" >&2; exit 2; }
if ! [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
  echo "error: '$tag' is not vMAJOR.MINOR.PATCH[-prerelease]" >&2
  exit 2
fi
version="${tag#v}"
name="$(awk '/^name:/ {print $2; exit}' "$CHART_DIR/Chart.yaml")"
[ -n "$name" ] || { echo "error: cannot read chart name from $CHART_DIR/Chart.yaml" >&2; exit 1; }

# Throwaway values so the chart's required-value guards pass when rendering.
tmpl_args=(--set config.dbMode=sqlite --set replicaCount=1 --set autoscaling.enabled=false --set secrets.bootstrapToken=render-only --set secrets.keystorePassphrase=render-only-passphrase)

out="${OUT_DIR:-$(mktemp -d)}"
mkdir -p "$out"

echo "==> lint $CHART_DIR"
helm lint "$CHART_DIR"

echo "==> package $name $version (appVersion $version)"
helm package "$CHART_DIR" --version "$version" --app-version "$version" --destination "$out"
tgz="$out/$name-$version.tgz"
[ -f "$tgz" ] || { echo "error: $tgz was not produced" >&2; exit 1; }

echo "==> template the packaged chart"
helm template "$name" "$tgz" "${tmpl_args[@]}" >/dev/null

if [ "$dry_run" = 1 ]; then
  echo "dry run ok: $tgz (no push, sign or verify)"
  exit 0
fi

echo "==> push to $OCI_REPO"
push_out="$(helm push "$tgz" "$OCI_REPO" 2>&1)"
echo "$push_out"
digest="$(sed -n 's/^Digest: *\(sha256:[0-9a-f]\{64\}\).*/\1/p' <<<"$push_out" | head -n1)"
[ -n "$digest" ] || { echo "error: could not read the pushed digest from helm push output" >&2; exit 1; }
ref="${OCI_REPO#oci://}/$name"

echo "==> cosign sign (keyless) $ref@$digest"
cosign sign --yes "$ref@$digest"

echo "==> cosign verify"
cosign verify \
  --certificate-identity-regexp "$IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  "$ref@$digest" >/dev/null

echo "==> clean helm pull + template"
pulled="$(mktemp -d)"
helm pull "$OCI_REPO/$name" --version "$version" --destination "$pulled"
helm template "$name" "$pulled/$name-$version.tgz" "${tmpl_args[@]}" >/dev/null

echo "chart $ref:$version published, signed and verified ($digest)"
