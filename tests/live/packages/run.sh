#!/usr/bin/env bash
# W25-12: prove the kryptkeeper deb and rpm install, upgrade (config byte-
# identical) and remove cleanly on Debian 12 and Rocky 9.
#
#   PKG_SOURCE=local (default)  build 0.0.1 and 0.0.2 packages from this tree
#                               with nfpm, a stub hub binary, install the files
#   PKG_SOURCE=repo             install from the hosted repo (W25-11); needs
#                               PKG_REPO_URL, PKG_REPO_KEY_URL (the .gpg key),
#                               PKG_OLD_VERSION and PKG_NEW_VERSION
#
# nfpm: uses `nfpm` on PATH, else runs the pinned goreleaser/nfpm image under
# podman (nothing is installed on the host). The harness tests packaging, not
# the hub, so the "binary" is a tiny stub script. No keys or secrets here.
#
# Idempotent, PASS/FAIL per step, non-zero exit on any FAIL, containers are
# --rm and the work dir is removed on exit. Podman only; containers use the
# host architecture (no emulation).
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/kk-uat-pkgs.XXXXXX")"
export PKG_SOURCE="${PKG_SOURCE:-local}"
NFPM_IMG="${NFPM_IMG:-docker.io/goreleaser/nfpm:v2.41.0}"
TARGETS="${TARGETS:-debian:12 rockylinux:9}"

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; exit 1; }
trap 'rm -rf "$WORK"' EXIT

command -v podman >/dev/null 2>&1 || DIE "podman not found"

case "$(uname -m)" in
  arm64|aarch64) ARCH=arm64 ;;
  x86_64|amd64)  ARCH=amd64 ;;
  *) DIE "unsupported host arch $(uname -m)" ;;
esac

build_pkg() { # build_pkg <version> <format> <dest>
  local ver="$1" fmt="$2" dest="$3"
  local envs=(-e "NFPM_ARCH=$ARCH" -e "NFPM_VERSION=$ver" -e "NFPM_HUB_BINARY=/out/stub/kryptkeeper")
  if command -v nfpm >/dev/null 2>&1; then
    (cd "$REPO_ROOT" && NFPM_ARCH=$ARCH NFPM_VERSION=$ver NFPM_HUB_BINARY="$WORK/stub/kryptkeeper" \
      nfpm package --config packaging/nfpm/nfpm.yaml --packager "$fmt" --target "$dest")
  else
    podman run --rm "${envs[@]}" -v "$REPO_ROOT:/src:ro" -v "$WORK:/out" -w /src \
      "$NFPM_IMG" package --config packaging/nfpm/nfpm.yaml --packager "$fmt" \
      --target "/out/$(basename "$dest")"
  fi
}

if [ "$PKG_SOURCE" = local ]; then
  STEP "build packages 0.0.1 and 0.0.2 ($ARCH)"
  mkdir -p "$WORK/stub"
  printf '#!/bin/sh\necho "kryptkeeper uat stub"\n' > "$WORK/stub/kryptkeeper"
  chmod 0755 "$WORK/stub/kryptkeeper"
  for spec in 0.0.1:old 0.0.2:new; do
    ver="${spec%%:*}"; tag="${spec##*:}"
    for fmt in deb rpm; do
      if build_pkg "$ver" "$fmt" "$WORK/$tag.$fmt" >"$WORK/build.log" 2>&1; then
        PASS "built $tag.$fmt (version $ver)"
      else
        cat "$WORK/build.log"; DIE "nfpm failed for $ver $fmt (install nfpm, or let podman pull $NFPM_IMG)"
      fi
    done
  done
elif [ "$PKG_SOURCE" = repo ]; then
  for v in PKG_REPO_URL PKG_REPO_KEY_URL PKG_OLD_VERSION PKG_NEW_VERSION; do
    [ -n "${!v:-}" ] || DIE "PKG_SOURCE=repo needs $v"
  done
else
  DIE "PKG_SOURCE must be local or repo"
fi

: > "$WORK/results.txt"
for target in $TARGETS; do
  case "$target" in
    debian:*) fam=deb ;;
    rockylinux:*) fam=rpm ;;
    *) DIE "unknown target $target" ;;
  esac
  STEP "$target ($fam)"
  podman run --rm \
    -e PKG_SOURCE -e PKG_REPO_URL -e PKG_REPO_KEY_URL -e PKG_OLD_VERSION -e PKG_NEW_VERSION \
    -v "$WORK:/w:ro" -v "$REPO_ROOT:/src:ro" -v "$HERE/inner.sh:/inner.sh:ro" \
    "docker.io/library/$target" bash /inner.sh "$fam" 2>&1 | tee "$WORK/out.$fam" \
    | grep -E '^(RES|INFO)\|' | sed "s|^|[$target] |"
  grep -E '^RES\|' "$WORK/out.$fam" | sed "s|^RES|$target|" >> "$WORK/results.txt"
  if [ "$(grep -c '^RES|' "$WORK/out.$fam")" -ne 4 ]; then
    tail -40 "$WORK/out.$fam"
    FAIL "$target: harness did not complete all 4 steps"
  fi
done

STEP "results"
printf '%-18s %-40s %s\n' target step result
while IFS='|' read -r target _fam step res detail; do
  printf '%-18s %-40s %s\n' "$target" "$step" "$res"
  [ "$res" = PASS ] || { FAILED=1; echo "    $detail"; }
done < "$WORK/results.txt"
echo
if [ "$FAILED" -eq 0 ]; then echo "ALL PASS (0 FAIL)"; else echo "FAILED"; fi
exit "$FAILED"
