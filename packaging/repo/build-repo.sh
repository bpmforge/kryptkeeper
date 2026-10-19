#!/usr/bin/env bash
# W25-11: build signed apt and yum repository trees from a directory of
# kryptkeeper .deb/.rpm packages.
#
#   build-repo.sh <pkg_dir> <out_dir>
#
# Env: GPG_KEY_ID (required), GNUPGHOME (optional), GPG_PASSPHRASE (optional;
# empty for passphrase-less test keys), BASE_URL (used in kryptkeeper.repo).
# Tools: apt-ftparchive (apt-utils), createrepo_c, gpg, gzip.
#
# Packages already present in <out_dir> are kept, so a caller may accumulate
# versions; the CI workflow instead rebuilds from every verified release.
# The passphrase goes in on stdin (--passphrase-fd 0), never on a command line.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <pkg_dir> <out_dir>" >&2
  exit 2
fi
: "${GPG_KEY_ID:?GPG_KEY_ID is required}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(cd "$1" && pwd)"
mkdir -p "$2"
OUT="$(cd "$2" && pwd)"
BASE_URL="${BASE_URL:-https://pkg.kryptkeeper.io}"
BASE_URL="${BASE_URL%/}"
ARCHES="amd64 arm64"

for tool in apt-ftparchive createrepo_c gpg gzip; do
  command -v "$tool" >/dev/null 2>&1 || { echo "build-repo: missing tool: $tool" >&2; exit 1; }
done

gpg_sign() { # gpg_sign <extra gpg args...>
  printf '%s' "${GPG_PASSPHRASE:-}" | gpg --batch --yes --pinentry-mode loopback \
    --passphrase-fd 0 --default-key "$GPG_KEY_ID" "$@"
}

mkdir -p "$OUT/apt/pool/main/k/kryptkeeper" "$OUT/rpm"
shopt -s nullglob
for f in "$PKG_DIR"/*.deb; do cp -f "$f" "$OUT/apt/pool/main/k/kryptkeeper/"; done
for f in "$PKG_DIR"/*.rpm; do cp -f "$f" "$OUT/rpm/"; done
debs=("$OUT"/apt/pool/main/k/kryptkeeper/*.deb)
rpms=("$OUT"/rpm/*.rpm)
if [ "${#debs[@]}" -eq 0 ] && [ "${#rpms[@]}" -eq 0 ]; then
  echo "build-repo: no .deb or .rpm packages found in $PKG_DIR or $OUT" >&2
  exit 1
fi

if [ "${#debs[@]}" -gt 0 ]; then
  # Run from apt/ so Filename: is pool/main/k/kryptkeeper/... relative to the
  # repository root.
  (
    cd "$OUT/apt"
    rm -f dists/stable/Release dists/stable/Release.gpg dists/stable/InRelease
    for arch in $ARCHES; do
      d="dists/stable/main/binary-$arch"
      mkdir -p "$d"
      apt-ftparchive --arch "$arch" packages pool > "$d/Packages"
      gzip -9nc "$d/Packages" > "$d/Packages.gz"
    done
    apt-ftparchive \
      -o APT::FTPArchive::Release::Origin=Kryptkeeper \
      -o APT::FTPArchive::Release::Label=Kryptkeeper \
      -o APT::FTPArchive::Release::Suite=stable \
      -o APT::FTPArchive::Release::Codename=stable \
      -o "APT::FTPArchive::Release::Architectures=$ARCHES" \
      -o APT::FTPArchive::Release::Components=main \
      release dists/stable > dists/stable/Release.tmp
    mv dists/stable/Release.tmp dists/stable/Release
    gpg_sign --armor --detach-sign -o dists/stable/Release.gpg dists/stable/Release
    gpg_sign --clearsign -o dists/stable/InRelease dists/stable/Release
  )
fi

if [ "${#rpms[@]}" -gt 0 ]; then
  createrepo_c --update "$OUT/rpm"
  rm -f "$OUT/rpm/repodata/repomd.xml.asc"
  gpg_sign --armor --detach-sign -o "$OUT/rpm/repodata/repomd.xml.asc" "$OUT/rpm/repodata/repomd.xml"
fi

gpg --batch --armor --export "$GPG_KEY_ID" > "$OUT/kryptkeeper.asc"
gpg --batch --export "$GPG_KEY_ID" > "$OUT/kryptkeeper.gpg"
[ -s "$OUT/kryptkeeper.asc" ] || { echo "build-repo: public key export is empty" >&2; exit 1; }
sed "s|__BASE_URL__|$BASE_URL|g" "$HERE/kryptkeeper.repo.tmpl" > "$OUT/kryptkeeper.repo"
echo "build-repo: ${#debs[@]} deb, ${#rpms[@]} rpm -> $OUT"
