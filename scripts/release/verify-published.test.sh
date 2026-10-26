#!/usr/bin/env bash
# Offline test for verify-published.sh --local: pass path, tampered asset,
# missing asset, missing checksums.txt. No network. The cosign steps cannot run
# offline (keyless verification needs Sigstore and the registry), so --local
# skips them; this test says so, and says when cosign is not installed either.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="$here/verify-published.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

make_dir() {
  local d="$1" f
  mkdir -p "$d"
  printf 'hub-binary\n' > "$d/kryptkeeper_1.2.3_linux_amd64.tar.gz"
  printf 'agent-binary\n' > "$d/kryptkeeper-agent_1.2.3_linux_arm64.tar.gz"
  : > "$d/checksums.txt"
  for f in kryptkeeper_1.2.3_linux_amd64.tar.gz kryptkeeper-agent_1.2.3_linux_arm64.tar.gz; do
    printf '%s  %s\n' "$(sha "$d/$f")" "$f" >> "$d/checksums.txt"
  done
}

pass=0
failed=0
check() { # name expected_rc expected_substring dir
  local name="$1" rc="$2" want="$3" dir="$4" out got=0
  out="$(bash "$script" v1.2.3 --local "$dir" 2>&1)" || got=$?
  if [ "$got" = "$rc" ] && grep -qF -- "$want" <<<"$out"; then
    echo "ok   $name"
    pass=$((pass + 1))
  else
    echo "FAIL $name (rc=$got want=$rc, wanted output: $want)"
    echo "$out"
    failed=$((failed + 1))
  fi
}

make_dir "$tmp/good"
check "good directory verifies" 0 "verified" "$tmp/good"

make_dir "$tmp/tamper"
printf 'evil\n' > "$tmp/tamper/kryptkeeper_1.2.3_linux_amd64.tar.gz"
check "tampered asset is named" 1 "sha256 mismatch for kryptkeeper_1.2.3_linux_amd64.tar.gz" "$tmp/tamper"

make_dir "$tmp/missing"
rm "$tmp/missing/kryptkeeper-agent_1.2.3_linux_arm64.tar.gz"
check "missing asset is named" 1 "kryptkeeper-agent_1.2.3_linux_arm64.tar.gz is listed in checksums.txt but missing" "$tmp/missing"

make_dir "$tmp/nosum"
rm "$tmp/nosum/checksums.txt"
check "missing checksums.txt fails" 1 "checksums.txt is missing" "$tmp/nosum"

make_dir "$tmp/multi"
printf 'evil\n' > "$tmp/multi/kryptkeeper_1.2.3_linux_amd64.tar.gz"
rm "$tmp/multi/kryptkeeper-agent_1.2.3_linux_arm64.tar.gz"
check "all failures are reported, not just the first" 1 "(2):" "$tmp/multi"

if command -v cosign >/dev/null 2>&1; then
  echo "note: cosign is installed but its checks need network; --local skips them (not exercised here)"
else
  echo "note: cosign not installed; cosign checks skipped (they are skipped by --local regardless)"
fi
echo "$pass passed, $failed failed"
[ "$failed" = 0 ]
