#!/usr/bin/env bash
set -euo pipefail

# filename: scripts/test/xlsx-libreoffice.sh
# W28-08: open exported XLSX files in LibreOffice headless and fail on
# anything unusable. Exit code 0 from LibreOffice alone is NOT proof of a
# good file (it can exit 0 and write nothing for an unreadable workbook),
# so success requires a converted CSV with a header plus at least one row.

usage() {
  cat <<'USAGE'
Usage: xlsx-libreoffice.sh <file.xlsx>...        # check each file
       xlsx-libreoffice.sh --self-test           # negative self-test, no LibreOffice needed
Exit: 0 all files OK | 1 a file failed | 2 usage error | 3 LibreOffice not installed
USAGE
}

fail() {
  printf 'FAIL %s: %s\n' "$1" "$2" >&2
}

find_soffice() {
  local c
  for c in soffice libreoffice; do
    if command -v "$c" >/dev/null 2>&1; then
      command -v "$c"
      return 0
    fi
  done
  return 1
}

# check_file <file>: returns 0 ok, 1 file failed, 3 LibreOffice missing.
check_file() {
  local f="$1" magic soffice tmp base csv lines rc=0

  if [[ ! -s "$f" ]]; then
    fail "$f" "file missing or empty"
    return 1
  fi

  magic="$(head -c4 "$f" | od -An -tx1 | tr -d ' \n')"
  if [[ "$magic" != "504b0304" ]]; then
    fail "$f" "not a zip container (magic bytes ${magic})"
    return 1
  fi

  if command -v unzip >/dev/null 2>&1 && ! unzip -tq "$f" >/dev/null 2>&1; then
    fail "$f" "zip integrity check failed"
    return 1
  fi

  # A missing converter is a failure, never a skip.
  if ! soffice="$(find_soffice)"; then
    printf 'FAIL %s: LibreOffice (soffice/libreoffice) is not installed\n' "$f" >&2
    return 3
  fi

  tmp="$(mktemp -d)"
  base="$(basename "${f%.xlsx}")"
  # Isolated profile: parallel/CI runs must not collide on a profile lock.
  if command -v timeout >/dev/null 2>&1; then
    timeout 180 "$soffice" -env:UserInstallation="file://$tmp/profile" --headless --norestore \
      --convert-to csv --outdir "$tmp/out" "$f" >/dev/null 2>&1 || rc=$?
  else
    "$soffice" -env:UserInstallation="file://$tmp/profile" --headless --norestore \
      --convert-to csv --outdir "$tmp/out" "$f" >/dev/null 2>&1 || rc=$?
  fi
  if [[ "$rc" -ne 0 ]]; then
    fail "$f" "LibreOffice conversion exited $rc"
    rm -rf "$tmp"
    return 1
  fi

  csv="$tmp/out/$base.csv"
  lines=0
  if [[ -f "$csv" ]]; then
    lines="$(wc -l <"$csv" | tr -d ' ')"
  fi
  if [[ "$lines" -lt 2 ]]; then
    fail "$f" "converted CSV missing/empty"
    rm -rf "$tmp"
    return 1
  fi

  printf 'OK %s: %s rows\n' "$f" "$lines"
  rm -rf "$tmp"
  return 0
}

self_test() {
  local dir rejected=0 f
  dir="$(mktemp -d)"

  printf 'definitely not xlsx' >"$dir/not-a-zip.xlsx"
  : >"$dir/empty.xlsx"
  { printf 'PK\003\004'; head -c 20 /dev/urandom; } >"$dir/truncated.xlsx"

  for f in "$dir/not-a-zip.xlsx" "$dir/empty.xlsx" "$dir/truncated.xlsx"; do
    if check_file "$f" 2>/dev/null; then
      printf 'self-test FAIL: corrupt fixture accepted: %s\n' "$(basename "$f")" >&2
    else
      rejected=$((rejected + 1))
    fi
  done

  rm -rf "$dir"

  if [[ "$rejected" -ne 3 ]]; then
    printf 'self-test FAIL: only %s of 3 corrupt fixtures rejected\n' "$rejected" >&2
    return 1
  fi
  printf 'self-test OK: 3 corrupt fixtures rejected\n'
}

main() {
  local rc=0 f r

  if [[ $# -eq 0 ]]; then
    usage >&2
    return 2
  fi
  case "$1" in
    -h|--help) usage; return 0 ;;
    --self-test)
      [[ $# -eq 1 ]] || { usage >&2; return 2; }
      self_test
      return $?
      ;;
  esac

  for f in "$@"; do
    r=0
    check_file "$f" || r=$?
    if [[ "$r" -eq 3 ]]; then
      return 3
    elif [[ "$r" -ne 0 ]]; then
      rc=1
    fi
  done
  return "$rc"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
