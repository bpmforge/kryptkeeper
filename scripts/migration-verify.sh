#!/usr/bin/env bash
# filename: scripts/migration-verify.sh
#
# W33-19: fingerprint-by-fingerprint migration verification.
# Compares a manifest of source-estate SHA-256 fingerprints with the hub
# inventory (GET /api/v1/certificates) and reports how many are mapped.
#
# Usage: scripts/migration-verify.sh --manifest FILE [--hub URL]
#            [--origin imported|synced] [--require-owner]
# Env:   KK_HUB_URL (default http://127.0.0.1:8080), KK_TOKEN (required; never
#        echoed, never placed in argv).
# Manifest: one lowercase hex SHA-256 fingerprint per line (no colons); blank
#   lines and '#' comments ignored; duplicates collapse. Colons/uppercase are
#   normalised on both sides so a format mismatch cannot silently yield 0%.
# Exit: 0 all mapped (manifest non-empty); 1 unmatched > 0 or empty manifest;
#       2 usage, missing token, HTTP or JSON error.
# Last stdout line: total=N mapped=M unmatched=U percent=P
set -u
set -o pipefail

usage() {
  echo "usage: $0 --manifest FILE [--hub URL] [--origin imported|synced] [--require-owner]" >&2
  exit 2
}

MANIFEST=""
HUB="${KK_HUB_URL:-http://127.0.0.1:8080}"
ORIGIN=""
REQUIRE_OWNER=0
while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) [ $# -ge 2 ] || usage; MANIFEST="$2"; shift 2;;
    --hub) [ $# -ge 2 ] || usage; HUB="$2"; shift 2;;
    --origin) [ $# -ge 2 ] || usage; ORIGIN="$2"; shift 2;;
    --require-owner) REQUIRE_OWNER=1; shift;;
    -h|--help) usage;;
    *) echo "unknown argument: $1" >&2; usage;;
  esac
done
[ -n "$MANIFEST" ] || usage
case "$ORIGIN" in ""|imported|synced) ;; *) echo "--origin must be imported or synced" >&2; exit 2;; esac
[ -r "$MANIFEST" ] || { echo "cannot read manifest: $MANIFEST" >&2; exit 2; }
[ -n "${KK_TOKEN:-}" ] || { echo "KK_TOKEN is required" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }

export KKMV_MANIFEST="$MANIFEST" KKMV_HUB="${HUB%/}" KKMV_ORIGIN="$ORIGIN" KKMV_REQUIRE_OWNER="$REQUIRE_OWNER"
exec python3 -c '
import json, os, sys, urllib.request, urllib.error

def norm(s):
    return s.strip().replace(":", "").lower()

manifest = []
seen = set()
with open(os.environ["KKMV_MANIFEST"]) as fh:
    for line in fh:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fp = norm(line)
        if fp not in seen:
            seen.add(fp)
            manifest.append(fp)
if not manifest:
    print("total=0 mapped=0 unmatched=0 percent=0.0")
    print("manifest is empty", file=sys.stderr)
    sys.exit(1)

hub = os.environ["KKMV_HUB"]
origin = os.environ["KKMV_ORIGIN"]
token = os.environ["KK_TOKEN"]
inv = {}
cursor = ""
pages = 0
while True:
    url = hub + "/api/v1/certificates?limit=100"
    if cursor:
        url += "&cursor=" + urllib.request.quote(cursor, safe="")
    if origin:
        url += "&origin=" + origin
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.load(resp)
    except urllib.error.HTTPError as e:
        print("hub returned HTTP %d for GET /api/v1/certificates" % e.code, file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print("hub request failed: %s" % type(e).__name__, file=sys.stderr)
        sys.exit(2)
    if not isinstance(body, dict) or not isinstance(body.get("data"), list):
        print("unexpected response shape from hub", file=sys.stderr)
        sys.exit(2)
    for c in body["data"]:
        fp = norm(str(c.get("fingerprint_sha256", "")))
        if fp:
            inv[fp] = c
    nxt = (body.get("meta") or {}).get("next_cursor")
    pages += 1
    if not nxt:
        break
    if nxt == cursor or pages > 100000:
        print("pagination did not advance", file=sys.stderr)
        sys.exit(2)
    cursor = str(nxt)

require_owner = os.environ["KKMV_REQUIRE_OWNER"] == "1"
unmatched = []
for fp in manifest:
    c = inv.get(fp)
    if c is None:
        unmatched.append((fp, "not in inventory"))
    elif c.get("origin") not in ("imported", "synced"):
        unmatched.append((fp, "origin=%s" % c.get("origin")))
    elif require_owner and not (c.get("owner_team") or "").strip():
        unmatched.append((fp, "no owner"))

total = len(manifest)
mapped = total - len(unmatched)
for fp, why in unmatched[:50]:
    print("UNMATCHED %s (%s)" % (fp, why), file=sys.stderr)
if len(unmatched) > 50:
    print("... and %d more" % (len(unmatched) - 50), file=sys.stderr)
print("total=%d mapped=%d unmatched=%d percent=%.1f" % (total, mapped, len(unmatched), 100.0 * mapped / total))
sys.exit(1 if unmatched else 0)
'
