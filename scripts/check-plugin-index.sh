#!/usr/bin/env bash
# Keep docs/plugins/REGISTRY.md honest (W32-07).
#
#   scripts/check-plugin-index.sh [--dist DIR] [--registry FILE] [--strict]
#   scripts/check-plugin-index.sh --self-test
#   scripts/check-plugin-index.sh --print-rows     # draft rows from source manifests
#
# Every row of the "Verified plugins" table must agree with the built, signed
# artifacts in DIST (default dist/plugins, produced by scripts/build-plugins.sh
# and scripts/sign-plugins.sh): version, module sha256 (manifest AND the
# plugin.wasm bytes) and, for first-party rows, a signing key id derived from
# internal/bootstrap/plugin_signing_keys.txt. This script never rebuilds: Go
# stamps VCS state into the module, so a rebuild can differ from the signed one.
# A row whose sha256 is PENDING-SIGN warns, and fails under --strict.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist/plugins"
REGISTRY="$ROOT/docs/plugins/REGISTRY.md"
KEYS="$ROOT/internal/bootstrap/plugin_signing_keys.txt"
STRICT=0; SELFTEST=0; PRINT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dist) DIST="${2:?--dist needs a directory}"; shift 2 ;;
    --registry) REGISTRY="${2:?--registry needs a file}"; shift 2 ;;
    --strict) STRICT=1; shift ;;
    --self-test) SELFTEST=1; shift ;;
    --print-rows) PRINT=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
command -v python3 >/dev/null || { echo "[plugin-index] python3 is required" >&2; exit 2; }

PY="$(mktemp)"; TMP=""
trap 'rm -f "$PY"; [ -z "$TMP" ] || rm -rf "$TMP"' EXIT
cat >"$PY" <<'PYEOF'
import base64, glob, hashlib, json, os, re, sys

mode, root, dist, registry, keys, strict = sys.argv[1:7]
strict = strict == "1"

def key_ids(path):
    ids = set()
    pem = open(path).read()
    for b64 in re.findall(r"-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----", pem, re.S):
        # key id = hex SHA-256 of the DER of the PEM PUBLIC KEY block
        ids.add(hashlib.sha256(base64.b64decode("".join(b64.split()))).hexdigest())
    return ids

def caps(c):
    out = []
    if c.get("receive_private_key"):
        out.append("receive_private_key")
    n = c.get("network")
    if n:
        parts = []
        if "hosts_from_credential" in n:
            parts.append("hosts_from_credential=" + n["hosts_from_credential"])
        if "hosts" in n:
            parts.append("hosts=%d" % len(n["hosts"]))
        if "ports" in n:
            parts.append("ports=" + ",".join(str(p) for p in n["ports"]))
        out.append("network: " + " ".join(parts))
    if c.get("tls_verify"):
        out.append("tls_verify")
    return "; ".join(out)

def manifests(base):
    found = {}
    for p in sorted(glob.glob(os.path.join(base, "*", "manifest.json"))):
        m = json.load(open(p))
        found[m["id"]] = (os.path.dirname(p), m)
    return found

if mode == "print":
    ids = key_ids(keys)
    kid = sorted(ids)[0]
    for pid, (d, m) in manifests(os.path.join(root, "plugins")).items():
        if "example" in pid:
            continue
        rel = os.path.relpath(d, root)
        print("| %s | first-party | %s | PENDING-SIGN | %s | %s | [%s](../../%s) |"
              % (pid, m["version"], caps(m["capabilities"]), kid, rel, rel))
    sys.exit(0)

errors, warns = [], []
rows, reference, section = [], set(), ""
for line in open(registry):
    if line.startswith("## "):
        section = line[3:].strip()
    elif line.startswith("| kryptkeeper."):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if section == "Verified plugins":
            rows.append(cells)
        elif section.startswith("Reference"):
            reference.add(cells[0])
if not rows:
    errors.append("no plugin rows found under '## Verified plugins' in %s" % registry)

good_keys = key_ids(keys)
built = manifests(dist)
source = manifests(os.path.join(root, "plugins"))
seen = set()
for cells in rows:
    if len(cells) < 7:
        errors.append("%s: row has %d columns, want 7" % (cells[0], len(cells)))
        continue
    pid, tier, ver, sha, _caps, kid, _src = cells[:7]
    seen.add(pid)
    if tier not in ("first-party", "verified"):
        errors.append("%s: tier %r must be first-party or verified" % (pid, tier))
    if not re.fullmatch(r"[0-9a-f]{64}", kid):
        errors.append("%s: signing key id is not 64 hex" % pid)
    elif tier == "first-party" and kid not in good_keys:
        errors.append("%s: signing key id %s is not derived from plugin_signing_keys.txt" % (pid, kid))
    pending = sha == "PENDING-SIGN"
    if pending:
        (errors if strict else warns).append("%s: sha256 is PENDING-SIGN (no signed release artifact yet)" % pid)
    elif not re.fullmatch(r"[0-9a-f]{64}", sha):
        errors.append("%s: sha256 %r is not 64 hex" % (pid, sha))
    if pid in built:
        d, m = built[pid]
        if m.get("version") != ver:
            errors.append("%s: version %s != manifest %s" % (pid, ver, m.get("version")))
        if not pending:
            if m.get("artifact", {}).get("sha256") != sha:
                errors.append("%s: sha256 != manifest artifact.sha256" % pid)
            wasm = os.path.join(d, m.get("artifact", {}).get("file", "plugin.wasm"))
            if not os.path.isfile(wasm):
                errors.append("%s: module %s is missing" % (pid, wasm))
            elif hashlib.sha256(open(wasm, "rb").read()).hexdigest() != sha:
                errors.append("%s: sha256 != sha256 of %s" % (pid, wasm))
    elif pending and pid in source:
        if source[pid][1].get("version") != ver:
            errors.append("%s: version %s != source manifest %s" % (pid, ver, source[pid][1].get("version")))
    else:
        errors.append("%s: row has no artifact under %s" % (pid, dist))
for pid in built:
    if pid not in seen and pid not in reference:
        errors.append("%s: built under %s but has no registry row" % (pid, dist))

for w in warns:
    print("[plugin-index] WARN " + w, file=sys.stderr)
if errors:
    for e in errors:
        print("[plugin-index] FAIL " + e, file=sys.stderr)
    sys.exit(1)
print("[plugin-index] OK %d plugins" % len(seen))
PYEOF

run_check() { python3 "$PY" check "$ROOT" "$1" "$2" "$KEYS" "$3"; }

if [ "$PRINT" = 1 ]; then python3 "$PY" print "$ROOT" "" "" "$KEYS" 0; exit 0; fi

if [ "$SELFTEST" = 1 ]; then
  TMP="$(mktemp -d)"
  kid="$(sed -n '/-----BEGIN PUBLIC KEY-----/,/-----END PUBLIC KEY-----/p' "$KEYS" | python3 -c '
import base64,hashlib,sys
b=[l for l in sys.stdin.read().split("\n") if l and not l.startswith("-----")]
print(hashlib.sha256(base64.b64decode("".join(b))).hexdigest())')"
  mkdir -p "$TMP/dist/fx"
  printf 'kkpl' >"$TMP/dist/fx/plugin.wasm"
  sha="$(shasum -a 256 "$TMP/dist/fx/plugin.wasm" | cut -d' ' -f1)"
  printf '{"id":"kryptkeeper.fixture","version":"9.9.9","artifact":{"file":"plugin.wasm","sha256":"%s"}}\n' "$sha" >"$TMP/dist/fx/manifest.json"
  printf '## Verified plugins\n\n| Plugin id | Tier | Version | Module sha256 | Capabilities | Signing key id | Source |\n|---|---|---|---|---|---|---|\n| kryptkeeper.fixture | first-party | 9.9.9 | %s | tls_verify | %s | x |\n' "$sha" "$kid" >"$TMP/registry.md"
  fail() { echo "[plugin-index] self-test FAILED: $1" >&2; exit 1; }
  run_check "$TMP/dist" "$TMP/registry.md" 1 >/dev/null 2>&1 || fail "unaltered registry should pass"
  first="${sha:0:1}"; flip=a; [ "$first" = a ] && flip=b
  sed "s/| ${sha} |/| ${flip}${sha:1} |/" "$TMP/registry.md" >"$TMP/altered.md"
  if out="$(run_check "$TMP/dist" "$TMP/altered.md" 1 2>&1)"; then fail "altered sha256 passed"; fi
  echo "$out" | grep -q 'kryptkeeper.fixture' || fail "failure did not name the plugin: $out"
  printf '{"id":"kryptkeeper.fixture","version":"9.9.9","artifact":{"file":"plugin.wasm","sha256":"%s"}}\n' "$sha" >"$TMP/dist/fx/manifest.json"
  printf 'tamp' >"$TMP/dist/fx/plugin.wasm"
  if run_check "$TMP/dist" "$TMP/registry.md" 1 >/dev/null 2>&1; then fail "tampered plugin.wasm passed"; fi
  echo "[plugin-index] self-test OK (unaltered passes; altered hash and tampered module fail)"
  exit 0
fi

run_check "$DIST" "$REGISTRY" "$STRICT"
