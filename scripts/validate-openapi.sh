#!/usr/bin/env bash
set -euo pipefail

# filename: scripts/validate-openapi.sh
# W1-03/G-5: fails if docs/openapi.yaml drifts from the routes actually
# registered on the hub's HTTP mux -- in either direction:
#   - a registered route with no spec path (spec understates reality)
#   - a spec path with no registered route (spec overstates reality, e.g.
#     a stale entry left behind after a route was removed)
#
# This is a real enforcement gate, not an optional check: if no YAML parser
# is available it fails closed (non-zero), it does not silently skip.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENAPI_FILE="$ROOT_DIR/docs/openapi.yaml"
BOOTSTRAP_DIR="$ROOT_DIR/internal/bootstrap"

if [[ ! -f "$OPENAPI_FILE" ]]; then
  echo "[openapi-validate] FAIL $OPENAPI_FILE not found" >&2
  exit 1
fi

# RFC-protocol mounts deliberately excluded from this REST API doc (see the
# scope comment at the top of docs/openapi.yaml) -- different content-types
# and auth models (RFC 8555 ACME, RFC 7030 EST, bare OCSP/CRL/SCEP), not
# /api/v1-scoped REST, and not maintained by this script's ground truth.
# W17-01 additions: /cmp (RFC 4210 CMP), /wstep (MS-WSTEP) and /xcep
# (MS-XCEP) are protocol servers on the same footing as the ACME/EST/SCEP
# mounts above -- SOAP/ASN.1 envelopes and their own auth models, not
# /api/v1-scoped REST. /metrics is the Prometheus exposition endpoint:
# telemetry in text/plain, not a JSON REST resource. Excluding these is
# what takes drift to 0 honestly, rather than documenting them as REST
# resources they are not.
EXCLUDED_MOUNTS=(
  "/acme/"
  "/ocsp"
  "/ocsp/" # RFC 5019 GET form: /ocsp/<base64 request> (W20-10)
  "/crl/"
  "/.well-known/est/"
  "/scep"
  "/scep/"
  "/cmp"
  "/wstep"
  "/xcep"
  "/metrics"
)

mapfile -t bootstrap_files < <(find "$BOOTSTRAP_DIR" -maxdepth 1 -name '*.go' ! -name '*_test.go' | sort)

if [[ ${#bootstrap_files[@]} -eq 0 ]]; then
  echo "[openapi-validate] FAIL no handler files found under $BOOTSTRAP_DIR" >&2
  exit 1
fi

mapfile -t raw_routes < <(
  grep -hoE '\.(HandleFunc|Handle)\("[^"]+"' "${bootstrap_files[@]}" \
    | sed -E 's/^\.(HandleFunc|Handle)\("//; s/"$//' \
    | sed -E 's/^(GET|POST|PUT|DELETE|PATCH) //' \
    | sort -u
)

registered_routes=()
for r in "${raw_routes[@]}"; do
  excluded=false
  for ex in "${EXCLUDED_MOUNTS[@]}"; do
    if [[ "$r" == "$ex" ]]; then
      excluded=true
      break
    fi
  done
  $excluded || registered_routes+=("$r")
done

# Extract the spec's documented path list. Prefer ruby's stdlib YAML (no
# extra install needed on GitHub Actions ubuntu runners); fall back to
# python3+PyYAML; fail closed if neither parses.
doc_paths=""
if command -v ruby >/dev/null 2>&1 && ruby -e 'require "yaml"; exit 0' 2>/dev/null; then
  doc_paths="$(ruby -e '
    require "yaml"
    d = YAML.load_file(ARGV[0])
    (d["paths"] || {}).keys.each { |p| puts p }
  ' "$OPENAPI_FILE")"
elif command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' 2>/dev/null; then
  doc_paths="$(python3 -c '
import sys, yaml
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f)
for p in (d.get("paths") or {}).keys():
    print(p)
' "$OPENAPI_FILE")"
else
  echo "[openapi-validate] FAIL no YAML parser available (ruby or python3+PyYAML) -- cannot validate, failing closed" >&2
  exit 1
fi

mapfile -t doc_path_list <<< "$doc_paths"

# Registrations ending in "/" are trailing-slash catch-alls whose handler
# parses the remaining path itself (fanning out into several documented
# sub-paths, e.g. one "/certificates/" registration -> {fingerprint},
# {fingerprint}/revoke, {fingerprint}/renew) -- prefix matching is correct
# for those. A bare (non-trailing-slash) registration never fans out, so it
# must match a spec path EXACTLY -- prefix matching there would let an
# unrelated sibling sub-path (e.g. /reports/pqc-waves/auto-derive) mask a
# missing entry for the actual collection route (/reports/pqc-waves).
route_is_covered() {
  local route="$1"
  case "$route" in
    "/"|"/healthz"|"/readyz")
      for p in "${doc_path_list[@]}"; do
        [[ "$p" == "$route" ]] && return 0
      done
      return 1
      ;;
    */)
      local stem="${route#/api/v1}"
      stem="${stem%/}"
      for p in "${doc_path_list[@]}"; do
        if [[ "$p" == "$stem" || "$p" == "$stem"/* ]]; then
          return 0
        fi
      done
      return 1
      ;;
    *)
      local stem="${route#/api/v1}"
      for p in "${doc_path_list[@]}"; do
        [[ "$p" == "$stem" ]] && return 0
      done
      return 1
      ;;
  esac
}

doc_path_has_route() {
  local docpath="$1"
  case "$docpath" in
    "/"|"/healthz"|"/readyz")
      for r in "${registered_routes[@]}"; do
        [[ "$r" == "$docpath" ]] && return 0
      done
      return 1
      ;;
    *)
      local stem
      for r in "${registered_routes[@]}"; do
        # "/" (root) is handled entirely by the explicit root/healthz/readyz
        # case above; skip it here so it can't degenerate to an empty stem
        # and glob-match every doc path via the "$docpath" == "$stem"/* check.
        [[ "$r" == "/" ]] && continue
        case "$r" in
          */)
            stem="${r#/api/v1}"
            stem="${stem%/}"
            if [[ "$stem" == "$docpath" || "$docpath" == "$stem"/* ]]; then
              return 0
            fi
            ;;
          *)
            stem="${r#/api/v1}"
            [[ "$stem" == "$docpath" ]] && return 0
            ;;
        esac
      done
      return 1
      ;;
  esac
}

failures=0

for r in "${registered_routes[@]}"; do
  if ! route_is_covered "$r"; then
    echo "[openapi-validate] FAIL registered route has no spec entry: $r" >&2
    failures=$((failures + 1))
  fi
done

for p in "${doc_path_list[@]}"; do
  [[ -z "$p" ]] && continue
  if ! doc_path_has_route "$p"; then
    echo "[openapi-validate] FAIL spec path has no registered route: $p" >&2
    failures=$((failures + 1))
  fi
done

# W20-28: a trailing-slash registration covers every spec sub-path under
# it, so a sub-route its handler serves but the spec omits is invisible
# above (the PQC wave execute routes went unnoticed that way). The UI
# client names the real sub-routes, so every path it calls must be in the
# spec, with a ${...} segment matching any {param}.
UI_CLIENT="$ROOT_DIR/ui/src/lib/api.ts"
if [[ -f "$UI_CLIENT" ]]; then
  while IFS= read -r missing; do
    [[ -z "$missing" ]] && continue
    echo "[openapi-validate] FAIL the UI calls a path the spec does not document: $missing" >&2
    failures=$((failures + 1))
  done < <(printf '%s\n' "${doc_path_list[@]}" | python3 -c '
import re, sys
spec = [l.strip() for l in sys.stdin if l.strip()]
def segs(p): return [s for s in p.strip("/").split("/") if s]
specs = [segs(p) for p in spec]
src = open(sys.argv[1]).read()
seen = set()
for m in re.finditer(r"(?:fetchJSON|fetch)[^(]*\(\s*[`\"](/[a-z][^`\"?$]*(?:\$\{[^}]*\}[^`\"?$]*)*)", src):
    p = re.sub(r"/\$\{[^}]*\}", "/{}", m.group(1))
    p = re.match(r"^[a-z0-9/_.{}-]+", p).group(0).rstrip("/")
    if p in seen: continue
    seen.add(p)
    want = segs(p)
    ok = any(len(s) == len(want) and all(a == b or (a == "{}" and b.startswith("{")) for a, b in zip(want, s)) for s in specs)
    if not ok: print(p)
' "$UI_CLIENT")
fi

if [[ "$failures" -gt 0 ]]; then
  echo "[openapi-validate] Completed with $failures drift(s) between docs/openapi.yaml and registered routes" >&2
  exit 1
fi

echo "[openapi-validate] PASS ${#registered_routes[@]} registered routes / ${#doc_path_list[@]} spec paths, no drift"
