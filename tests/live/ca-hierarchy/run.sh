#!/usr/bin/env bash
# W23-02: timed day-one CA hierarchy. From a fresh `compose up` (or an existing
# hub in attach mode) create root + issuing + leaf for EVERY supported CA
# algorithm, verify each chain with `openssl verify`, and time the whole run.
#
# Attach mode : KK_BASE_URL=https://localhost:8080 KK_TOKEN=... [KK_CACERT=ca.pem]
# Compose mode: (KK_BASE_URL unset) starts podman compose project "kkw23ca",
#               only the hub service, with a throwaway token and passphrase.
# Env: OPENSSL_BIN (default openssl), BUDGET_SECONDS (default 900),
#      REQUIRE_ALL=1 (fail instead of SKIP when OpenSSL < 3.5 for ML-DSA),
#      EXPECT_ALGS (default 9; the supported-algorithm count is asserted).
set -u -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
PROJECT="kkw23ca"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
BUDGET_SECONDS="${BUDGET_SECONDS:-900}"
EXPECT_ALGS="${EXPECT_ALGS:-9}"
REQUIRE_ALL="${REQUIRE_ALL:-0}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/kk-ca-hier.XXXXXX")"
COMPOSE_MODE=0
FAILED=0
RUN_ID="$(date +%s)"

STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
cleanup() {
  if [ "$COMPOSE_MODE" = 1 ]; then
    (cd "$REPO_ROOT" && podman compose -p "$PROJECT" down -v --remove-orphans) >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
DIE() { echo "FAIL: $*"; cleanup; exit 1; }
trap cleanup EXIT

STEP "preflight"
for t in curl python3 "$OPENSSL_BIN"; do command -v "$t" >/dev/null 2>&1 || DIE "missing tool: $t"; done
OSSL_VER="$("$OPENSSL_BIN" version)"
OSSL_NUM="$(echo "$OSSL_VER" | awk '{print $2}')"
echo "openssl: $OSSL_VER"
ossl_ge_35() { python3 - "$OSSL_NUM" <<'PY'
import re,sys
m=re.match(r'(\d+)\.(\d+)',sys.argv[1]); sys.exit(0 if m and (int(m[1]),int(m[2]))>=(3,5) else 1)
PY
}
case "$OSSL_VER" in LibreSSL*) OSSL_MLDSA=0;; *) ossl_ge_35 && OSSL_MLDSA=1 || OSSL_MLDSA=0;; esac

CACERT_ARGS=()
if [ -n "${KK_BASE_URL:-}" ]; then
  BASE="$KK_BASE_URL"; TOKEN="${KK_TOKEN:?KK_TOKEN required in attach mode}"
  [ -n "${KK_CACERT:-}" ] && CACERT_ARGS=(--cacert "$KK_CACERT")
  T0=$(date +%s)
else
  COMPOSE_MODE=1
  BASE="https://localhost:8080"
  TOKEN="w23ca-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  export APP_BOOTSTRAP_TOKEN="$TOKEN"
  KRYPTKEEPER_KEYSTORE_PASSPHRASE="w23ca-keystore-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  export KRYPTKEEPER_KEYSTORE_PASSPHRASE
  # The hub refuses to start with no CA at all (startup_ca.go), so the day-one
  # root the operator would have is created by the documented bootstrap flag.
  export KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true
  COMMIT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  export COMMIT
  cd "$REPO_ROOT" || exit 1
  podman compose -p "$PROJECT" down -v --remove-orphans >/dev/null 2>&1 || true
  STEP "build hub image (untimed)"
  podman compose -p "$PROJECT" build kryptkeeper >"$WORK/build.log" 2>&1 || { tail -30 "$WORK/build.log"; DIE "compose build failed"; }
  PASS "image built (excluded from the clock)"
  STEP "compose up (clock starts)"
  T0=$(date +%s)
  podman compose -p "$PROJECT" up -d kryptkeeper >"$WORK/up.log" 2>&1 || { tail -30 "$WORK/up.log"; DIE "compose up failed"; }
fi

api() { curl -sS "${CACERT_ARGS[@]}" -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c 'import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d=d[int(k)] if isinstance(d,list) else d[k]
print(d)' "$1" 2>/dev/null; }

if [ "$COMPOSE_MODE" = 1 ]; then
  STEP "export ca.pem from tls-trust volume and wait for hub"
  for _ in $(seq 1 90); do
    podman run --rm -v "${PROJECT}_tls-trust:/trust:ro" docker.io/library/alpine:3.20 cat /trust/ca.pem >"$WORK/ca.pem" 2>/dev/null && [ -s "$WORK/ca.pem" ] && break
    sleep 2
  done
  [ -s "$WORK/ca.pem" ] || { podman compose -p "$PROJECT" logs --tail 40 kryptkeeper; DIE "ca.pem never appeared"; }
  CACERT_ARGS=(--cacert "$WORK/ca.pem")
fi
ready=0
for _ in $(seq 1 90); do
  [ "$(curl -sS -o /dev/null -w '%{http_code}' "${CACERT_ARGS[@]}" "$BASE/readyz" 2>/dev/null)" = 200 ] && { ready=1; break; }
  sleep 2
done
[ "$ready" = 1 ] || DIE "hub never became ready at $BASE"
PASS "hub ready at $BASE"

STEP "leaf template"
TPL_ID="$(api -X POST "$BASE/api/v1/templates" -d "{\"name\":\"d1-leaf-$RUN_ID\",\"display_name\":\"Day-one leaf\",\"validity_period\":\"P365D\",\"key_usage\":[\"digitalSignature\",\"keyEncipherment\"],\"extended_key_usage\":[\"clientAuth\"],\"allowed_algorithms\":[\"ECDSA\",\"RSA\"],\"active\":true}" | jget data.id)"
[ -n "$TPL_ID" ] && PASS "template $TPL_ID" || DIE "template create failed"

STEP "discover supported algorithms (POST algorithm=DSA -> 400 supported_algorithms)"
ALGS="$(api -X POST "$BASE/api/v1/cas" -d '{"name":"probe","type":"root","algorithm":"DSA","subject_cn":"probe"}' \
  | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)["supported_algorithms"]))' 2>/dev/null)"
N_ALGS="$(echo "$ALGS" | wc -w | tr -d ' ')"
echo "supported algorithms ($N_ALGS): $ALGS"
[ "$N_ALGS" = "$EXPECT_ALGS" ] && PASS "supported algorithm count == $EXPECT_ALGS" || DIE "supported algorithm count $N_ALGS != $EXPECT_ALGS"

openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/leaf.key" 2>/dev/null || DIE "leaf key"
"$OPENSSL_BIN" req -new -key "$WORK/leaf.key" -subj "/CN=d1-leaf.example.test" -out "$WORK/leaf.csr" 2>/dev/null || DIE "leaf csr"
CSR_JSON="$(python3 -c 'import json,sys; print(json.dumps(open(sys.argv[1]).read()))' "$WORK/leaf.csr")"

RESULTS=()
for ALG in $ALGS; do
  STEP "$ALG"
  D="$WORK/$ALG"; mkdir -p "$D"
  ok=1; why=""
  if case "$ALG" in ML-DSA-*) [ "$OSSL_MLDSA" = 0 ];; *) false;; esac; then
    if [ "$REQUIRE_ALL" = 1 ]; then FAIL "$ALG: openssl < 3.5 cannot verify ML-DSA (REQUIRE_ALL=1)"; RESULTS+=("{\"alg\":\"$ALG\",\"ok\":false}")
    else echo "SKIP-openssl<3.5: $ALG"; RESULTS+=("{\"alg\":\"$ALG\",\"ok\":null,\"skipped\":\"openssl<3.5\"}"); fi
    continue
  fi
  ROOT_ID="$(api -X POST "$BASE/api/v1/cas" -d "{\"name\":\"d1-root-$ALG-$RUN_ID\",\"type\":\"root\",\"algorithm\":\"$ALG\",\"subject_cn\":\"D1 Root $ALG\"}" | jget data.id)"
  [ -n "$ROOT_ID" ] || { ok=0; why="root create"; }
  if [ "$ok" = 1 ]; then
    ISS_ID="$(api -X POST "$BASE/api/v1/cas" -d "{\"name\":\"d1-iss-$ALG-$RUN_ID\",\"type\":\"intermediate\",\"parent_ca_id\":\"$ROOT_ID\",\"algorithm\":\"$ALG\",\"subject_cn\":\"D1 Issuing $ALG\"}" | jget data.id)"
    [ -n "$ISS_ID" ] || { ok=0; why="issuing create"; }
  fi
  if [ "$ok" = 1 ]; then
    FP="$(api -X POST "$BASE/api/v1/certificates" -d "{\"ca_id\":\"$ISS_ID\",\"template_id\":\"$TPL_ID\",\"csr_pem\":$CSR_JSON}" | jget data.fingerprint_sha256)"
    [ -n "$FP" ] || { ok=0; why="leaf issue"; }
  fi
  if [ "$ok" = 1 ]; then
    api "$BASE/api/v1/cas/$ROOT_ID/chain?format=pem" -o "$D/root-chain.pem"
    api "$BASE/api/v1/cas/$ISS_ID/chain?format=pem" -o "$D/iss-chain.pem"
    api "$BASE/api/v1/certificates/$FP/download?format=pem" -o "$D/leaf.pem"
    # first PEM block of a chain = the CA's own certificate
    awk '/BEGIN CERTIFICATE/{n++} n==1' "$D/root-chain.pem" > "$D/root.pem"
    awk '/BEGIN CERTIFICATE/{n++} n==1' "$D/iss-chain.pem" > "$D/issuing.pem"
    out="$("$OPENSSL_BIN" verify -CAfile "$D/root.pem" -untrusted "$D/issuing.pem" "$D/leaf.pem" 2>&1)"
    if echo "$out" | grep -q ': OK$'; then :; else ok=0; why="openssl verify: $out"; fi
  fi
  if [ "$ok" = 1 ]; then PASS "$ALG: root+issuing+leaf created, openssl verify OK"; RESULTS+=("{\"alg\":\"$ALG\",\"ok\":true}")
  else FAIL "$ALG: $why"; RESULTS+=("{\"alg\":\"$ALG\",\"ok\":false}"); fi
done

T1=$(date +%s); ELAPSED=$((T1 - T0))
STEP "result"
echo "ELAPSED=${ELAPSED}s (budget ${BUDGET_SECONDS}s)"
[ "$ELAPSED" -lt "$BUDGET_SECONDS" ] && PASS "elapsed under budget" || FAIL "elapsed ${ELAPSED}s >= budget ${BUDGET_SECONDS}s"

MACHINE="$(uname -sm), $(sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo | cut -d: -f2), $(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1073741824 )) GiB RAM"
HUB_VER="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
RES_JOINED="$(IFS=,; echo "${RESULTS[*]}")"
python3 - "$HERE/last-run.json" "$HUB_VER" "$OSSL_VER" "$ELAPSED" "$BUDGET_SECONDS" "$MACHINE" "$COMPOSE_MODE" "[$RES_JOINED]" <<'PY'
import json,sys,datetime
p,ver,ossl,el,bud,mach,comp,res=sys.argv[1:9]
json.dump({"date":datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),"hub_version":ver,"openssl":ossl,
 "mode":"compose" if comp=="1" else "attach","algorithms":json.loads(res),"elapsed_s":int(el),"budget_s":int(bud),"machine":mach},open(p,"w"),indent=2)
open(p,"a").write("\n")
PY
cat "$HERE/last-run.json"
if [ "$FAILED" = 0 ]; then echo "ALL PASS"; else echo "ONE OR MORE STEPS FAILED"; fi
exit "$FAILED"
