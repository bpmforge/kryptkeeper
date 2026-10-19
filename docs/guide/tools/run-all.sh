#!/usr/bin/env bash
# Ordered capture run on a fresh hub. Env: RUN (work dir with pid/log/token files), BIN (hub binary),
# STAGE=main|finals|all  (default all). Stops only PIDs recorded under $RUN.
set -uo pipefail
H="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; REPO="$H/../../.."; cd "$REPO"
: "${RUN:?}" "${BIN:?}"
NAME=main; HP=${HP:-18080}; UP=${UP:-14180}; DATA=${DATA:-$RUN/data-main}
export KK_BASE="http://127.0.0.1:$UP"
rs() { for f in "$@"; do perl -e 'alarm 420; exec @ARGV' node "$H/run-spec.mjs" --base "$KK_BASE" --tokdir "$RUN" ${RSARGS:-} "docs/guide/specs/$f.json" || echo "$f: WATCHDOG/ERR"; done; }
persona() { bash "$H/hub.sh" stop $NAME hub; sleep 1.5
  LOGIN_EMAIL=$1 LOGIN_SUBJECT=$2 LOGIN_ROLE=$3 bash "$H/hub.sh" start $NAME $HP $UP $DATA >/dev/null; bash "$H/tokens.sh" $HP $1 "$RUN/tok-$4.json"; }
export EXTRA_ENV="KRYPTKEEPER_ANOMALY_SWEEP_MINUTES=2 KRYPTKEEPER_SLO_SWEEP_MINUTES=2"
STAGE=${STAGE:-all}
LANIP=${LANIP:-$(cat "$RUN/lanip")}
SHOTS=docs/guide/screenshots
if [ "$STAGE" = main ] || [ "$STAGE" = all ]; then
  rm -rf "$SHOTS"; mkdir -p "$SHOTS"
  curl -s -X DELETE http://127.0.0.1:18025/api/v1/messages >/dev/null || true; : > "$RUN/webhook.log"
  bash "$H/fresh.sh" $NAME $HP $UP $DATA
  persona marcus.webb@acme.test marcus.webb pki-admin marcus
  persona dana.approver@acme.test dana approver dana
  persona alice@acme.test alice pki-admin alice
  persona bob@acme.test bob pki-admin bob
  persona ada.admin@acme.test ada.admin pki-admin ada
  # time-sensitive and empty states first (anomaly sweep every 2 min)
  rs U-54 U-47a U-41 U-44 U-50 U-53
  rs U-01 U-02 U-03 U-07 U-04 U-05 U-06 U-10 U-11 U-12 U-13 U-14 U-15 U-16 U-20 U-21 U-22 U-24
  rs U-25 U-26 U-27 U-28 U-29 U-30 U-31 U-32 U-33 U-34 U-37 U-38 U-39 U-40 U-42 U-43 U-45 U-46 U-48 U-49 U-51 U-52
  rs U-09 U-35 U-36 U-56 U-57 U-58 U-55
  rs U-19x U-17 U-19 U-43b U-18
  rs U-09b U-09c
  rs U-26b U-15b U-47 U-45 U-59 U-60
  rs U-08 U-23
  # let the scheduled sweeps run (2 minute interval), then capture the populated reports
  sleep 150
  rs U-54b
fi
if [ "$STAGE" = config ] || [ "$STAGE" = all ]; then
  # CONFIG stories run against their own hubs and data dirs
  CFGDATA=${CFGDATA:-$RUN/data-cfg}; TENDATA=${TENDATA:-$RUN/data-ten}
  bash "$H/hub.sh" stop cfg all; bash "$H/hub.sh" stop ten all; sleep 1; rm -rf "$CFGDATA" "$CFGDATA.cwd" "$TENDATA" "$TENDATA.cwd"
  bash "$H/hub.sh" start cfg 18082 14182 "$CFGDATA" >/dev/null; bash "$H/tokens.sh" 18082 ada.admin@acme.test "$RUN/tok-cfgada.json"
  T=$(jq -r .access_token "$RUN/tok-cfgada.json")
  ROOT=$(curl -s localhost:18082/api/v1/cas -H "authorization: Bearer $T" | jq -r '.data[0].id')
  RSA=$(curl -s -X POST localhost:18082/api/v1/cas -H "authorization: Bearer $T" -H 'content-type: application/json' -d '{"type":"root","subject_cn":"Acme SCEP Root","subject_org":"Acme","algorithm":"RSA-2048","validity":"10y"}' | jq -r .data.id)
  bash "$H/hub.sh" stop cfg hub; sleep 1.5
  EXTRA_ENV="KRYPTKEEPER_SCEP_ENABLED=true KRYPTKEEPER_SCEP_CA_ID=$RSA SPIFFE_SIGNING_CA_ID=$ROOT SIEM_WEBHOOK_URL=http://$LANIP:18099/siem SIEM_FORMAT=cef" bash "$H/hub.sh" start cfg 18082 14182 "$CFGDATA" >/dev/null
  KK_BASE=http://127.0.0.1:14182 rs U-28b U-44b U-58b
  RSARGS="--finals --theme dark --vp 1440x900" KK_BASE=http://127.0.0.1:14182 rs U-28b U-44b U-58b
  RSARGS="--finals --theme light --vp 375x812" KK_BASE=http://127.0.0.1:14182 rs U-28b U-44b U-58b
  LOGIN_ROLE=super-admin EXTRA_ENV="MULTI_TENANCY=on KRYPTKEEPER_MULTI_TENANCY_EXPERIMENTAL=accept-risk" bash "$H/hub.sh" start ten 18083 14183 "$TENDATA" >/dev/null
  echo '{"access_token":"dev-token","refresh_token":"x"}' > "$RUN/tok-tenboot.json"
  KK_BASE=http://127.0.0.1:14183 rs U-41b
  RSARGS="--finals --theme dark --vp 1440x900" KK_BASE=http://127.0.0.1:14183 rs U-41b
  RSARGS="--finals --theme light --vp 375x812" KK_BASE=http://127.0.0.1:14183 rs U-41b
  bash "$H/hub.sh" stop cfg all; bash "$H/hub.sh" stop ten all
fi
if [ "$STAGE" = finals ] || [ "$STAGE" = all ]; then
  # final state of every story: dark theme at 1440 and light at 375 (re-opens the recorded final URL on the main hub)
  ALL=$(ls docs/guide/specs/*.json | xargs -n1 basename | sed 's/\.json$//' | grep -v '^U-\(28b\|44b\|58b\|41b\)$' | grep -v '^BUG-')
  RSARGS="--finals --theme dark --vp 1440x900" rs $ALL
  RSARGS="--finals --theme light --vp 375x812" rs $ALL
fi
