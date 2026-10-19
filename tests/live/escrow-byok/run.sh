#!/usr/bin/env bash
# W23-20: executed escrow-recover + BYOK-import drill. Real code paths
# (keystore.EscrowKey / RecoverEscrowedKey / ExportEscrowedKeyToKMS) against
# moto (AWS KMS emulator). Lowkey Vault (Azure emulator) is started and pinged
# so the record shows the Azure emulator was present, but no Azure BYOK target
# exists (refused by design, follow-up W23-20a), so the Azure leg asserts that
# refusal. Writes a dated record to $KK_DRILL_OUT
# (default docs/release/DRILL_ESCROW_BYOK_v0.11.md). No secrets in the record.
set -u -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
CE="${CONTAINER_ENGINE:-podman}"
MOTO="kk-drill-escrow-moto"; LOWKEY="kk-drill-escrow-lowkey"
MPORT="${KK_MOTO_PORT:-5556}"; LPORT="${KK_LOWKEY_PORT:-8444}"
MIMAGE="${KK_MOTO_IMAGE:-docker.io/motoserver/moto:latest}"
LIMAGE="${KK_LOWKEY_IMAGE:-docker.io/nagyesta/lowkey-vault:7.3.112}"
OUT="${KK_DRILL_OUT:-$REPO_ROOT/docs/release/DRILL_ESCROW_BYOK_v0.11.md}"
WORK="$(mktemp -d /tmp/kk-drill-escrow.XXXXXX)"
cleanup() { "$CE" rm -f "$MOTO" "$LOWKEY" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT
"$CE" rm -f "$MOTO" "$LOWKEY" >/dev/null 2>&1 || true

"$CE" run -d --name "$MOTO" -p "127.0.0.1:${MPORT}:5000" "$MIMAGE" >/dev/null || { echo "FAIL: start moto"; exit 1; }
"$CE" run -d --name "$LOWKEY" -p "127.0.0.1:${LPORT}:8443" "$LIMAGE" >/dev/null || { echo "FAIL: start lowkey-vault"; exit 1; }
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:${MPORT}/moto-api/" >/dev/null && break; sleep 1; done
curl -sf "http://127.0.0.1:${MPORT}/moto-api/" >/dev/null || { echo "FAIL: moto never answered"; exit 1; }
for _ in $(seq 1 150); do curl -sfk -m3 "https://localhost:${LPORT}/ping" >/dev/null && break; sleep 1; done
curl -sfk "https://localhost:${LPORT}/ping" >/dev/null || { echo "FAIL: lowkey-vault never answered"; exit 1; }
echo "PASS: moto :${MPORT} and lowkey-vault :${LPORT} answering"

MDIGEST="$("$CE" image inspect "$MIMAGE" --format '{{.Id}}' 2>/dev/null | cut -c1-12)"
LDIGEST="$("$CE" image inspect "$LIMAGE" --format '{{.Id}}' 2>/dev/null | cut -c1-12)"
MVER="$("$CE" exec "$MOTO" python -c 'import moto;print(moto.__version__)' 2>/dev/null || echo unknown)"

export AWS_ENDPOINT_URL="http://127.0.0.1:${MPORT}" AWS_REGION=us-east-1 \
  AWS_ACCESS_KEY_ID=kk-drill AWS_SECRET_ACCESS_KEY=kk-drill KK_LIVE_ESCROW_BYOK=1
cd "$REPO_ROOT" && go test ./tests/live/escrow-byok/ -count=1 -v 2>&1 | tee "$WORK/test.log"
RC="${PIPESTATUS[0]}"
# Server-side evidence of why the AWS leg is PARTIAL: moto's own log.
"$CE" logs "$MOTO" 2>&1 | grep -E "NotImplementedError|has not been implemented" | sort | uniq -c >"$WORK/moto-ni.log"

{
  echo "# DRILL: escrow-recover and BYOK import (W23-20)"
  echo
  echo "- Date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- Git SHA: $(git -C "$REPO_ROOT" rev-parse HEAD)"
  echo "- Machine: $(uname -srm), $(go version | awk '{print $3}'), podman $(podman --version | awk '{print $NF}')"
  echo "- moto image: $MIMAGE (id $MDIGEST, moto $MVER)"
  echo "- Lowkey Vault image: $LIMAGE (id $LDIGEST)"
  echo "- Result: $([ "$RC" -eq 0 ] && echo 'go test exit 0' || echo "go test exit $RC (FAILED)")"
  echo
  echo "## Leg results (extracted from the run below)"
  echo
  grep -E '^(--- |    --- )(PASS|FAIL)|RESULT:' "$WORK/test.log" | sed -E 's/^ +escrow_byok_live_test.go:[0-9]+: //' | sed 's/^/- /'
  echo
  echo "## Full output"
  echo
  echo '```'
  cat "$WORK/test.log"
  echo '```'
  echo
  echo "moto server-side log (why the AWS leg is PARTIAL):"
  echo '```'
  cat "$WORK/moto-ni.log"
  echo '```'
  echo
  echo "## Not proven by this drill"
  echo
  echo "- AWS BYOK import is PARTIAL: moto does not implement GetParametersForImport, so the RSA_AES_KEY_WRAP_SHA_256 wrap, ImportKeyMaterial and post-import key equality are NOT exercised against any AWS-compatible service here. The wrap format is covered only by the in-process KMS stand-in in internal/keystore/byok_test.go. Real AWS KMS is needed to close this."
  echo "- Azure BYOK: no Azure import target exists (NewKMSImportTarget refuses by design); Lowkey Vault was started and answered /ping only. Follow-up W23-20a. Acceptance #2 is NOT met for Azure."
  echo "- moto caveats from tests/live/kms-aws/README.md apply (IAM, quotas, MessageType=DIGEST handling are not emulated). Lowkey Vault runs amd64 under qemu on this arm64 host (slow start, ~75s)."
  echo "- RTO/RPO of the surrounding DR restore are not measured by this drill; see docs/ops/RESTORE_DRILL.md."
  echo
  echo "Reproduce: \`bash tests/live/escrow-byok/run.sh\`"
} >"$WORK/record.md"
if grep -c 'BEGIN' "$WORK/record.md" | grep -qv '^0$'; then echo "FAIL: record contains BEGIN marker; not writing"; exit 1; fi
cp "$WORK/record.md" "$OUT"
echo "record written to $OUT"
if [ "$RC" -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "FAIL: see above"; exit 1; fi
