#!/usr/bin/env bash
# W19-12 (Azure leg, free): the real Azure Key Vault code path against the
# Lowkey Vault emulator, with a stub token endpoint standing in for Entra ID
# (AZURE_AUTHORITY_HOST, loopback only). No Azure account, no cost. Proves
# wiring, JWK parsing and signature format; NOT RBAC, token validation or HSM.
set -u -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
CE="${CONTAINER_ENGINE:-podman}"
NAME=kk-uat-lowkey
IMAGE="${KK_LOWKEY_IMAGE:-docker.io/nagyesta/lowkey-vault:7.3.112}"
VPORT="${KK_LOWKEY_PORT:-8443}"
TPORT="${KK_TOKEN_PORT:-9099}"
WORK="$(mktemp -d /tmp/kk-uat-azure.XXXXXX)"
TOKEN_PID=""
cleanup() {
  [ -n "$TOKEN_PID" ] && kill "$TOKEN_PID" 2>/dev/null || true
  "$CE" rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

"$CE" rm -f "$NAME" >/dev/null 2>&1 || true
"$CE" image inspect "$IMAGE" >/dev/null 2>&1 || "$CE" pull "$IMAGE" >/dev/null || { echo "FAIL: pull $IMAGE"; exit 1; }
"$CE" run -d --name "$NAME" -p "127.0.0.1:${VPORT}:8443" "$IMAGE" >/dev/null || { echo "FAIL: start lowkey-vault"; exit 1; }
for _ in $(seq 1 40); do curl -sfk "https://localhost:${VPORT}/ping" >/dev/null && break; sleep 1; done
curl -sfk "https://localhost:${VPORT}/ping" >/dev/null || { echo "FAIL: lowkey-vault never answered"; exit 1; }
echo "PASS: lowkey-vault answering on :${VPORT}"

# The emulator ships a self-signed localhost cert; trust exactly that cert
# for the Go process (SSL_CERT_FILE replaces the system roots for this run).
openssl s_client -connect "localhost:${VPORT}" -servername localhost </dev/null 2>/dev/null \
  | openssl x509 >"$WORK/lowkey.pem" || { echo "FAIL: could not read emulator cert"; exit 1; }

# Stub Entra ID: any client-credentials request gets a fixed placeholder token.
python3 - "$TPORT" >"$WORK/token.log" 2>&1 <<'PY' &
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = json.dumps({"access_token": "kk-uat-placeholder", "token_type": "Bearer", "expires_in": 3600}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
TOKEN_PID=$!
sleep 1

export SSL_CERT_FILE="$WORK/lowkey.pem" AZURE_KEYVAULT_URL="https://localhost:${VPORT}" \
  AZURE_AUTHORITY_HOST="http://127.0.0.1:${TPORT}" AZURE_TENANT_ID=kk-uat \
  AZURE_CLIENT_ID=kk-uat AZURE_CLIENT_SECRET=kk-uat-placeholder KK_LIVE_KMS_AZURE=1
cd "$REPO_ROOT" && go test ./tests/live/kms-azure/ -count=1 -v 2>&1 | tee "$WORK/test.log"
if [ "${PIPESTATUS[0]}" -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "FAIL: see above"; exit 1; fi
