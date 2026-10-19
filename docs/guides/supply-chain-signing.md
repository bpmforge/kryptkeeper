# Signing containers and SBOMs from CI with Kryptkeeper

Go from a CI job to a signed container image and SBOM, timestamped, and
verifiable after the signing certificate has expired, using only Kryptkeeper:
the hub verifies the job's OIDC token, issues a short-lived code-signing
certificate for the key the job generated, and timestamps the signature.

**Tested with:** hub `v0.13.0-20-gb570f97e` (v0.17.0 development branch),
cosign v3.1.3, OpenSSL 3.6.5, syft 1.54.1, podman 6.1.3, 2026-10-16. The token
issuer was a **fake CI issuer** (`tests/live/codesign-oidc/fakeidp`), not GitHub.
JDK/`jarsigner`: **not tested** (no JDK on the test host). Every command below
that touches the hub was run by `tests/live/codesign-oidc/run.sh` against a live hub
(62 checks passed); the GitHub Actions and GitLab snippets in section 3 show how
the same calls are made from those systems and were not run on them.

## 1. What you get, and what you do not

- A code-signing certificate (EKU `codeSigning` only) valid for at most 15
  minutes (`KRYPTKEEPER_CODESIGN_TTL`, default 14 minutes, clamped to
  30 s to 14 min), for a key that never leaves the CI job.
- The certificate is bound to the repository and ref by a URI SAN
  `<base>/<repo>@<ref>`, for example `https://github.com/acme/app@refs/heads/main`
  (`https://github.com` for GitHub, the token issuer URL for GitLab). Verifiers
  match it with `--certificate-identity`.
- RFC 3161 timestamps from the hub (`POST /api/v1/tsa`), so a signature made
  while the certificate was valid still verifies after it expired.
- Revocation through the normal path (`POST /api/v1/certificates/{fingerprint}/revoke`),
  and every issuance and timestamp is audited.

**Not in v1.0:** Sigstore-compatible (Fulcio-style) mode, the Fulcio and Rekor
APIs, and a transparency log (Rekor) are v1.x. Signatures here are not logged
anywhere public: use `--tlog-upload=false` when signing and `--insecure-ignore-tlog`
when verifying. The certificate also lacks Fulcio's OIDC-issuer extension, so
cosign refuses an exact `--certificate-oidc-issuer` (`expected issuer value ...,
got ""`); verify with `--certificate-oidc-issuer-regexp '.*'` and pin trust with
the certificate identity and your own trusted root.

## 2. One-time setup (operator)

1. Have an active CA that will sign these certificates. A dedicated
   intermediate is recommended; the live run used the hub's bootstrap root. No
   certificate template is needed.
2. Optional TSA: provision a time-stamping certificate (EKU `timeStamping`,
   marked critical) and key, and set `KRYPTKEEPER_TSA_CERT_FILE` and
   `KRYPTKEEPER_TSA_KEY_FILE` (PKCS#8, mode 0600). Without them
   `POST /api/v1/tsa` answers 503.
3. If the hub reaches your token issuer over a private CA, make the hub trust it
   (the live run set `SSL_CERT_FILE` on a Linux container).
4. Propose a trust rule as an administrator. `ref_pattern` must start with
   `refs/`, `repo_pattern` must name an owner, patterns follow Go `path.Match`
   (`*` stays inside one path segment, `**` is refused), and the issuer must be
   https:

```bash
curl -s -X POST -H "Authorization: Bearer $ALICE" -H 'Content-Type: application/json' \
  "$HUB/api/v1/codesign/oidc-trust-rules" -d '{
    "provider": "github",
    "issuer": "https://token.actions.githubusercontent.com",
    "audience": "lab-hub",
    "repo_pattern": "acme/app",
    "ref_pattern": "refs/heads/main",
    "ca_id": "'"$CA_ID"'",
    "rationale": "release signing"
  }'
```

The answer is `202 {"data":{"action_id":"...","status":"pending"}}`. The rule
does nothing yet: tokens are still refused. A **second** administrator approves
it (the proposer gets 403 on their own request):

```bash
URL=$(printf '%s' "$HUB/api/v1/pending-actions/{id}/approve" | sed "s|{id}|$ACTION_ID|")
curl -s -X POST -H "Authorization: Bearer $BOB" "$URL"
```

Rules are listed with `GET /api/v1/codesign/oidc-trust-rules` (your tenant's
only) and removed with `DELETE /api/v1/codesign/oidc-trust-rules/{id}`. Removal
is single control by design: taking trust away is the safe direction.

## 3. CI exchange

In GitHub Actions the job needs `permissions: id-token: write`, then requests a
token for your audience and exchanges it. No hub credential is involved: the
OIDC token is the credential.

```bash
OIDC=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=lab-hub" | python3 -c 'import json,sys; print(json.load(sys.stdin)["value"])')
```

The live run obtained the equivalent token from the fake issuer instead:
`curl "$IDP/token?repo=acme/app&ref=refs/heads/main&aud=lab-hub"`.

Generate an ephemeral key and CSR (ECDSA P-256/P-384/P-521 or RSA 3072 and up;
Ed25519, RSA-2048 and ML-DSA are refused with 400), then exchange:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out key.pem
openssl req -new -key key.pem -subj "/CN=ci-ephemeral" -out csr.pem
BODY=$(python3 -c 'import json,sys; print(json.dumps({"oidc_token":sys.argv[1],"csr_pem":open("csr.pem").read()}))' "$OIDC")
curl -s -X POST -H 'Content-Type: application/json' "$HUB/api/v1/codesign/issue" -d "$BODY" > issued.json
python3 -c 'import json; print(json.load(open("issued.json"))["data"]["certificate_pem"])' > cert.pem
python3 -c 'import json; print(json.load(open("issued.json"))["data"]["chain_pem"])' > chain.pem
```

The `201` body carries `certificate_pem`, `chain_pem`, `serial_number`,
`fingerprint_sha256`, `not_before`, `not_after`, `repo` and `ref`. A refused token
(unknown issuer, wrong audience, repo or ref outside every rule, expired, or a
reused `jti`) gets `401 {"error":"unauthorized","message":"token refused"}` and
nothing else: the reason is in the audit trail only (section 8). The certificate's
subject comes from the token, never from the CSR.

GitLab CI: declare `id_tokens: { KK_TOKEN: { aud: lab-hub } }`, create the rule
with `"provider": "gitlab"` and the GitLab instance as issuer; the repository
claim is `project_path` and the identity URI base is the issuer URL. This path
is covered by unit tests, not by the live run.

## 4. Sign a container and an SBOM with cosign

cosign 3.1.3 reads only its own key format, so import the job's key first. Do
not pass `--certificate-chain` when signing: with it cosign 3.1.3 writes a
legacy bundle that its own verifier rejects (the chain goes to the verifier in a
trusted root, section 6).

```bash
COSIGN_PASSWORD="" cosign import-key-pair --key key.pem --output-key-prefix cs

# container, pinned by digest
COSIGN_PASSWORD="" cosign sign --key cs.key --certificate cert.pem \
  --tlog-upload=false --use-signing-config=false --yes "$IMAGE@$DIGEST"

# SBOM
syft "registry:$IMAGE" -o cyclonedx-json=sbom.cdx.json
COSIGN_PASSWORD="" cosign sign-blob --key cs.key --certificate cert.pem \
  --use-signing-config=false --tlog-upload=false --bundle sbom.bundle.json sbom.cdx.json
```

## 5. Timestamp (RFC 3161)

`POST /api/v1/tsa` needs a hub Bearer token unless the operator set
`KRYPTKEEPER_TSA_ALLOW_ANONYMOUS=true` (off by default; `jarsigner -tsa` and
`openssl ts` cannot send a Bearer token). Timestamp the **signature**, so the
time proves the signature existed while the certificate was valid:

```bash
python3 -c "import json,base64,sys; sys.stdout.buffer.write(base64.b64decode(json.load(open('sbom.bundle.json'))['messageSignature']['signature']))" > sbom.sig
openssl ts -query -data sbom.sig -sha256 -cert -out q.tsq
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/timestamp-query' \
  --data-binary @q.tsq -o r.tsr "$HUB/api/v1/tsa"
openssl ts -verify -data sbom.sig -in r.tsr -CAfile tsa-root.pem
```

A rejected request (for example SHA-1) is still HTTP 200; read the PKIStatus.
cosign cannot send the Bearer token, so put the whole reply into the bundle:

```bash
python3 - sbom.bundle.json r.tsr <<'PY'
import json, base64, sys
d = json.load(open(sys.argv[1]))
d["verificationMaterial"]["timestampVerificationData"] = {"rfc3161Timestamps": [{"signedTimestamp": base64.b64encode(open(sys.argv[2], "rb").read()).decode()}]}
json.dump(d, open(sys.argv[1], "w"))
PY
```

`jarsigner -tsa "$HUB/api/v1/tsa"` and `signtool /tr "$HUB/api/v1/tsa"` take the
same endpoint (anonymous mode required); neither was run for this guide
(signtool is Windows-lane only).

## 6. Verify, including after the certificate expired

Build a trusted root from your CA chain and the TSA certificates (the live run
generated it with a short Python script, see `tests/live/codesign-oidc/run.sh`, section
F), then:

```bash
cosign verify-blob --trusted-root trusted_root.json \
  --certificate-identity "https://github.com/acme/app@refs/heads/main" \
  --certificate-oidc-issuer-regexp '.*' --insecure-ignore-tlog --insecure-ignore-sct \
  --use-signed-timestamps --bundle sbom.bundle.json sbom.cdx.json

cosign verify --trusted-root trusted_root.json \
  --certificate-identity "https://github.com/acme/app@refs/heads/main" \
  --certificate-oidc-issuer-regexp '.*' --insecure-ignore-tlog --insecure-ignore-sct "$IMAGE@$DIGEST"
```

The SBOM verification succeeded after the certificate had expired (the cert's
`openssl x509 -checkend 0` failed first). The image verification was run while the
certificate was still valid; this guide does not claim a post-expiry image check
(cosign would need the timestamp inside the image's signature bundle, which needs
a signing config pointing at an anonymous TSA, not exercised here).

Negative checks that were run: the same expired certificate with no timestamp in
the bundle is refused (`threshold not met for verified signed timestamps: 0 < 1`),
as are a tampered blob and another repository's identity. With OpenSSL alone:

```bash
openssl ts -verify -data blob.sig -in r.tsr -CAfile tsa-root.pem          # passes after expiry
openssl verify -attime "$GEN_TIME_EPOCH" -purpose codesign -CAfile chain.pem cert.pem   # passes as of the timestamp
openssl verify -purpose codesign -CAfile chain.pem cert.pem               # fails: certificate has expired
```

## 7. Revocation semantics

A timestamp proves only that a signature existed at `genTime`; it never
overrides revocation. If the certificate is revoked with reason `keyCompromise`,
treat every signature from it as untrusted, timestamped or not: CRL/OCSP verifiers
do (the live run shows the CA's CRL listing the serial with `Key Compromise`
while the timestamp itself still verifies). For any other reason, signatures
timestamped before the revocation time stay valid. The cut-off is the hub's
`revoked_at` (`GET /api/v1/certificates/{fingerprint}`) compared with the token's
`genTime`; the run asserts `genTime <= revoked_at` for the revoked certificate.
Revoke with:

```bash
URL=$(printf '%s' "$HUB/api/v1/certificates/{fingerprint}/revoke" | sed "s|{fingerprint}|$FINGERPRINT|")
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$URL" -d '{"reason_code":1}'
```

A revoke must happen while the certificate is still valid: the hub answers 409
for an expired one.

## 8. Audit and troubleshooting

`GET /api/v1/audit?action=...` shows:

- `codesign.issue` success: `repo`, `ref`, certificate `serial`, issuer and rule id.
- `codesign.issue` denied: `issuer` and `reason`, for every refused token.
- `codesign.timestamp`: `digest`, `alg`, `serial`, `nonce` (never the request body).
- `codesign.trust_rule_propose`, `codesign.trust_rule_create` (proposer and
  approver) and `codesign.trust_rule_delete`.

| Audit `reason` | Meaning |
|---|---|
| `untrusted_issuer` | No approved trust rule for the token's issuer (also: rule still pending approval) |
| `token_invalid` | Bad signature, wrong audience, expired, `nbf`/`iat` outside tolerance, or lifetime over 1 hour |
| `no_matching_rule` | Valid token, but repository or ref matches no rule for that audience |
| `replay` | The `jti` was already used |
| `missing_jti` | The token has no `jti` |
| `malformed` | Not a JWT, empty, or over 2 KiB |

Clock tolerance: `nbf` and `iat` accept up to 60 seconds of skew; `exp` has none.
The live run saw all of `untrusted_issuer`, `no_matching_rule` and `replay`.
