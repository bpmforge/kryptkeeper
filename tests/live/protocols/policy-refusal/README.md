# Policy refusal live proof (W22-17)

Shows that an issuance-policy refusal reaches real ACME (lego) and EST
(globalsign/est via `../estcheck`) clients with the policy and rule in the
error, and that nothing is signed. A policy `rsa-only`
(`allowed_algorithms: [RSA-4096]`) is created through `POST /api/v1/policies`;
ACME and EST requests with an ECDSA P-256 key are then refused. Controls:
an RSA-3072 ACME order succeeds, and EST enrolls before the policy exists.

The policy is `rsa-only`, not the spec's P-384 list: lego also uses
`--key-type` for its account key and the hub's ACME rejects P-384 account
JWKs (`unsupported EC curve "P-384"`), so a P-384 control cannot run.

Run: `bash tests/live/protocols/policy-refusal/run.sh` (podman, network for
`go get` and image pulls; set `KK_UAT_GOARCH=amd64` on an amd64 podman
machine). It is also invoked by `tests/live/protocols/run.sh`. Exit is
non-zero on any FAIL, including a refused flow that produced a certificate.

Lines proven (2026-10-16):

| Client | Refusal text received |
|---|---|
| lego (ACME) | `400 :: urn:ietf:params:acme:error:badCSR :: issuance policy "rsa-only": rule allowed_algorithms: ...` |
| estcheck (EST) | `FAIL enroll: issuance policy "rsa-only": rule allowed_algorithms: ...` |

```
=== RESULT: 19 passed, 0 failed ===
```
