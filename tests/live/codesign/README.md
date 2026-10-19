# W26-24 - code-signing lifecycle on SoftHSM2 with osslsigncode

Proves the code-signing flow against a REAL SoftHSM2 token: hub-generated key in
the token (`POST /api/v1/codesign/requests`, W26-22), second-user approval,
issuance, an `osslsigncode` signature with the HSM-held key that verifies, no key
export (`CKA_EXTRACTABLE=false`), and the inventory policy-check flagging a
deliberately non-compliant certificate.

## Run

```
bash tests/live/codesign/run.sh
```

SoftHSM2, `pkcs11-tool` and `osslsigncode` are not on most hosts, so the script
builds `Dockerfile` (Debian bookworm with softhsm2, opensc, osslsigncode,
libengine-pkcs11-openssl, Go with cgo) using podman and re-runs itself inside it,
repo mounted read-only at `/src`, hub built with `-tags pkcs11` in the container.
The podman machine is shared with CI: run serially.

| Env | Default | Meaning |
|---|---|---|
| `HUB_PORT` | `8226` | hub port inside the container |
| `KEEP_IMAGE` | `0` | `1` keeps `localhost/kk-codesign-uat:latest` |
| `KK_CODESIGN_NATIVE` | `0` | `1` runs on the host (needs softhsm2-util, pkcs11-tool, osslsigncode, openssl, python3, go with cgo, gcc) |
| `KK_CODESIGN_GOMODCACHE` | unset | host Go module cache dir to mount (faster build) |

Exit codes: `0` all passed; `1` a step failed; `77` SKIP (a tool or podman is
missing); `78` no FAIL but a step is BLOCKED (tooling, e.g. osslsigncode has
neither `-pkcs11engine` nor a usable provider path), which is never a pass.
Prints `MEASURE key=value` lines for the results doc.

Self-cleaning: private `SOFTHSM2_CONF` per run (never `~/.config/softhsm2`), token
selected by label, all state in `mktemp -d`, removed by a trap; the container is
`--rm` and the image is removed unless `KEEP_IMAGE=1`. The PIN is the throwaway
constant `1234`. Nothing is committed: no key, token dir or signed output.

## What each step proves

1. SoftHSM2 token + hub `-tags pkcs11` with `KRYPTKEEPER_KEY_BACKEND=pkcs11`,
   `KRYPTKEEPER_CODESIGN_PROTECTED=true`, bootstrap root in the token, identities
   alice and bob (both `pki-admin`) from `APP_API_KEYS_JSON`.
2. Template `uat-codesign` (EKU `codeSigning`, `require_approval:false`): approval
   is gated by the EKU alone.
3. Request as alice: 202 with `approval_id`/`key_id`; inventory has 0 certs.
4. alice approving her own request: 403; bob approves: 201 with the fingerprint.
5. `pkcs11-tool` lists a private key object labelled with the `key_id`.
6. `osslsigncode sign` (engine or provider, chosen from `--help`) a PowerShell
   script with `pkcs11:object=<key_id>`; `osslsigncode verify -CAfile chain.pem` ok.
7. Export fails: object is "never extractable"; `pkcs11-tool --read-object` yields
   no bytes; `POST /api/v1/keys/<id>/export` goes through dual control (propose,
   bob approves, alice redeems) and the store then refuses: 4xx/5xx, no PEM.
8. Import an RSA-2048 code-signing cert; `policy-check` (`min_rsa_key_size_bits`
   3072, `max_validity_days` 398) reports it and not the HSM cert; audit holds
   `codesign.policy.check` and `codesign.request.deny` (request against a
   serverAuth-only template -> 422). Also: a requester CSR without attestation is
   refused 422 `attestation_missing` in protected mode (FR-P92 fail-closed).

## Attestation: PENDING

FR-P92 requires a YubiKey PIV attestation for requester-supplied CSRs and no
vendor root is shipped yet, so the success path needs a real YubiKey and the
Yubico root. This run uses the hub-generated-key path; only the refusal is asserted.

## Findings

See `docs/release/LIVE_RESULTS_FG2_CODESIGN_v0.14.md` (filled from a real run).
