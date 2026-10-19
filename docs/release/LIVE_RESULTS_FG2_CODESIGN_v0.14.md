# Live validation W26-24: code-signing with SoftHSM2 and osslsigncode - v0.14

Date: 2026-10-16T17:15:31Z. Hub commit: 8b226a19. Host: Linux 7.1.10-200.fc44.aarch64 aarch64
(container image `tests/live/codesign/Dockerfile`, Debian bookworm). Harness: `tests/live/codesign/run.sh`.
softhsm2: 2.6.1. osslsigncode: 2.5. openssl: 3.0.22. pkcs11-tool: version not reported
(`--version` is unrecognised by this build). osslsigncode PKCS#11 path: engine by name (`pkcs11`).
SoftHSM2 module: `/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so`.
Source log: `uat24-pass.log`, real run 2026-10-16, ends `ALL STEPS PASSED (attestation path PENDING)`, `EXIT 0`.

## Verdict: PASS - validated, except the attestation success path (PENDING, hardware)

Both board acceptance items are shown passing. The attestation success path (FR-P92) needs a
real YubiKey and the Yubico root; it is not part of this ticket's acceptance and stays PENDING.

## Steps

| Step | Result | Evidence |
|---|---|---|
| 1. SoftHSM2 token, hub `-tags pkcs11`, protected mode, root CA in token | PASS | token `kk-uat`; hub on :8226 with `KRYPTKEEPER_CODESIGN_PROTECTED=true`; root CA ea492fc5-230a-47db-86e6-527ef94d7286 |
| 2. template `uat-codesign` created, `require_approval:false` | PASS | 201 (also `uat-serverauth` 201) |
| 3. request -> 202; 0 certificates in inventory | PASS | 202, `apr-4dcfda2f46408625d7442b7ffd395faf`; 0 certs for 'UAT Publisher' |
| 4. self-approval 403; second user approves 201; 1 certificate | PASS | 403, then bob 201; fingerprint 629eb1a8cc61efe68a6e52bc1b8689b8306b3b811138bbacafdbbbef58f4061c; exactly 1 cert |
| 5. private key object labelled `key_id` present in the token | PASS | `codesign-apr-4dcfda2f46408625d7442b7ffd395faf` |
| 6. osslsigncode signs with the HSM key; `osslsigncode verify` ok | PASS | `Signature verification: ok Number of verified signatures: 1` |
| 7. export fails: never extractable, read-object no bytes, API export refused | PASS | "never extractable"; read-object yields no bytes; export proposed 202, approved 200, store refused HTTP 503, no PEM |
| 8. policy-check flags the non-compliant cert (and not the HSM cert) | PASS | `{'evaluated': 2, 'violating': 1, 'compliant': 1}` (min RSA 3072, max 398 days; imported RSA-2048 cert flagged) |
| 8. audit holds `codesign.policy.check` and `codesign.request.deny` | PASS | serverAuth-only template refused 422 |
| 8. requester CSR without attestation refused (`attestation_missing`) | PASS | 422, `attestation_missing`, no certificate issued |
| Attestation success path (YubiKey PIV, Yubico root) | PENDING (hardware) | `MEASURE attestation_path=PENDING`; not run |

## Findings and product fixes this run drove

- osslsigncode 2.5 signs a PE via the engine by name (`engine-by-name (pkcs11)`); no flag workaround was needed.
- Migration 000196: Baseline policy allows RSA-3072; the policy API, openapi and UI accept RSA-3072.
- X.509 approval templates now dry-run the engine policy before queueing (W26-32 commit).
- No defect in W26-22/23 was revealed.
