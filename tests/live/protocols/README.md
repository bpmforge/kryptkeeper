# W19-05: EST/SCEP/CMP/OCSP/CRL live UAT

Proves (or disproves) EST, SCEP and CMP issuance and OCSP/CRL-after-revocation
against REAL third-party clients, not the fakes-only `scripts/test/run.sh
--suite protocol` suite.

```
bash tests/live/protocols/run.sh
```

Podman only (no docker). Idempotent, PASS/FAIL per step, non-zero exit if any
step fails, cleans up the hub process and its temp dir on exit. No real key
material is committed — every key is generated fresh per run.

## Result (2026-10-09)

40 PASS, 0 FAIL.

| Step | Client | Result |
|---|---|---|
| EST cacerts/enroll (over TLS) | `github.com/globalsign/est` | PASS |
| SCEP getcacert/enroll (RSA CA, one-time challenge) | `micromdm/scep` | PASS |
| CMP ir/kur (PBM-protected) | `openssl cmp` | PASS |
| Inventory (`source` = est, scep, cmp, api) | `curl` + hub API | PASS |
| SCEP renewal (current-cert RenewalReq; unrelated key and self-signed signer refused; replay refused) | `micromdm/scep` | PENDING-RUN (W26-11) |
| CMP rr (OCSP revoked, CRL lists serial) and ir + pollReq against an approval-required template | `openssl cmp` | PENDING-RUN (W26-11) |
| EST label enroll, refused outside the suffix / without `protocol:est`, unknown label 404 | `github.com/globalsign/est` | PENDING-RUN (W26-11) |
| OCSP good/revoked | `openssl ocsp` | PASS |
| CRL | `openssl crl` | PASS |

MS-WSTEP/XCEP is not part of this harness. It needs a Windows/AD lab and passed
there on 2026-10-08 (user and machine context); see `tests/live/wstep/README.md`
and `docs/ops/WSTEP_AUTOENROLLMENT.md`.

The 2026-09-10 run recorded FAILs for EST, SCEP enroll, CMP and protocol
inventory; all have since been fixed. The findings below are kept as history.

## W26-11 additions

SCEP renewal, CMP `rr` and poll, and EST labels run inside the same
`run.sh` (record in `docs/release/LIVE_RESULTS_FG2_PROTOCOLS_v0.14.md`).
`APP_API_KEYS_JSON` now carries one named pki-admin (alice, secret generated per
run) because the bootstrap token can never approve. CMP template selection is
`KRYPTKEEPER_CMP_TEMPLATE`, set only for the poll step (it gates every CMP
enrollment), so the hub is restarted once more. `openssl cmp` has no
`-polltime`: the client sleeps the hub's 30 s `checkAfter` between polls, so the
poll step takes about a minute. The CMP and SCEP clients write issued
certificates to `.scep-out.*` next to the script (removed on exit).

## Why EST/SCEP/CMP use hand-built harnesses instead of a CLI

- **EST**: `cmd/estclient` (the CLI globalsign/est ships) fails to build via
  `go install .../estclient@latest` — its optional PKCS#11/`crypto11` code
  path does not compile against the `miekg/pkcs11` version the module proxy
  resolves today (an upstream break, unrelated to Kryptkeeper). `estcheck/`
  is a ~40-line Go program built against the same `github.com/globalsign/est`
  library `cmd/estclient` wraps, exercising the identical RFC 7030 client
  code (`Client.CACerts`, `Client.Enroll`) without the CLI's HSM plumbing.
- **SCEP**: `micromdm/scep`'s `cmd/scepclient` builds and runs cleanly and is
  a real, maintained SCEP client — used directly, no harness needed.
- **CMP**: OpenSSL 3's `openssl cmp` app is used directly.

## Historical findings from 2026-09-10 (all since fixed; see docs/STATUS.md)

1. **EST is unreachable by any real client.** `cmd/kryptkeeper/main.go` has
   no TLS listener anywhere; RFC 7030 mandates TLS, so `globalsign/est`
   (and every other compliant EST client) fails at the handshake:
   `tls: first record does not look like a TLS handshake`. Independently,
   `/.well-known/est/cacerts` (`internal/est/server.go` `handleCACerts`,
   comment "simplified: PEM") returns concatenated raw base64 DER certs, not
   a PKCS#7 degenerate SignedData structure per RFC 7030 §4.1 — `openssl
   pkcs7`/libest reject it.

2. **SCEP enrollment cannot work against an ECDSA CA.** Classic SCEP
   (RFC 8894) key-wraps the CSR to the CA's public key via PKCS#7
   `EnvelopedData`, which requires an RSA recipient certificate. Kryptkeeper's
   default root CA is ECDSA P-256, so `micromdm/scep` fails client-side
   before any bytes reach the wire: `pkcs7: only RSA keys are supported`.
   This is upstream of and independent from `internal/scep/server.go`'s
   `handlePKIOperation`, which also does not implement the real PKCS#7
   envelope/unwrap (comment: "simplified — production parses PKCS#7
   envelope") — even an RSA CA would still fail server-side.

3. **CMP `ir` is rejected by a real client.** `openssl cmp -cmd ir` places
   the requested public key in `CertTemplate.publicKey` with a
   `POPOSigningKey` proof-of-possession signature; it never embeds a PKCS#10
   CSR. `internal/cmp/asn1codec.go`'s `extractCSRFromCertReqMessages`
   (lines 97-133) only recognizes a CSR smuggled in the POPO signature field
   or raw bytes of `CertTemplate`, finds nothing, and
   `internal/cmp/server.go:76-79` returns 400 `missing certificate request`.
   Also confirmed by inspection: no RFC 4210 message protection (PBM or
   signature) or shared secret is ever checked — an anonymous request that
   *did* satisfy the CSR-extraction gap would be issued with zero
   authentication.

4. **Protocol-issued certs would never reach the inventory API even if
   issuance worked.** `cmd/kryptkeeper/main.go:519,525,533` wire
   `est.NewServer`/`scep.NewServer`/`cmp.NewServer` directly against the raw
   `ca.Service` (`caEngine`), bypassing `bootstrap.CertificateProvider`
   entirely. Only `caCertificateProvider.IssueCertificate`
   (`internal/bootstrap/certificate_ca_provider.go:313-420`) writes the
   `source` column `GET /api/v1/certificates` reads back.

5. **Fixed, small and safe (with unit tests), landed on this branch:**
   - `internal/scep/server.go` `handlePKIOperation`'s POST path used a single
     `r.Body.Read(buf)` with no loop, silently truncating any body delivered
     across more than one `Read` — replaced with `io.ReadAll` matching
     est/cmp's pattern (`internal/scep/server_test.go`
     `TestSCEPPKIOperationEnroll_SlowReaderNotTruncated`).
   - `internal/cmp/server.go`'s `handleCertRequest` mapped every non-IR
     request (including KUR) to `cp` (3) instead of `kup` (8) — a real
     `openssl cmp -cmd kur` rejects that as a transfer-error mismatch.
     Fixed via a `responseBodyType` helper
     (`internal/cmp/cmp_test.go` `TestCMPHandlerKURReturnsKUPBodyType`).
   These fixes do not make SCEP/CMP interoperate with real clients — they
   fix bugs found while probing a still-fundamentally-incompatible wire
   format, per the rule against loosening any verification path
   ([SECURITY_PRINCIPLES.md](../../../docs/design/SECURITY_PRINCIPLES.md)).

## What passed

OCSP and CRL are proven end-to-end with real `openssl ocsp`/`openssl crl`
against certs issued and revoked through the hub's own `/api/v1/certificates`
API (a working, already-proven surface, independent of EST/SCEP/CMP):
revoked leaf reports `Cert Status: revoked` with the correct reason and
revocation time (signature verified against the real CA cert, no
`-noverify`); a second, non-revoked leaf reports `good`; the CRL fetched from
`/crl/<ca id>.crl` verifies against the CA cert and lists exactly the revoked
leaf's serial. `GET /api/v1/certificates` correctly shows `source: "api"` for
both API-issued certs.
