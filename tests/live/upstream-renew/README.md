# W27-10 live upstream-renewal UAT

Proves the SCEP, EST, WSTEP and DigiCert upstream clients (and, for SCEP and
EST, the hub's connector wiring from W27-35) against servers that are NOT
Kryptkeeper's own `internal/scep`, `internal/est` or `internal/wstep`.

```
bash tests/live/upstream-renew/run.sh        # about 3 to 6 minutes, podman only
```

## What `run.sh` does

1. Builds two independent servers, each from a pinned upstream tag inside a
   container (`servers/`): `micromdm/scep` `scepserver` v2.3.0 (SCEP, RFC 8894,
   `go install` of the tag on a digest-pinned `golang` image) and Cisco
   `libest` r3.2.0 `estserver` (EST, RFC 7030, commit
   `4ca02c6d7540f2b1bcea278a4fbe373daac7103b`, digest-pinned `ubuntu:20.04`,
   built `-fsigned-char`: its option loop keeps `getopt`'s return in a plain
   `char`, unsigned on arm64). Base images are pinned by index digest in the
   Containerfiles. The EST server's CA is libest's demo CA generated at start; its
   client credential `estuser` / `estpwd` is libest's own documented example
   credential for its test server.
2. Checks the servers speak the protocol with plain curl/openssl (GetCACaps,
   GetCACert, EST `/cacerts` PKCS#7, unauthenticated `simpleenroll` -> 401).
3. Leg 1, connector level: `go test ./tests/live/upstream-renew/` with
   `KK_LIVE_UPSTREAM=1` drives the clients directly, serves the issued leaf
   over TLS and compares fingerprints, and checks the chain to the server's CA.
4. Leg 2, hub level: a hub container creates `scep` and `est` connectors with
   `POST /api/v1/connectors`, imports a certificate, takes it over onto the
   connector (`POST /estate/takeover`), runs `POST /renewal/execute` into an
   nginx over SSH, and compares the SERVED fingerprint with `new_fingerprint`.
   The EST password must appear 0 times in the hub log and the audit trail.

## Env for the go test (all optional; a leg with a missing variable is `NOT RUN`)

| Variable | Leg |
|---|---|
| `KK_LIVE_UPSTREAM=1` | gate for every leg except the 429 test (which needs no account and always runs) |
| `KK_UP_SCEP_URL`, `KK_UP_SCEP_CA_FILE` | SCEP |
| `KK_UP_EST_URL`, `KK_UP_EST_CA_FILE`, `KK_UP_EST_USER`, `KK_UP_EST_PASSWORD_FILE` | EST |
| `KK_UP_WSTEP_URL`, `KK_UP_WSTEP_USER`, `KK_UP_WSTEP_PASSWORD_FILE`, `KK_UP_WSTEP_TEMPLATE` | WSTEP (needs an AD CS lab, see `tests/live/wstep/README.md`) |
| `KK_UP_DIGICERT_KEY_FILE`, `KK_UP_DIGICERT_ORG_ID`, `KK_UP_DIGICERT_BASE_URL` | DigiCert CertCentral sandbox |

Passwords and keys are read from files, never argv, and every logged line is
checked against them. `KK_EVIDENCE_DIR` makes `run.sh` copy the go test output,
hub log and audit dump there.

## Not covered

WSTEP and DigiCert issuance are `NOT RUN` without a lab/sandbox. DigiCert's 429
is covered with a local stub (a real 429 cannot be forced on demand). At the
hub API level a 429 is only handled by the scheduler (deferred with backoff);
`POST /renewal/execute` answers a generic 503 for it (see the results doc).
