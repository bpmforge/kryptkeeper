# CMVP status per release (W23-33, FR-P51)

Kryptkeeper is not itself a validated product. It builds against the Go
FIPS 140-3 Cryptographic Module; whether and how that module is validated is a
fact recorded here, per release, by a human reading the NIST CMVP site.

## 1. Claim text

Use this sentence verbatim in release notes, the README and sales material.
Never describe the product as validated.

> Kryptkeeper uses the Go FIPS 140-3 module (CMVP status: <status>).

Until section 2 is filled in, the status reads **not yet recorded**. As of v0.21 it reads:

> Kryptkeeper uses the Go FIPS 140-3 module (CMVP status: certificate #5247, Active).

The placeholder form, for a release whose module has not been looked up:

> Kryptkeeper uses the Go FIPS 140-3 module (CMVP status: not yet recorded).

## 2. Pinned module

| Field | Value |
|---|---|
| Build pin | `GOFIPS140=v1.0.0` (snapshot `v1.0.0-c2097c7c`, per `$(go env GOROOT)/lib/fips140/`) |
| Reported `module_version` | `v1.0.0` (`GET /api/v1/meta`, `.fips.module_version`) |
| Go toolchain | `go.mod` `toolchain` line, read at claim time (currently `go1.27.3`; the certificate follows the `GOFIPS140=v1.0.0` module pin, not the toolchain version, so the 1.26 to 1.27 bump does not change it) |
| CMVP certificate number | [#5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247) (vendor Geomys LLC, "Go Cryptographic Module", FIPS 140-3, overall level 1) |
| CMVP status | Active; sunset 2031-04-26 (validated 2026-04-27, updated 2026-07-07) |
| Date checked | 2026-10-17 (NIST CMVP certificate page) |
| Source | NIST CMVP module search, <https://csrc.nist.gov/projects/cryptographic-module-validation-program> |

The certificate number and status must be looked up on the NIST CMVP site by a
person at release time. Do not infer them from Go toolchain files, release
notes or memory. Leave `TBD` until that lookup is done.

Version mapping note (2026-10-17): the NIST certificate page for #5247 does not list a software
version. Geomys, the module's vendor, states that #5247 covers Go Cryptographic Module v1.0.0
(<https://buttondown.com/geomys-fips140/archive/go-and-fips-140-may-update/>, <https://go.dev/doc/security/fips140>),
which is the `GOFIPS140=v1.0.0` pin above. Module v1.26.0 (Go 1.26's default snapshot) is on the
Modules In Process list, not yet certificated, so the pin must stay `v1.0.0` for this claim.

## 3. Per-release log

| Release tag | Pinned `GOFIPS140` | CMVP cert / status | Date checked | Checked by |
|---|---|---|---|---|
| v0.11 | v1.0.0 | TBD | TBD | TBD |
| v0.21 | v1.0.0 | #5247 Active | 2026-10-17 | Claude (W33 thread), from the NIST page; version mapping below |

## 4. Release-notes checklist

1. Confirm the pin is unchanged in `Dockerfile.fips` and the `Makefile`
   (`GOFIPS140`), and update section 2 if it moved.
2. Look up the module on the NIST CMVP site and fill in section 2 and this
   release's row in section 3 (certificate number, status, date, who checked).
3. Paste the claim line from section 1 into
   `docs/release/RELEASE_NOTES_<tag>.md` under a "FIPS" heading, linking
   `docs/release/CMVP_STATUS.md`.
4. Run the wording audit (section 5) and attach its output to the release PR.
5. Confirm the `<version>-fips` image was published (`release.yml`, job
   `fips-image`) and that `make fips-smoke` passed for it.

## 5. Wording audit

```sh
grep -rIn -i "fips[ -]validated" README.md docs site --exclude-dir=sdlc --exclude-dir=board --exclude-dir=v1-vision
```

It must print only the line in `docs/design/FIPS_POSTURE.md` that says Vault
transit is not validated, and nothing else. `docs/sdlc`, `docs/board` and
`docs/v1-vision` are historical planning text and are excluded.
