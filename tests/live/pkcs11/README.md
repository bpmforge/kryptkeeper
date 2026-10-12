# W19-08 — PKCS#11 UAT against SoftHSM2

Proves the `internal/keystore` PKCS#11/HSM backend (`-tags pkcs11`,
`github.com/ThalesGroup/crypto11` + `github.com/miekg/pkcs11`) against a REAL
SoftHSM2 token — not the mocked interfaces the code had only ever been
exercised against before. Private key custody is a security-sensitive path;
this closes the "never proven against a real token" gap.

## Run

```
bash tests/live/pkcs11/run.sh
```

Requires (macOS/Apple Silicon, native — option A from the ticket):

- `brew install softhsm opensc` (SoftHSM2 2.7.0, OpenSC/pkcs11-tool 0.27.1
  as of 2026-09-10/11)
- `go` with `CGO_ENABLED=1` (the hub is built with `-tags pkcs11`, which
  needs cgo)
- `openssl`, `python3`

Idempotent: initialises a fresh SoftHSM2 token into its own `mktemp` temp
dir every run via a per-run `SOFTHSM2_CONF` (never touches
`~/.config/softhsm2`), PASS/FAIL per step, non-zero exit on any FAIL, and
cleans up the hub process, the token directory, and all temp state on exit
via a trap (including on failure). No real key material is ever committed —
the token is destroyed with the temp dir at the end of every run.

## What it proves

1. The hub, built with `CGO_ENABLED=1 go build -tags pkcs11`, starts with
   `KRYPTKEEPER_KEY_BACKEND=pkcs11` pointed at a live SoftHSM2 token
   (selected by `KRYPTKEEPER_PKCS11_TOKEN_LABEL`, not slot number — see
   Findings).
2. `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true` creates a root CA whose key
   lives IN the token: `pkcs11-tool --list-objects --type privkey --login`
   shows a real private key object, and `GET /api/v1/cas` reports
   `key_storage_type: pkcs11` on the CA record (see Findings — this field
   did not previously exist).
3. A certificate issued from a CSR against that CA verifies with
   `openssl verify` against the CA cert (no `-noverify`/bypass).
4. OCSP (`openssl ocsp`) and CRL (`openssl crl`) both verify signatures
   produced by the HSM-resident key, and correctly report/list the
   revoked leaf.
5. A PQC/ML-DSA key request against the pkcs11 backend
   (`POST /api/v1/keys {"algorithm":"ML-DSA-44"}`) is refused (HTTP 503,
   no key created in the token) — consistent with
   `docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md`, though the refusal message does
   not cite the ADR (see Findings). Behaviour is asserted, not changed,
   per the ticket instruction.
6. Key deletion via `DELETE /api/v1/keys/{id}` removes the corresponding
   token object (`pkcs11-tool`'s private-key object count drops by one).
   Deliberately exercised on a disposable key generated for this step,
   not the CA's own signing key (see Findings).

## Findings (this run, 2026-09-11)

Two hub defects were found and fixed on this branch (both proven against
this real token, not by inspection alone — the "before" state was
reproduced and the fix verified to flip it):

- **PKCS#11 backend could never open any token at all.**
  `internal/keystore/pkcs11.go`'s `NewPKCS11StoreFromEnv` always set both
  `crypto11.Config.SlotNumber` (defaulting to `0`) and `TokenLabel`, but
  `crypto11.Configure` requires *exactly one* token selector and hard-errors
  otherwise (verified against the vendored source,
  `$GOMODCACHE/github.com/!thales!group/crypto11@v1.6.1/crypto11.go`).
  Confirmed empirically: the existing `TestPKCS11Store_*` tests failed with
  `config must specify exactly one way to select a token: slot number,
  token label given` against a real SoftHSM2 token before the fix, and pass
  after it. The "default slot 0" fallback was independently wrong too:
  `softhsm2-util --init-token` reassigns an initialized token to a fresh,
  non-zero slot ID every time — never slot 0. Fixed to select by
  `TokenLabel` alone unless `KRYPTKEEPER_PKCS11_SLOT` is explicitly set.
  See `internal/keystore/pkcs11.go`, `internal/keystore/pkcs11_test.go`
  (new regression test `TestPKCS11Store_TokenLabelOnly_OpensWithoutSlot`).

- **`CA.KeyStorageType` was hardcoded `"software"` everywhere, and the ADR's
  PQC-on-hardware refusal was dead code.** `internal/ca/store_db.go`'s
  `Save()` wrote the literal `"software"` into the DB regardless of which
  keystore backend generated the key, `scanCA()` didn't even select the
  column back, and `internal/bootstrap/ca_engine_provider.go`'s
  `caToListItem` also hardcoded `"software"` in the API response — an
  HSM-held CA key was misreported as software custody by both the
  persistence layer and the API. Separately,
  `keystore.CheckHSMPQCSupport` (the ADR's refusal gate) was defined and
  unit-tested in isolation but never called from any CA-creation path.
  Fixed: `ca.CA.KeyStorageType` field, `Engine.SetKeyBackend` (wired from
  `main.go`'s existing `keyBackend` variable), both `CreateRootCA` and
  `CreateIntermediateCA` now call `CheckHSMPQCSupport` before key
  generation. See `internal/ca/ca.go`, `internal/ca/engine.go`,
  `internal/ca/store_db.go`, `internal/bootstrap/ca_engine_provider.go`,
  `cmd/kryptkeeper/main.go`, and their `_test.go` files.

One gap found but **not** fixed, per the ticket's "assert the documented
behaviour, do not change it" instruction for step 5:

- `POST /api/v1/keys` (`internal/bootstrap/handlers_keys.go`) calls
  `store.GenerateKey` directly and never calls
  `keystore.CheckHSMPQCSupport`. The refusal that does happen comes from
  `PKCS11Store.GenerateKey`'s own `default:` case (an
  algorithm-not-supported error, not the ADR-specific
  `ErrPQCHSMUnsupported` message) — so the key is correctly never created
  in the HSM, but the caller doesn't see the ADR's reasoning. A future
  ticket should wire `CheckHSMPQCSupport` into this handler for message
  parity with the CA-creation path fixed above.

A related, unfixed gap noticed while building step 6 (deletion): `DELETE
/api/v1/keys/{id}` has no CA-in-use guard, unlike `POST
/api/v1/keys/{id}/rotate` (`internal/bootstrap/handlers_keys.go`, the
`ca.KeyInUseByCA` check). Deleting a CA's live signing key via the raw key
API would silently break that CA. Not exercised or fixed here — the
fixture uses a disposable key for the deletion step precisely to avoid
this. Worth its own ticket.
