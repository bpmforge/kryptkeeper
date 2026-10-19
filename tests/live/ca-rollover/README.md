# W23-19 — live CA rollover (cross-sign) with a running ACME client

```
bash tests/live/ca-rollover/run.sh      # podman only; builds the hub for the machine's arch
```

Built on `tests/live/acme/` (read its README for the podman-network topology). A hub with its
self-issued TLS listener issues through lego; the bootstrap root CA is then rolled with
`POST /api/v1/cas/{id}/rotate-key?mode=cross-sign` while a bounded lego renew loop (12 forced
renewals, 5 s apart) is running.

## Checks (each is a PASS/FAIL line)
- `old+new anchor verify`: the post-rotation leaf verifies against the new anchor, and against the
  OLD anchor through the cross-signed bridge (`-CAfile old.pem -untrusted cross.pem`).
- `pre-rotation leaf still verifies` against the old anchor.
- `0 failed ACME renewals across rollover`: the loop's fail log is empty, and at least one
  certificate was issued after the rollover started; the client's latest certificate chains to the new anchor.
- `OCSP verified against new key within 60s` and `CRL verified against new key within 60s`
  (OCSP via openssl in an alpine helper on the podman network, CRL via `openssl crl -CAfile ca-new.pem`),
  with an assertion that both finished within 60 s of the rotate call.
- `OCSP for pre-rotation leaf, request naming the OLD issuer key`: a relying party that still holds the old
  anchor asks OCSP about a pre-rotation leaf. The responder recognises the retired issuer by key hash and signs
  with the OLD key, so the response verifies against the old anchor (W23-19 fix; the old certificate is stored in
  `ca_key_rotations.old_cert_pem`, migration 000129). After the retired key is destroyed (`RetireRotatedKeys`,
  90-day grace) the same request is answered `unauthorized` by design; this harness does not cover retirement.

## Run record
- 2026-10-15/16, branch `kk/w23-o1`, podman, postgres 16: `=== RESULT: 26 passed, 0 failed ===`
  (the OLD-issuer OCSP check was the one failing check before the fix: `unauthorized (6)`; OCSP and CRL checks
  finished 8 s after rollover; 12 renewals, 0 failed, 11 issued after the rollover started).

## Decisions and limits
- Dual control is off (`KRYPTKEEPER_KEY_DUAL_CONTROL=false`) because a bash harness has no second human
  principal; the 202/approval path is covered by the W23-15 Go tests. The script prints a NOTE saying so.
- The bootstrap root is the rotated CA. The hub's TLS listener chain is unaffected because lego trusts the
  exported listener CA, not the rotated CA, so the loop surviving the rollover also proves that.
- Does not cover: intermediate CA rollover, RSA/ML-DSA rollover, rollback, or retirement of the old key.
