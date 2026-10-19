# W23-06 — air-gap offline-root quickstart

```
bash tests/live/ca-offline-root/run.sh      # HUB_PORT=8097 OPENSSL_BIN=openssl BUDGET_SECONDS=1800
```

Builds the hub, starts it on loopback with no CA, then walks UC-A02: OpenSSL root
generated in `offline/` (key never leaves it) -> `POST /cas/import` under dual control
(alice proposes, alice and the bootstrap token are refused as approvers, bob approves)
-> issuing-CA CSR -> offline `openssl x509 -req` signing -> `POST /cas/{id}/certificate`
-> first leaf -> `openssl verify` against the offline root. Writes `last-run.json`.

## Proves
- `key-custody` lists 0 keys before import and exactly 1 (the issuing CA's) afterwards; the root never appears.
- Issuance from the keyless root is refused (422), the import needs a second human, the
  root cannot be deleted while a child CA is active.
- Machine time for the whole flow (clock starts before the hub build, so a cold Go cache counts).

## Does NOT prove
- Operator time: moving the CSR and certificate across the air gap by hand is extra.
- TLS: the hub runs plain HTTP on 127.0.0.1 here; TLS and the compose stack are covered by other harnesses.
- A real air-gapped host. The "offline host" is a separate temp directory on the same machine.
- Boot with no CA needs `KRYPTKEEPER_DEFAULT_CA_ID=<anything>` (the id need not exist);
  otherwise the hub refuses to start, and `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true` would put a hub-held key in custody.
