# W23-14 (Vault leg) — transit against a real Vault dev server

```
CONTAINER_ENGINE=docker bash tests/live/vault/run.sh   # podman is the default
```

Starts `hashicorp/vault:1.17` in dev mode (`-dev-root-token-id=kk-uat`, a
throwaway token), enables `transit`, and runs the real `VaultStore` for
ECDSA P-256/P-384, RSA-2048 and Ed25519: create, duplicate -> `ErrKeyExists`,
sign, verify against `PublicKey`, tamper check, delete, then `ErrKeyNotFound`.
Exit 0 only if `go test` passes and nothing was skipped.

## Proven
The real transit wire format: key create/read/rotate JSON, PEM public keys for
ECDSA/RSA, base64 raw public key for Ed25519, `vault:v1:` signatures (ASN.1 for
ECDSA by default), prehashed ECDSA/RSA signing, raw-message Ed25519 signing,
`deletion_allowed` gating, and idempotent key creation.

## Not proven
Auth policies and least-privilege tokens, AppRole login, namespaces (Enterprise),
TLS/`VAULT_CACERT`, HA/replication, auto-unseal, audit devices, a production
seal. Dev mode is in-memory and unsealed.
