# SPIFFE / SVID Issuance

Kryptkeeper is a SPIFFE-compatible X.509-SVID issuer with UID-selector
attestation. It is **not a SPIRE server**: no node attestation, no
SPIRE-compatible registration API, no federation. It mints short-lived
**SVIDs** (X.509 certs whose SAN is a `spiffe://trust-domain/workload` URI),
serves the trust bundle, and serves the SPIFFE Workload API on a Unix socket.

## Enable

Requires the CA engine (not the file provider). Set:

```
SPIFFE_TRUST_DOMAIN=example.org      # your trust domain
SPIFFE_SIGNING_CA_ID=<ca-id>         # which CA signs SVIDs
SPIFFE_SVID_TTL=1h                   # SVID validity (default 1h)
```

Best practice: dedicate a SPIFFE **intermediate** CA for SVID signing rather
than your root.

## Mint an SVID

`POST /api/v1/spiffe/svid` (admin/operator role):

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"spiffe_id":"spiffe://example.org/ns/prod/sa/checkout"}' \
  https://kryptkeeper.example.com/api/v1/spiffe/svid
```

Returns `svid_pem`, `key_pem` (the workload's freshly-generated key),
`bundle_pem` (the signing chain), and `expires_at`. The trust domain in the
SPIFFE ID must match `SPIFFE_TRUST_DOMAIN`, or the request is rejected.

## Trust bundle

`GET /api/v1/spiffe/bundle` returns the trust domain's CA chain as PEM, for
peers/clients to verify SVIDs.

## Workload API (Unix socket)

Set `SPIFFE_WORKLOAD_SOCKET=/run/kryptkeeper/workload.sock` to start the
listener (unset means it is off). Workloads are attested by the kernel peer
UID of the socket connection, so bind a UID to an identity first (approver
role required; the ID must be inside `SPIFFE_TRUST_DOMAIN`):

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"uid":1001,"spiffe_id":"spiffe://example.org/ns/prod/sa/checkout"}' \
  https://kryptkeeper.example.com/api/v1/spiffe/workload-selectors
```

The served call is `FetchX509SVID` only. Clients must send the
`workload.spiffe.io: true` header (go-spiffe does). A UID with no binding gets
gRPC `PermissionDenied`. The stream stays open and the hub re-pushes a fresh
SVID at 50% of its lifetime, so a go-spiffe `X509Source` rotates with no
restart. All of this is exercised against a real hub by `tests/live/spiffe`.

## TTL

Workload entries (join tokens) default to 24 h and cap at 7 d. The SVID
lifetime itself is `SPIFFE_SVID_TTL` (default 1h).

## Attestation limits

- Attestation is UID-selector via kernel peer credentials, nothing else.
- **Shared-UID limitation:** two workloads under one UID, or sharing one pid
  namespace (containers on one host), are indistinguishable and receive the
  same SPIFFE ID (`TestSharedUIDWorkloadsGetSameSPIFFEID`). Run one UID per
  workload.
- Kubernetes PSAT, AWS instance-identity and TPM attestors are **v1.x, not
  shipped**.

## SVID types

X.509-SVID only. There is **no JWT-SVID**: no `FetchJWTSVID` or
`FetchJWTBundles`.

## Using Kryptkeeper with SPIRE

Kryptkeeper can be the *upstream* authority for a SPIRE deployment: export a
CA from Kryptkeeper and point SPIRE's `UpstreamAuthority "disk"` plugin at
it. SPIRE then issues the SVIDs and Kryptkeeper never sees the workloads.
Kryptkeeper ships no SPIRE plugin; this is the manual disk-plugin boundary.
Running both issuers under one trust domain is unsupported.

## Join-token path (non-human identities)

`POST /api/v1/spiffe/workload-svid` redeems a single-use join token for an
SVID; tokens come from the NHI flow (propose, approve by a different person,
redeem). Revoking an NHI burns its unredeemed token and the live NHI
authorizer refuses it immediately, but an SVID already issued stays
cryptographically valid until it expires (up to 7 d) until CRL/OCSP linkage
ships. The authorizer is built but not yet wired to a request path (D-150), so
treat expiry, not revocation, as the bound on an issued SVID today.

## Monitoring

UI page `/spiffe` shows entries and bindings. Audit actions:
`spiffe.workload_entry_create`, `spiffe.selector_bind`,
`spiffe.workload_attest`.
