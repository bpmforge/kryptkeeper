# SPIFFE / SVID Issuance

Kryptkeeper can mint short-lived **SVIDs** (X.509 certs whose SAN is a
`spiffe://trust-domain/workload` URI) and serve the trust bundle. v2.1 is a
REST mint + bundle; the gRPC SPIFFE Workload API + attestation are a follow-up.

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
