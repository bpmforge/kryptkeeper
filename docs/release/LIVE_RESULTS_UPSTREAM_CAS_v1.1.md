# Live results: upstream CAs (W36-16), v1.1

Date: 2026-10-25. Harness: `tests/live/upstream-cas/run.sh` (one run, scenarios A, B and C).
Hub commit under test: `132dc8e0` (the wiring fix below on top of `4a25bee8`). Host: macOS, podman 6.1.3 (arm64).
Result: **47 PASS, 0 FAIL, 0 skipped** on the final run.

## Images

| Role | Image | Tag |
|---|---|---|
| Vault | `docker.io/hashicorp/vault` | 1.18.5 (Vault v1.18.5) |
| ACME client | `docker.io/goacme/lego` | v4.21.0 |
| EJBCA | `docker.io/keyfactor/ejbca-ce` | 9.3.7 |
| moto | `docker.io/motoserver/moto` | 5.0.28 |
| tamper proxy, boto3 | `docker.io/library/python` | 3.12-alpine |
| EJBCA REST probe | `docker.io/curlimages/curl` | 8.10.1 |

## First run found two product bugs (fixed in `132dc8e0`)

The first scenario A run failed in two places, both in W36 wiring:

1. **Revoke through the hub answered 409 `upstream_revoke_unsupported` for a Vault certificate.**
   `caCertificateProvider.SetUpstreamRevoker` was never called in production, so the hub never had
   an upstream revoker and every external-CA certificate looked unrevocable upstream.
2. **A tampered upstream response left no `certificate.issue.upstream_rejected` audit row.**
   `Engine.SetExternalRejectionObserver` was never called either.

Fix: `internal/bootstrap/external_ca_wiring.go` (`wireExternalCA`, called from `handlers.go` where
`SetExternalIssuer` was) plus `engineCAProvider.SetExternalRejectionObserver`, with a unit test.
No verification check was changed. `go test ./...`: 86 packages ok. `golangci-lint` on `internal/bootstrap`: 0 issues.

## Scenario A: HashiCorp Vault PKI (dev server, TLS)

| Step | Result | Evidence |
|---|---|---|
| Vault up, pki mount, internal root, role `uat` for `uat.example` and subdomains | PASS | root `CN=UAT Vault PKI Root` |
| outbound credential `{token}`, `vault_pki` connector, `POST /connectors/{id}/test` | PASS | `200 {"status":"healthy"}` |
| `POST /cas/external` with the Vault root as `trust_pem` | PASS | 202 (dual control), bob approves, alice redeems, 201 |
| Issue by REST `POST /api/v1/certificates` | PASS | 201, serial `1F214A6D3F33D846B6A5AA315217CCF5CC52B131`, issuer `CN=UAT Vault PKI Root`, `openssl verify -CAfile vaultroot` OK |
| Issue by ACME (lego, http-01, provisioner `vaultca` bound to the external CA) | PASS | serial `719ECBFB19522AEDECFB7037A31EAF328EDA4340`, issuer Vault root, verify OK |
| Issue by EST simpleenroll (`KRYPTKEEPER_DEFAULT_CA_ID` = external CA) | PASS | 200, serial `524291F5056601F41072CE9C318B50A6164CC4D9`, issuer Vault root, verify OK |
| Revoke through the hub | PASS | 200 `revocation_scope=upstream`; Vault `pki/cert/1f:21:...:b1:31` `revocation_time=1792893555` |
| Tamper (a): proxy swaps the CSR for one with another key | PASS | refused, no certificate stored |
| Tamper (b): proxy adds an extra SAN | PASS | refused; audit reason `DNS name "extra-san.uat.example" was not requested` |
| Audit for both tampers | PASS | two `certificate.issue.upstream_rejected` rows with ca, connector, fingerprint and reason |
| Vault stopped, revoke another certificate | PASS | 502 `upstream_revoke_failed`; certificate still has `revoked_at=None`, no scope |
| Audit for the failed revoke | PASS | `certificate.revoke.upstream_failed` present |

Tamper was done with a Python HTTPS proxy in front of Vault (Vault cannot be made to add a SAN),
as the ticket allowed. The proxy replaces the `csr` in the `pki/sign` request, so Vault signs
a certificate for a key or name the hub did not ask for.

## Scenario B: EJBCA Community 9.3.7

| Step | Result | Evidence |
|---|---|---|
| EJBCA up, REST enabled, REST client certificate in the Super Administrator Role | PASS | healthy after about 75 s |
| REST client-certificate auth | PASS | `GET /v1/certificate/status` 200 with the client certificate |
| credential `{client_cert_pem, client_key_pem}`, `ejbca` connector, `/test`, external CA | PASS | `200 {"status":"healthy"}` |
| Issue by REST | PASS | serial `73B6ABB5EF5240E3A960C63BC6CEA7C7D205C433`, issuer `CN=UAT EJBCA Short Root`, SAN `ej1.uat.example`, verify OK |
| Revoke through the hub | PASS | 200 `revocation_scope=upstream`; EJBCA `revocationstatus`: `"revoked":true`, reason `KEY_COMPROMISE`, date `2026-10-25T02:01:04Z` |
| EJBCA stopped, revoke another certificate | PASS | 502 `upstream_revoke_failed`; not revoked in the hub |

Not run for EJBCA: ACME, EST and the tamper proxy (A covers those paths; they do not depend on the connector type).

What it took to get REST auth working, in case you repeat it:

- EJBCA's container "simple" TLS mode starts with an **empty** server truststore, so Wildfly resets any
  connection that presents a client certificate (TLS handshake completes, then the connection is
  reset). The harness imports ManagementCA into `truststore.jks` with `keytool` and runs
  `jboss-cli.sh --connect --command=reload`. The H2 database survives that soft reload.
- The REST end entity is created with `ejbca.sh ra addendentity`, `ra setclearpwd`, `batch` (PEM output)
  and `roles addrolemember` in the Super Administrator Role.
- The hostname variable is `HTTPSERVER_HOSTNAME` (one S); `HTTPSSERVER_HOSTNAME` is ignored and the TLS
  certificate then has the container id as its name.
- EJBCA's SERVER profile issues 2-year certificates, which the hub rightly refuses against its 397-day
  cap. The harness creates a 300-day CA (`ejbca.sh ca init -v 300`), because a CA caps what it issues
  at its own lifetime. No hub check was loosened.

## Scenario C: AWS Private CA via moto 5.0.28

moto implements the acm-pca `issue_certificate`, `get_certificate` and `revoke_certificate`
handlers, so the scenario ran rather than being recorded as fixture-only.

| Step | Result | Evidence |
|---|---|---|
| moto (TLS) up, ROOT CA created and its own CSR signed and imported | PASS | `arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/...` |
| credential, `aws_pca` connector with `endpoint_url`, `/test`, external CA | PASS | `200 {"status":"healthy"}` |
| Issue by REST | PASS | serial `10D8DB4CFC26534EA2DADFF6120FBC60B770B419`, issuer `CN=UAT moto PCA Root`, verify OK |
| Revoke through the hub | PASS (hub side only) | 200 `revocation_scope=upstream`. moto's `revoke_certificate` is documented as a no-op, so moto's state cannot confirm the revocation |

Limits of this scenario: moto ignores `Validity` and `SigningAlgorithm`, so it proves the request
shape, SigV4 signing, TLS to a custom `endpoint_url` and response parsing, not real AWS behaviour.
The hub trusts the fixture CA as its system roots (`SSL_CERT_FILE`) because the connector has no
`ca_cert_pem` setting.

## Observations (not fixed)

- A refused or failed upstream issuance returns the generic `503 service_unavailable "certificate unavailable"`
  to the caller, including for `certificate.issue.upstream_rejected`. The reason is in the audit row only.
  A 502 with the reason would be more useful; this is in `handlers_certificates.go`, outside the W36 file list, so left for a ticket.
- `tests/live/lib/podman.sh kk_wait_dns` uses `nslookup`, which fails on busybox on this podman 6 stack
  although the name resolves (`getent` works). The harness uses its own `wait_name`.
- Not covered here: GCP CAS, Sectigo, GlobalSign, Entrust and DigiCert stay on recorded vendor responses.
  SCEP and WSTEP external CAs are refused by design (D-305).
