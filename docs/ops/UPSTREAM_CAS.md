# Using your existing CA: external CAs and upstream connectors

Kryptkeeper does not make you replace your CA. An **external CA** sends every
issuance request through a CA you already run or buy from: HashiCorp Vault PKI,
EJBCA, AWS Private CA, Google Cloud CAS, Sectigo, GlobalSign, Entrust, DigiCert or any
ACME CA. Kryptkeeper still applies its own front doors (ACME, EST, SCEP, CMP,
Windows autoenrollment, the REST API, cert-manager and Terraform), template policy,
approvals, inventory, renewal and revocation (W36, D-304..D-308).

Setup has two steps:

1. Add an **issuer connector**, which records how to reach and authenticate to the CA.
2. Create an **external CA** bound to that connector. Templates, ACME directories,
   EST labels and other front doors then use it like any other CA id.

The dashboard does both from **Issuers → Add issuer**. The API calls are below.

## 1. What can sit behind what

| Upstream type | REST, cert-manager, Terraform | ACME, EST, CMP | SCEP, Windows (WSTEP) | Renewal of hub-generated keys |
|---|---|---|---|---|
| `vault_pki`, `ejbca`, `aws_pca`, `gcp_cas`, `sectigo`, `globalsign`, `entrust`, `digicert` | yes | yes | yes | yes |
| `acme` (a public or private ACME CA) | yes | yes | yes | yes |
| `est` | yes | yes | yes | yes |
| `scep`, `wstep` | renewal only | renewal only | renewal only | yes |

An upstream SCEP or WSTEP request has to be signed with the requester's private key, and the hub
holds that key only for keys it generated. So an external CA cannot be bound to a
`scep` or `wstep` connector, and the refusal says so. ML-DSA and hybrid
requests are refused for external CAs because no supported upstream accepts them.

## 2. What Kryptkeeper checks on every certificate the CA returns

Before a certificate from an upstream is stored or handed to anyone, the hub
verifies all of the following:

- its public key is the key in the request;
- it is not a CA certificate and cannot sign certificates or CRLs;
- every DNS name, IP address and URI in it was requested (and, for Windows
  autoenrollment, the subject matches the authenticated machine);
- it carries no code-signing, email, timestamping, OCSP or IPsec usage unless
  the template asked for it (serverAuth and clientAuth may be added by the CA);
- it is valid for no longer than the template allows, plus one day for rounding;
- it chains to the **trust bundle** you gave when you created the external CA.

Any failure discards the certificate, fails the request with the reason, and
writes `certificate.issue.upstream_rejected` to the audit log. The trust
bundle can hold the CA's root (intermediates may then rotate) or the issuing
intermediate (pinned).

## 3. Revocation

Revoking a certificate that came through a connector revokes it **at the
upstream CA first**:

| Upstream answer | Result |
|---|---|
| accepted | marked revoked, `revocation_scope: upstream` |
| refused or unreachable | **not** marked revoked; HTTP 502 `upstream_revoke_failed`; audit `certificate.revoke.upstream_failed` |
| connector cannot revoke (EST) | HTTP 409 `upstream_revoke_unsupported` |

An admin can still record a revocation in Kryptkeeper only, after revoking it at the CA by
hand, with `POST /api/v1/certificates/{fingerprint}/revoke?scope=inventory_only`.
The hub publishes no CRL or OCSP for external CAs: `/crl/{id}` and OCSP answer
404 `external_ca`, and relying parties use the CA's own endpoints.

## 4. Connector settings

Secrets never go in `config_json`. Any `api_key`, `password`, `secret` or `token`
key in it is refused. Secrets live in an outbound credential (`POST
/api/v1/credentials`), which is encrypted at rest and never returned. The connector names it in
`credential_ref`. Client certificates for mutual TLS are presented through the
hub's egress policy (`docs/ops/EGRESS.md`).

| Type | `config_json` (non-secret) | Credential payload |
|---|---|---|
| `vault_pki` | `base_url`, `role`, `mount` (default `pki`), `namespace`, `ttl`, `approle_mount` (default `approle`), `ca_cert_pem` | `{"token"}` or `{"role_id","secret_id"}` |
| `ejbca` | `base_url`, `certificate_profile_name`, `end_entity_profile_name`, `certificate_authority_name`, `username_prefix` (default `kk-`), `ca_cert_pem` | `{"client_cert_pem","client_key_pem"}` |
| `aws_pca` | `certificate_authority_arn`, `region`, `signing_algorithm` (default: the CA's own), `validity_days` (default 90), `template_arn`, `endpoint_url`, `auth` (`static` or `ambient`) | `{"access_key_id","secret_access_key","session_token"}`; none for `ambient` |
| `gcp_cas` | `project`, `location`, `ca_pool`, `certificate_authority_id`, `certificate_template`, `lifetime_days` (default 90), `auth` (`service_account` or `ambient`) | `{"service_account_json"}`; none for `ambient` |
| `sectigo` | `base_url` (default `https://cert-manager.com`), `customer_uri`, `org_id`, `cert_type`, `term_days` | `{"login","password"}` or `{"login","client_cert_pem","client_key_pem"}` |
| `globalsign` | `base_url` (default Atlas EMEA), `validity_days` (default 90), `ca_cert_pem` | `{"api_key","api_secret","client_cert_pem","client_key_pem"}` |
| `entrust` | `base_url` (default `https://api.entrust.net/enterprise/v2`), `client_id`, `cert_type`, `validity_days` or `cert_lifetime`, `requester_name`, `requester_email`, `requester_phone` | `{"username","api_key","client_cert_pem","client_key_pem"}` |
| `digicert` | `organization_id`, `product_name_id`, `validity_years`, `base_url` | `{"api_key"}` |
| `acme` | see `ACME_UPSTREAM.md` | see `ACME_UPSTREAM.md` |

Each vendor-specific behaviour is documented in its connector source, with a link to
the vendor reference it was checked against. Notable points:

- **GlobalSign Atlas** takes the public key, subject and names rather than a CSR. Kryptkeeper copies them from the
  request.
- **Entrust** ignores the CSR's names when names are sent separately. Kryptkeeper
  sends the CSR's names.
- **Sectigo** and **Entrust** pending orders are polled within a fixed budget. A
  certificate that needs manual validation at the CA fails with the order id so it
  can be approved in the CA's portal.

## 5. API walkthrough

```bash
# 1. secret
curl -X POST $HUB/api/v1/credentials -d '{"name":"vault-token","credential_type":"api_token","payload":{"token":"..."}}'
# 2. connector
curl -X POST $HUB/api/v1/connectors -d '{"name":"Vault PKI","type":"vault_pki",
  "config_json":"{\"base_url\":\"https://vault.internal:8200\",\"role\":\"web\"}","credential_ref":"<credential id>"}'
# 3. test it
curl -X POST $HUB/api/v1/connectors/<connector id>/test
# 4. external CA (trust bundle = the Vault root or issuing CA)
curl -X POST $HUB/api/v1/cas/external -d '{"name":"Vault web CA","connector_id":"<connector id>","trust_pem":"-----BEGIN CERTIFICATE-----..."}'
```

Then point a template, ACME directory or EST label at the new CA id.

## 6. Multi-tenancy

With `MULTI_TENANCY=on`, an external CA, its connector and the connector's
credential must belong to the same tenant. Only a global admin may use a
default-tenant credential. A cross-tenant binding is refused when the external CA
is created and checked again on every issuance (D-308).

## 7. Proof status

Vault PKI and EJBCA are proven against real containers
(`tests/live/upstream-cas`, `docs/release/LIVE_RESULTS_UPSTREAM_CAS_v1.1.md`). The
other types are tested against recorded vendor API responses and are listed on the
roadmap under "Proven against real partner systems" until they have run against
the real service.
