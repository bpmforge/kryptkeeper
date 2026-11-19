# Live results: AWS's own emulator (AWS Emulator), v1.2

Date: 2026-11-18. Commit under test: `28519724` (branch `kk/aws-emulator-legs`).
Emulator: **aws-emulator Version 1.0.512, release date 2026.11.18, commit
`1591f1d9df5fd60ebca7d7483d8a2951176db352`** (Debian package, amd64), started by
`tests/live/lib/aws-emulator.sh` with `--telemetry off`, SigV4 on (its per-run keys), its
per-run CA trusted through `AWS_CA_BUNDLE`, and a 2 GiB cap.
Comparison emulator: moto (`docker.io/motoserver/moto:latest`, moto 5.2.6.dev; 5.0.28 for
upstream-cas). Host: Linux x86_64, podman 5.7.0, Go 1.27.4.

**Everything on this page ran against emulators, not real AWS.** "Proven" here means proven
against AWS's emulator. IAM, key policies, quotas and HSM tiers are not emulated.

Reproduce: `KK_AWS_EMULATOR=aws bash tests/live/<harness>/run.sh` (upstream-cas:
`KK_AWS_EMULATOR=aws KK_SCENARIOS=C`). Without the variable each harness runs on moto as
before. If `aws-emulator` is not installed the AWS leg prints a named SKIP and exits 0
(checked: `SKIP: aws-emulator not installed (...)`, exit 0).

## Per-leg results

Go harnesses count tests and subtests. Shell harnesses count steps.

| Harness | moto | AWS's emulator |
|---|---|---|
| tests/live/kms-aws | PASS (6 pass) | PASS (6 pass) |
| tests/live/escrow-byok | PASS (9 pass; BYOK PARTIAL, as before) | PASS (9 pass; BYOK "PASS, public key byte-identical") |
| tests/live/key-inventory | PASS (4 pass, 4 named skips) | PASS (6 pass, 5 named skips) |
| tests/live/cloud-inventory | PASS (27 pass, 4 named skips) | PASS (26 pass, 3 named skips) |
| tests/live/upstream-cas | FAIL: 35 pass, 1 fail. Scenarios A and C pass; B stops at the EJBCA truststore import (see "Not caused by this change") | PASS, scenario C only (14 pass, 1 named skip: the known SHA384WITHECDSA bug) |
| tests/live/delivery-cloud (aws-sm, aws-alb, aws-cloudfront) | not run: no emulator leg | not added: the plugins cannot take an endpoint (below) |
| tests/live/acme-dns-providers (route53) | not run: no emulator leg | not added: the connector cannot take an endpoint (below) |

## What the AWS emulator legs prove (against the emulator, not real AWS)

- **KMS signing and deletion** (kms-aws): ECDSA P-256 and P-384, RSA-2048 and RSA-3072 through
  `CloudKMSStore`. `MessageType=DIGEST` signatures verify over the digest itself, and a tampered
  digest fails. `Delete` schedules deletion by ARN and the signer is gone afterwards.
  PendingDeletion has the 7-day window, and the product cancel returns the key to Enabled.
- **BYOK import** (escrow-byok): GetParametersForImport, the `RSA_AES_KEY_WRAP_SHA_256` wrap and
  ImportKeyMaterial all succeed. The key goes from PendingImport to Enabled. GetPublicKey after
  import is **byte-identical** to the escrowed key.
- **Key inventory** (key-inventory): an `ML_DSA_65` KMS key is listed with `SIGN_VERIFY` and
  `pqc_readiness=quantum_safe`. 450 keys are listed across five 100-key ListKeys pages.
- **Cloud certificate inventory** (cloud-inventory):
  - `dns_names` comes from `SubjectAlternativeNameSummaries`.
  - ECDSA certificates are listed at all.
  - A pending DNS-validated request is listed as `PENDING_VALIDATION`.
  - 1,106 certificates span two ListCertificates pages and give `certificates=1106` with 200
    persisted items.
  - A bad profile scope gives `completed_with_errors` and names the scope.
  - An unreachable endpoint gives a readable failure that does not contain the access key id.
- **AWS Private CA** (upstream-cas C):
  - Setup: an EC P-256 root with a CRL to S3. The connector `/test` reports `healthy`.
  - Issue: issuance by REST through the hub with `signing_algorithm=SHA256WITHECDSA` and
    `validity_days=29`. The issuer is the emulator root and `openssl verify` passes. The leaf
    signature is `ecdsa-with-SHA256`. notAfter = issue time + 29 days (drift 0 s).
  - Revoke: the hub reports `revocation_scope=upstream`. The emulator's own audit report lists
    the serial as KEY_COMPROMISE, and its CRL, read from S3, verifies against the root and lists
    the serial.

## Product bugs found and fixed in this change

1. **ACM inventory missed every certificate that is not RSA-1024 or RSA-2048**
   (`internal/cloudinventory/aws_acm.go`, commit `bc4e1a3f`).
   - Cause: ListCertificates was called without `Includes.KeyTypes`, and ACM's default filter
     returns only RSA_1024 and RSA_2048.
   - Effect: on real ACM, ECDSA and RSA-3072/4096 certificates would never reach the inventory.
   - How it surfaced: moto ignores the filter, which hid this. Against AWS's emulator the scan
     listed 0 of 5 imported ECDSA certificates.
   - Fix: ask for every key type. A unit test checks the filter.
2. **ML-DSA KMS keys were scored `pqc_readiness=unknown`**
   (`internal/keyinventory/inventory.go`, commit `7fc13753`).
   - Cause: AWS spells the KeySpec `ML_DSA_65` and GCP spells the algorithm `PQ_SIGN_ML_DSA_65`;
     the scorer matched only `ML-DSA` and `MLDSA`.
   - Fix: underscore spellings of ML-DSA, ML-KEM and SLH-DSA now score `quantum_safe`, with unit
     cases.

No verification check was loosened.

## Harness fix found on the way

- upstream-cas scenario C posted an `api_token` credential to the `aws_pca` connector. Since C-02
  the hub accepts only `cloud_iam` there, so the moto leg failed with "credential_ref does not
  name a credential you may use".
- Both legs now use `cloud_iam` (commit `28519724`), and moto scenario C passes again.

## What it took to reach the emulator

- **Go tests and host-process hubs** (kms-aws, escrow-byok, key-inventory, cloud-inventory) need
  only the environment from AWS's "point the SDK at the emulator" page: `AWS_ENDPOINT_URL`
  (`127.0.0.1`, not `localhost`), the per-run credentials and config files, and
  `AWS_CA_BUNDLE`. No product change was needed.
- **Containerised hub** (upstream-cas C):
  - The problem: the hub's egress guard refuses loopback, and the emulator's certificate names
    only `localhost` and `127.0.0.1`, so the hub cannot dial the emulator directly.
  - The workaround: an nginx pass-through on the run network re-terminates TLS with the
    harness's fixture CA, which the hub already trusts as its system roots. It forwards to
    `aws-emulator` running in nginx's own network namespace, with the Host header unchanged so
    SigV4 still verifies.
  - The connector gets the emulator's per-run keys as a `cloud_iam` credential. These keys stay
    in the run's temporary directory and are deleted with it.

## Known emulator gaps and bugs (recorded, never counted as a pass)

| Gap | Where | Recorded as |
|---|---|---|
| KMS GetPublicKey and Sign on `ML_DSA_65` return 501 NotImplemented ("scaffolded but not implemented") | key-inventory | named SKIP `KNOWN EMULATOR GAP` |
| ACM PCA `SHA384WITHECDSA` on a P-256 CA: the leaf's signature field holds 32 raw bytes, not a DER ECDSA signature, and it does not verify | upstream-cas C1b | named SKIP `KNOWN EMULATOR BUG`; hub legs use SHA256WITHECDSA |
| KMS holds at most 500 keys | key-inventory | 1,000+ key case runs with 450 keys; named SKIP line |
| One Region for all of the emulator | cloud-inventory | two-region merge skipped by name; runs on moto |
| CloudFront accepts a nonexistent `ACMCertificateArn` (and `"None"`) | spike only (no CloudFront leg) | not provable here |

moto gaps that remain:

- moto ignores DIGEST.
- moto returns 500 for ScheduleKeyDeletion by ARN.
- moto has no GetParametersForImport.
- moto cannot create ML-DSA keys.
- moto returns all KMS keys and ACM certificates in one page.
- moto omits `SubjectAlternativeNameSummaries`.
- moto's PCA revoke is a no-op.

## Plugin and Route 53 endpoint override: not possible today

None of these three can be pointed at AWS's emulator (or a VPC endpoint) today, so
`tests/live/delivery-cloud` (aws-sm, aws-alb, aws-cloudfront) and
`tests/live/acme-dns-providers` (route53) have **no** emulator legs in this change, and no
product code was changed for them. Row: "A custom AWS endpoint for the AWS delivery plugins
and the Route 53 DNS-01 connector" in [ROADMAP.md](../ROADMAP.md).

Why, per component:

| Component | How it calls AWS | Why `AWS_ENDPOINT_URL` / `AWS_CA_BUNDLE` do nothing |
|---|---|---|
| `plugins/aws` (ACM import, ALB listener, CloudFront) | Hand-rolled SigV4 (`plugins/aws/sigv4.go`) from WASM, through the hub's `HTTP()` host call | URLs are fixed: `plugins/aws/acm.go` `hostFor()` builds `https://<service>.<region>.amazonaws.com/` (ACM, ELB); `plugins/aws/cloudfront.go` `cfBinding.path()` builds `https://cloudfront.amazonaws.com/2020-05-31/...`. The manifest's `capabilities.network.hosts` lists only those hosts for 10 Regions, port 443 only. Plugins get no environment (wazero module config has no env). |
| `plugins/aws-secretsmanager` | Same pattern (`plugins/aws-secretsmanager/sigv4.go`) | `main.go` posts to `"https://secretsmanager." + region + ".amazonaws.com/"`; manifest hosts are those 10 Regions only. |
| Route 53 DNS-01 (`internal/bootstrap/connector_acme_dns01_route53.go`) | `net/http` request signed with aws-sdk-go-v2's v4 signer, not an SDK client | `route53APIBase = "https://route53.amazonaws.com"` is fixed in the constructor (`apiBase` is a test seam only). Its client (`dnsAPIClient()`, `connector_acme_dns01.go`) is behind the egress guard, which refuses loopback in production. |

Trust is not the blocker: plugins already honour a `tls_ca_pem` field in the credential
(`internal/bootstrap/renewal_plugin.go`, `credentialFieldTLSCA`), and the Route 53 client uses
the hub's system roots, so `SSL_CERT_FILE` works.

What a later change needs (no code in this PR):

1. `plugins/aws`: an optional credential field, for example `endpoint_url` (one base URL the
   emulator serves for every service), used by `hostFor()` and `cfBinding.path()` when set;
   `credential_schema` gains the field, and `capabilities.network` gains
   `"hosts_from_credential": "endpoint_url"` plus `ports` for a non-443 port. The azure plugin's
   `vault_url` grant is the precedent.
2. `plugins/aws-secretsmanager`: the same `endpoint_url` field, used in `main.go` in place of the
   regional host, with the same manifest grant.
3. Route 53: an optional `endpoint_url` (and `tls_ca_pem`) in the ACME connector credential's
   `dns` object (`route53Payload` in `connector_acme_dns01_route53.go`), used for `apiBase`.
4. Harnesses: with those, the emulator legs would sit behind the same TLS pass-through used by
   `tests/live/upstream-cas` scenario C, since the hub's egress guard refuses loopback and the
   emulator's certificate names only `localhost` and `127.0.0.1`. The direct readers in
   `tests/live/delivery-cloud/storeread.py` and `tests/live/acme-dns-providers/txtleft.py` also
   hard-code the public AWS hosts.

Workaround considered and not used: resolving the real `*.amazonaws.com` names to an emulator
container on port 443 with a certificate for those names. The emulator has no option to serve a
custom certificate, and the trick would test name redirection rather than the product.

## Not proven

- IAM, key policies and grants (neither emulator enforces them).
- KMS HSM tiers and custom key stores, and real quotas and throttling.
- Real load balancers and CloudFront edges: no TLS handshake against an ALB or distribution
  serving a delivered certificate.
- Public DNS: no Route 53 leg, and no resolution through public resolvers.
- ML-DSA signing in KMS: creation and inventory only; GetPublicKey and Sign are 501 on the
  emulator.
- CloudFront certificate validation: the emulator accepts a nonexistent certificate ARN.
- Delivery to ACM, ALB, CloudFront and Secrets Manager, and Route 53 DNS-01: no emulator leg
  until the endpoint override exists.
- 1,000+ KMS keys across real ListKeys pages: the emulator caps at 500 keys, and moto does not
  page.
- SHA384WITHECDSA issuance through AWS Private CA (emulator bug).

## Not caused by this change

- upstream-cas scenario B (EJBCA CE 9.3.7) failed twice on this host at
  `B1 ... could not trust ManagementCA in the EJBCA truststore`.
- This branch does not change scenario B, and the step runs before any AWS code.
- The recorded passing run (`LIVE_RESULTS_UPSTREAM_CAS_v1.1.md`) was on macOS with podman 6.1.3.
  This host runs Linux with podman 5.7.0.

## Run tails (home paths and the host name scrubbed)

### kms-aws, moto
```
--- PASS: TestAWSKMSDeletionPendingAndCancel (0.70s)
--- PASS: TestAWSKMSStoreAgainstEmulator (17.40s)
    --- PASS: TestAWSKMSStoreAgainstEmulator/ECDSA-P256 (4.82s)
    --- PASS: TestAWSKMSStoreAgainstEmulator/ECDSA-P384 (4.04s)
    --- PASS: TestAWSKMSStoreAgainstEmulator/RSA-2048 (3.86s)
    --- PASS: TestAWSKMSStoreAgainstEmulator/RSA-3072 (4.68s)
ok  	kryptkeeper/tests/live/kms-aws	18.120s
ALL CHECKS PASSED
```

### kms-aws, AWS's emulator
```
aws-emulator: Version: 1.0.512 Release date: 2026.11.18 Commit: 1591f1d9df5fd60ebca7d7483d8a2951176db352
--- PASS: TestAWSKMSDeletionPendingAndCancel (0.04s)
--- PASS: TestAWSKMSStoreAgainstEmulator (0.74s)
    --- PASS: TestAWSKMSStoreAgainstEmulator/ECDSA-P256 (0.01s)
    --- PASS: TestAWSKMSStoreAgainstEmulator/ECDSA-P384 (0.03s)
    --- PASS: TestAWSKMSStoreAgainstEmulator/RSA-2048 (0.12s)
    --- PASS: TestAWSKMSStoreAgainstEmulator/RSA-3072 (0.58s)
ok  	kryptkeeper/tests/live/kms-aws	0.791s
ALL CHECKS PASSED
```

### escrow-byok, moto
```
--- PASS: TestEscrowRecoverRoundTrip (7.05s)
    --- PASS: TestEscrowRecoverRoundTrip/rsa (1.40s)
    --- PASS: TestEscrowRecoverRoundTrip/ecdsa (1.46s)
    --- PASS: TestEscrowRecoverRoundTrip/mldsa (1.47s)
    --- PASS: TestEscrowRecoverRoundTrip/hybrid (2.73s)
--- PASS: TestEscrowRecoverWrongPassphrase (1.24s)
--- PASS: TestEscrowRecoverExistingID (1.19s)
    escrow_byok_live_test.go:316: audit sequence reaching moto: byok.params=failure
    escrow_byok_live_test.go:330: RESULT: PARTIAL (emulator): ExportEscrowedKeyToKMS returned: byok: import parameters: aws kms GetParametersForImport d38e3b30-bd87-46a2-998e-b72fd6e0facd: operation error KMS: GetParametersForImpo
--- PASS: TestBYOKImportAWS (4.99s)
    escrow_byok_live_test.go:378: RESULT: NOT IMPLEMENTED (refused by design, follow-up W23-20a): byok: Azure Key Vault import is not implemented — its BYOK blob is a signed transfer structure with its own KEK ceremony, not AWS's 
--- PASS: TestBYOKImportAzure (0.00s)
ok  	kryptkeeper/tests/live/escrow-byok	14.507s
ALL CHECKS PASSED
```

### escrow-byok, AWS's emulator
```
aws-emulator: Version: 1.0.512 Release date: 2026.11.18 Commit: 1591f1d9df5fd60ebca7d7483d8a2951176db352
--- PASS: TestEscrowRecoverRoundTrip (5.39s)
    --- PASS: TestEscrowRecoverRoundTrip/rsa (1.44s)
    --- PASS: TestEscrowRecoverRoundTrip/ecdsa (1.21s)
    --- PASS: TestEscrowRecoverRoundTrip/mldsa (1.20s)
    --- PASS: TestEscrowRecoverRoundTrip/hybrid (1.54s)
--- PASS: TestEscrowRecoverWrongPassphrase (0.70s)
--- PASS: TestEscrowRecoverExistingID (0.64s)
    escrow_byok_live_test.go:316: audit sequence reaching aws-emulator: byok.params=success, byok.wrap=success, byok.import=success
    escrow_byok_live_test.go:360: RESULT: PASS: ImportKeyMaterial accepted, key Enabled, KMS public key byte-identical to the escrowed key
--- PASS: TestBYOKImportAWS (2.64s)
    escrow_byok_live_test.go:378: RESULT: NOT IMPLEMENTED (refused by design, follow-up W23-20a): byok: Azure Key Vault import is not implemented — its BYOK blob is a signed transfer structure with its own KEK ceremony, not AWS's 
--- PASS: TestBYOKImportAzure (0.00s)
ok  	kryptkeeper/tests/live/escrow-byok	9.404s
ALL CHECKS PASSED
```

### key-inventory, moto
```
--- PASS: TestLiveKeyInventory_AWSKeyAlgorithmAndRotation (0.84s)
--- SKIP: TestLiveKeyInventory_AzureKeyVault (0.00s)
--- PASS: TestLiveKeyInventory_SSHSourceAndDownProviderIsNamed (0.47s)
--- PASS: TestLiveKeyInventory_HungProviderIsAbandoned (2.17s)
--- SKIP: TestLiveKeyInventory_GCPSkipped (0.00s)
--- SKIP: TestLiveKeyInventory_HubEndpoint (0.00s)
    keyinventory_live_test.go:295: emulator cannot create an ML_DSA_65 key: operation error KMS: CreateKey, https response error StatusCode: 400, RequestID: <id>, api error Validatio
--- SKIP: TestLiveKeyInventory_MLDSAKeyListedQuantumSafe (0.01s)
    keyinventory_live_test.go:393: KNOWN EMULATOR LIMIT: one ListKeys page holds all 1011 keys; NextMarker path not exercised
    keyinventory_live_test.go:413: inventory listed all 1005 created keys (1011 total) in 8.952s
--- PASS: TestLiveKeyInventory_PaginationAcrossPages (53.07s)
ok  	kryptkeeper/tests/live/key-inventory	56.581s
--- skips (named, never silent) ---
    keyinventory_live_test.go:295: emulator cannot create an ML_DSA_65 key: operation error KMS: CreateKey, https response error StatusCode: 400, RequestID: <id>, api error Validatio
    keyinventory_live_test.go:393: KNOWN EMULATOR LIMIT: one ListKeys page holds all 1011 keys; NextMarker path not exercised
ALL CHECKS PASSED
```

### key-inventory, AWS's emulator
```
aws-emulator: Version: 1.0.512 Release date: 2026.11.18 Commit: 1591f1d9df5fd60ebca7d7483d8a2951176db352
SKIP: 1,000+ key pagination on aws-emulator: it holds at most 500 KMS keys; the case runs with 450 keys
--- PASS: TestLiveKeyInventory_AWSKeyAlgorithmAndRotation (0.19s)
--- SKIP: TestLiveKeyInventory_AzureKeyVault (0.00s)
--- PASS: TestLiveKeyInventory_SSHSourceAndDownProviderIsNamed (0.11s)
--- PASS: TestLiveKeyInventory_HungProviderIsAbandoned (2.18s)
--- SKIP: TestLiveKeyInventory_GCPSkipped (0.00s)
--- SKIP: TestLiveKeyInventory_HubEndpoint (0.00s)
    keyinventory_live_test.go:315: KNOWN EMULATOR GAP: GetPublicKey on ML_DSA_65 returns 501: operation error KMS: GetPublicKey, https response error StatusCode: 501, RequestID: , api error NotImplemented: operation GetPublicKey f
    keyinventory_live_test.go:327: KNOWN EMULATOR GAP: Sign with ML_DSA_SHAKE_256 returns 501: operation error KMS: Sign, https response error StatusCode: 501, RequestID: , api error NotImplemented: operation Sign with the ML_DSA_
--- PASS: TestLiveKeyInventory_MLDSAKeyListedQuantumSafe (0.04s)
    --- PASS: TestLiveKeyInventory_MLDSAKeyListedQuantumSafe/listed (0.03s)
    --- SKIP: TestLiveKeyInventory_MLDSAKeyListedQuantumSafe/get-public-key (0.00s)
    --- SKIP: TestLiveKeyInventory_MLDSAKeyListedQuantumSafe/sign (0.00s)
    keyinventory_live_test.go:387: first ListKeys page: 100 keys, truncated
    keyinventory_live_test.go:413: inventory listed all 450 created keys (457 total) in 801ms
--- PASS: TestLiveKeyInventory_PaginationAcrossPages (1.03s)
ok  	kryptkeeper/tests/live/key-inventory	3.556s
--- skips (named, never silent) ---
    keyinventory_live_test.go:315: KNOWN EMULATOR GAP: GetPublicKey on ML_DSA_65 returns 501: operation error KMS: GetPublicKey, https response error StatusCode: 501, RequestID: , api error NotImplemented: operation GetPublicKey f
    keyinventory_live_test.go:327: KNOWN EMULATOR GAP: Sign with ML_DSA_SHAKE_256 returns 501: operation error KMS: Sign, https response error StatusCode: 501, RequestID: , api error NotImplemented: operation Sign with the ML_DSA_
ALL CHECKS PASSED
```

### cloud-inventory, moto
```
PASS: emulator answering on :5566 (docker.io/motoserver/moto:latest)
SKIP dns_names assertion: emulator omits SubjectAlternativeNameSummaries in ListCertificates (common_name asserted instead)
PASS: 5 certificates imported (ARNs captured)
PASS: hub built
PASS: scan job scan-1795032772256977652 completed
PASS: results_summary: 5 distinct ARNs equal to imported, common_name + not_after set
PASS: rerun job completed
PASS: rerun: still 5 certificates, same ARN set, no duplicate resource_id
PASS: 2 certificates imported into eu-west-1
PASS: two scopes: 7 certificates, all ARNs present
PASS: bad scope: status completed_with_errors
PASS: error_message names the failing scope
PASS: good scopes' 7 certificates still listed
PASS: requested certificate arn:aws:acm:us-east-1:123456789012:certificate/10eb75f8-ff44-45c3-ac3a-a329af2917ab
PASS: scan with a pending certificate completed
PASS: results_summary: 6 certificates (5 imported + 1 pending)
PASS: pending certificate listed with status PENDING_VALIDATION
PASS: 1100 certificates imported
  ListCertificates as the hub calls it: PAGES=1 CERTS=1106
SKIP NextToken path: the emulator returned all certificates in one ListCertificates page (PAGES=1 CERTS=1106); completeness still asserted
PASS: scan over 1106 certificates completed
PASS: results_summary.certificates=1106, 200 persisted items, no duplicate resource_id
PASS: aws unreachable: job failed
PASS: message readable: 1 of 1 scopes failed: aws-acm/default/us-east-1: aws acm: list certificates: operation error ACM: ListCertificates, exceeded maximum number of attempts, 3, http
PASS: message carries no credential value
PASS: message has no stack trace
PASS: azure missing creds: job failed
PASS: azure message readable: connector init: azure keyvault: get token: AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET are required
SKIP azure positive: no test tenant (set KK_LIVE_AZURE_KV_URL, AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
PASS: gcp no credentials: job failed
PASS: gcp message readable: connector init: gcp certmanager: get token: GCP metadata server unreachable — set GOOGLE_ACCESS_TOKEN or run on GCE/GKE: Get "http://metadata.google.internal/co
SKIP gcp positive: no test project (set KK_LIVE_GCP_PROJECT and GOOGLE_ACCESS_TOKEN)
=== cloud-inventory: 27 passed, 0 failed, 4 skipped ===
ALL CHECKS PASSED
```

### cloud-inventory, AWS's emulator
```
aws-emulator: Version: 1.0.512 Release date: 2026.11.18 Commit: 1591f1d9df5fd60ebca7d7483d8a2951176db352
PASS: aws-emulator answering on https://127.0.0.1:55611 (SigV4 on, telemetry off)
PASS: 5 certificates imported (ARNs captured)
PASS: hub built
PASS: scan job scan-1795032811422722718 completed
PASS: results_summary: 5 distinct ARNs equal to imported, common_name + not_after set
PASS: rerun job completed
PASS: rerun: still 5 certificates, same ARN set, no duplicate resource_id
SKIP two-region merge: aws-emulator does not separate Regions (one Region per emulator), so this case stays on moto
PASS: bad scope: status completed_with_errors
PASS: error_message names the failing scope
PASS: good scope's 5 certificates still listed
PASS: requested certificate arn:aws:acm:us-east-1:000000000000:certificate/1e04009b-5d89-4048-923d-51ed4b98c1b2
PASS: scan with a pending certificate completed
PASS: results_summary: 6 certificates (5 imported + 1 pending)
PASS: pending certificate listed with status PENDING_VALIDATION
PASS: 1100 certificates imported
  ListCertificates as the hub calls it: PAGES=2 CERTS=1106
PASS: ListCertificates spans several pages (PAGES=2 CERTS=1106)
PASS: scan over 1106 certificates completed
PASS: results_summary.certificates=1106, 200 persisted items, no duplicate resource_id
PASS: aws unreachable: job failed
PASS: message readable: 1 of 1 scopes failed: aws-acm/default/us-east-1: aws acm: list certificates: operation error ACM: ListCertificates, exceeded maximum number of attempts, 3, http
PASS: message carries no credential value
PASS: message has no stack trace
PASS: azure missing creds: job failed
PASS: azure message readable: connector init: azure keyvault: get token: AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET are required
SKIP azure positive: no test tenant (set KK_LIVE_AZURE_KV_URL, AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
PASS: gcp no credentials: job failed
PASS: gcp message readable: connector init: gcp certmanager: get token: GCP metadata server unreachable — set GOOGLE_ACCESS_TOKEN or run on GCE/GKE: Get "http://metadata.google.internal/co
SKIP gcp positive: no test project (set KK_LIVE_GCP_PROJECT and GOOGLE_ACCESS_TOKEN)
=== cloud-inventory: 25 passed, 0 failed, 3 skipped ===
ALL CHECKS PASSED
```

### upstream-cas, moto (scenarios A, B, C)
```
=== build hub, create network kk-upca-net-8a3356 ===
PASS: hub up at https://localhost:42255 (container kk-upca-hub-8a3356); commit 28519724
PASS: template tpl-upca-server-1795032839789600579
=== A1 Vault dev server (TLS) with a PKI mount, internal root and a role for uat.example ===
PASS: vault Vault v1.18.5 (2cb3755273dbd63f5b0f8ec50089b57ffd3fa330), built 2025-02-24T09:40:28Z ready; root: subject=CN=UAT Vault PKI Root
=== A2 hub: outbound credential, vault_pki connector, /test, external CA ===
PASS: connector test -> 200 {"status":"healthy","detail":""}
PASS: external CA 19505dbc-5db5-48a3-b736-d4cce2b52275 bound to conn-bb1e206f16232230d74406dbb2c011d3
=== A3 issue via REST POST /api/v1/certificates ===
PASS: REST issue -> 201
PASS: REST: issuer is the upstream CA (CN=UAT Vault PKI Root), serial 3B9EFF4DE3915D9AE896A3524867A2E386D5DBD0
PASS: REST: openssl verify -CAfile <upstream root> -> ~/kk-uat-upca-8a3356/rest1.uat.example.crt: OK 
PASS: REST issue #2 -> 201 (1B4EDF14798603699B8EB74A96BB9F98C397A2EC)
=== A4 issue via ACME (lego, http-01) on a provisioner bound to the external CA ===
PASS: ACME provisioner vaultca -> 201
PASS: lego obtained a certificate (exit 0)
PASS: ACME: issuer is the upstream CA (CN=UAT Vault PKI Root), serial 45F02A543DEF189F6D9E03813986EEDF4817189E
PASS: ACME: openssl verify -CAfile <upstream root> -> ~/kk-uat-upca-8a3356/acme-leaf.pem: OK 
=== A5 issue via EST simpleenroll (default CA = the external CA) ===
PASS: EST simpleenroll -> 200
PASS: EST: issuer is the upstream CA (CN=UAT Vault PKI Root), serial 6A496EE56A8148FB5BAB38CC6D8E14E9A3FFAD7A
PASS: EST: openssl verify -CAfile <upstream root> -> ~/kk-uat-upca-8a3356/est.crt: OK 
=== A6 revoke through the hub -> upstream (Vault) revocation ===
PASS: revoke -> 200 revocation_scope=upstream
PASS: vault pki/cert/3b:9e:ff:4d:e3:91:5d:9a:e8:96:a3:52:48:67:a2:e3:86:d5:db:d0 revocation_time=1795032853
=== A7 tamper: a CA that returns something other than the request is refused ===
PASS: tamper connector reaches Vault through the proxy
PASS: key-swapped certificate refused -> 502 {"error":"upstream_response_rejected","message":"the external CA returned a certificate that does not match the request: certificate public key does not match the request's key"}
PASS: extra-SAN certificate refused -> 502 {"error":"upstream_response_rejected","message":"the external CA returned a certificate that does not match the request: DNS name \"extra-san.uat.example\" was not requested"}
PASS: audit has certificate.issue.upstream_rejected for both tampers: 2 row(s): {"ca_id":"5a861c5f-6507-4f4e-9588-d95fe02f78da","connector_id":"conn-6135cae770da387b16a69590119d9317","fingerprint":"5045efcf2af7f3e0f253773b9c327cba
PASS: no rejected certificate was stored
=== A8 revoke while Vault is unreachable -> 502, NOT revoked in the hub ===
PASS: revoke with Vault down -> 502 {"error":"upstream_revoke_failed","message":"upstream CA (connector conn-bb1e206f16232230d74406dbb2c011d3) did not revoke the certificate: Post \"https://kk-upca-vault-8a3356:8200/v1/pki/revoke\
PASS: certificate NOT revoked in the hub after the failed upstream revoke (revoked_at=None revocation_scope=None)
PASS: audit has certificate.revoke.upstream_failed
=== B1 EJBCA CE container (docker.io/keyfactor/ejbca-ce:9.3.7), REST enabled, REST client certificate ===
PASS: EJBCA healthy after ~150s
FAIL: could not trust ManagementCA in the EJBCA truststore (stopped here: truststore)
=== C1 moto (docker.io/motoserver/moto:5.0.28): does it implement acm-pca issue/get/revoke? ===
PASS: moto implements issue, get and revoke handlers
PASS: moto PCA root created: arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/696472dd-8e5f-4c7e-be19-8218c54ef40e
=== C2 hub: aws_pca connector -> moto, external CA, issue, revoke ===
PASS: connector test -> 200 {"status":"healthy","detail":""}
PASS: external CA 013bc908-c399-4679-83a6-6f8e6e32f868
PASS: REST issue -> 201
PASS: AWS PCA (moto): issuer is the upstream CA (CN=UAT moto PCA Root), serial 65BEF0C0550D01B5AF2DF8C41A3C477F1CC9E413
PASS: AWS PCA (moto): openssl verify -CAfile <upstream root> -> ~/kk-uat-upca-8a3356/pca1.uat.example.crt: OK 
PASS: revoke -> 200 revocation_scope=upstream (moto revoke_certificate is NOOP: the hub's call was accepted, upstream state cannot be checked)
ONE OR MORE STEPS FAILED
```

### upstream-cas, AWS's emulator (scenario C)
```
=== build hub, create network kk-upca-net-b12b1c ===
PASS: hub up at https://localhost:52045 (container kk-upca-hub-b12b1c); commit 28519724
PASS: template tpl-upca-server-1795033098994960051
=== C1 AWS's emulator behind a TLS pass-through on kk-upca-net-b12b1c ===
aws-emulator: Version: 1.0.512 Release date: 2026.11.18 Commit: 1591f1d9df5fd60ebca7d7483d8a2951176db352
PASS: aws-emulator answering inside kk-upca-awsemu-b12b1c at https://127.0.0.1:9297 (SigV4 on, telemetry off)
PASS: emulator PCA root (EC P-256, SHA256WITHECDSA, CRL to S3) created: arn:aws:acm-pca:us-east-1:000000000000:certificate-authority/28192f19-15c1-44e0-8884-4efba05a0955
=== C1b known emulator bug: SHA384WITHECDSA on a P-256 CA ===
SKIP: KNOWN EMULATOR BUG: SHA384WITHECDSA leaf from a P-256 CA does not verify ( Signature Algorithm: ecdsa-with-SHA384); the hub legs use SHA256WITHECDSA
=== C2 hub: aws_pca connector -> emulator, external CA, issue, revoke ===
PASS: connector test -> 200 status=healthy
PASS: external CA e69ad654-ce54-48fd-bbd3-430c076d9549
PASS: REST issue -> 201
PASS: AWS PCA (aws-emulator): issuer is the upstream CA (CN=UAT AWS emulator PCA Root), serial 20968F0A52EAACCD5EBDFD994BB5ED2B
PASS: AWS PCA (aws-emulator): openssl verify -CAfile <upstream root> -> ~/kk-uat-upca-b12b1c/pca1.uat.example.crt: OK 
PASS: leaf signature algorithm ecdsa-with-SHA256 (requested SHA256WITHECDSA)
PASS: leaf notAfter = issue time + 29 days (drift 0s; requested validity_days=29)
PASS: revoke -> 200 revocation_scope=upstream
=== C3 revocation in the emulator's own state (audit report and CRL) ===
PASS: audit report lists serial 20:96:8f:0a:52:ea:ac:cd:5e:bd:fd:99:4b:b5:ed:2b as KEY_COMPROMISE
PASS: CRL from S3 verifies against the root and lists serial 20968F0A52EAACCD5EBDFD994BB5ED2B
ALL STEPS PASSED
```
