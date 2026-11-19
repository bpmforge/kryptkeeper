# W36-16: upstream CA live proof (Vault PKI, EJBCA, AWS PCA via moto or AWS's emulator)

Proves that the hub issues and revokes through real upstream CAs, driven only
through the hub API. Record of a run: `docs/release/LIVE_RESULTS_UPSTREAM_CAS_v1.1.md`.

```
bash tests/live/upstream-cas/run.sh              # scenarios A B C
KK_SCENARIOS=A bash tests/live/upstream-cas/run.sh
KK_AWS_EMULATOR=aws KK_SCENARIOS=C bash tests/live/upstream-cas/run.sh   # C against AWS's emulator
```

Needs podman, `openssl`, `python3`, `go`. About 6 minutes (EJBCA takes about 70 s to boot).
Every container and the network carry a random `RUN_ID`; the cleanup trap removes
only those names. Image tags are pinned and overridable
(`KK_VAULT_IMAGE`, `KK_LEGO_IMAGE`, `KK_EJBCA_IMAGE`, `KK_MOTO_IMAGE`, `KK_PY_IMAGE`).

| Scenario | Upstream | What it asserts |
|---|---|---|
| A | HashiCorp Vault PKI (`-dev -dev-tls`) | connector `/test`; issue by REST, ACME (lego, http-01) and EST simpleenroll; issuer is the Vault root and `openssl verify -CAfile` passes; hub revoke gives `revocation_scope=upstream` and Vault's `pki/cert/<serial>` has `revocation_time>0`; a tamper proxy that swaps the CSR (other key, extra SAN) is refused and audited `certificate.issue.upstream_rejected`; revoke with Vault stopped gives 502 `upstream_revoke_failed` and the certificate stays active |
| B | EJBCA CE | REST with a client certificate; issue, `openssl verify`, revoke with EJBCA's own `revocationstatus` confirming; revoke with EJBCA stopped gives 502 |
| C | AWS PCA via moto | checks that the pulled moto has the acm-pca handlers; issue, verify, revoke (moto's revoke is a no-op) |
| C (`KK_AWS_EMULATOR=aws`) | AWS PCA via AWS's emulator (not real AWS) | EC P-256 root with a CRL to S3; connector `/test` healthy; issue by REST with `signing_algorithm=SHA256WITHECDSA`, `validity_days=29`: issuer, `openssl verify`, leaf signature `ecdsa-with-SHA256`, notAfter = issue time + 29 days; hub revoke gives `revocation_scope=upstream`, and the emulator's own audit report lists the serial as KEY_COMPROMISE and its CRL (from S3) verifies and lists it. SHA384WITHECDSA on a P-256 CA is a named KNOWN EMULATOR BUG (the leaf does not verify), never a pass |

## Fixture notes

- Creating an external CA is dual-controlled, so the script runs as two named pki-admins (alice proposes and redeems, bob approves).
- The hub's own listener certificate comes from a throwaway CA. Self-issue would sign it from the default CA, and EST needs the default CA to be the external one.
- EST has no per-label CA, so A5 restarts the hub with `KRYPTKEEPER_DEFAULT_CA_ID` set to the external CA and enrolls with curl and HTTP Basic.
- The tamper proxy (`tamper_proxy.py`) sits in front of Vault with its own CA in the connector's `ca_cert_pem`.
- EJBCA's container "simple" TLS mode starts with an empty server truststore, which resets any connection that presents a client certificate. B1 imports ManagementCA into it and soft-reloads Wildfly. EJBCA's profiles issue 2-year certificates, so B creates a 300-day CA (a CA caps what it issues at its own lifetime) rather than touching the hub's validity check.
- `tests/live/lib/podman.sh kk_wait_dns` uses `nslookup`, which busybox answers NXDOMAIN on the podman 6 stack used here although the name resolves; this script uses `getent` instead (`wait_name`).
- Neither EJBCA nor moto takes a validity in the request, so B and C use a 397-day template. AWS's emulator does, so C on it uses the 30-day template with `validity_days=29`.
- The aws_pca connector takes a `cloud_iam` credential (C-02 refuses `api_token`).
- C on AWS's emulator: the hub's egress guard refuses loopback and the emulator's certificate names only `localhost` and `127.0.0.1`, so an nginx pass-through (`KK_NGINX_IMAGE`) on the run network re-terminates TLS with the fixture CA and forwards, Host header unchanged for SigV4, to `aws-emulator` running in nginx's network namespace (`kk_aws_emulator_netns`). If `aws-emulator` is not installed, C prints a named SKIP.
