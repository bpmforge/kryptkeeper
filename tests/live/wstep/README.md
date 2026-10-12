# W19-10: user-context WSTEP/XCEP against a real KDC

`wstep_live_test.go` signs in to Active Directory as a domain user with real
Kerberos (gokrb5, SPNEGO). It then drives the hub's XCEP and WSTEP endpoints
the way Windows does on a user autoenrollment pulse.

Machine-context GPO autoenrollment from a Windows client is W18-08. For that
evidence and the GPO runbook, see `docs/ops/WSTEP_AUTOENROLLMENT.md`.

## What it checks

- Anonymous XCEP and WSTEP requests get `401 Negotiate`.
- GetPolicies, as the user:
  - offers at least one template;
  - offers every template as a user template (`subjectNameFlags` CN from
    directory, no machine-type flag);
  - names the issuing CA.
- WSTEP enroll, as the user, with a CSR that asks for `CN=Administrator,
  O=Domain Admins` and a DNS SAN. The issued certificate must:
  - be `CN=<user>` with no SANs;
  - be for the CSR's key;
  - be client-auth only;
  - be signed by the CA from the policy.
- With `KK_WSTEP_API_TOKEN` set, two more checks:
  - the inventory row is `source=wstep` for the user, and carries a
    `template_id` when a template OID was named;
  - the test certificate is revoked at the end.

## Running

```bash
KK_LIVE_WSTEP=1 \
KK_WSTEP_BASE=https://hub.example.lab:8443 \
KK_WSTEP_CA_FILE=/path/to/hub-ca.pem \
KK_WSTEP_REALM=EXAMPLE.LAB KK_WSTEP_KDC=dc.example.lab:88 \
KK_WSTEP_USER=uat-user KK_WSTEP_PASSWORD="$(read from your secret store)" \
KK_WSTEP_CONNECT_ADDR=10.0.0.5:8443 \
KK_WSTEP_TEMPLATE_OID=1.3.6.1.4.1.311.21.8.... \
KK_WSTEP_API_TOKEN="$(read from your secret store)" \
go test ./tests/live/wstep -v -count=1
```

Requirements:

- `KK_WSTEP_BASE` must use the hub's Kerberos name: the service ticket is
  for `HTTP/<that host>`, and the hub refuses NTLM.
- `KK_WSTEP_CONNECT_ADDR` is optional. Set it when the hub's name does not
  resolve where the test runs.
- Use a disposable user who is only in Domain Users.
- The test never logs the password or the token.
