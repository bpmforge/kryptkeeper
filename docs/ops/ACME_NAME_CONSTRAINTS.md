# ACME under a name-constrained CA: fixed subject components

ACME clients (win-acme, acme.sh, Posh-ACME, certbot, lego) ask for a DNS
name and nothing else, so the certificate subject is `CN=<name>`. If the
issuing CA carries **directoryName name constraints** (RFC 5280 §4.2.1.10),
for example "permitted: DC=foo,DC=bar", a relying party rejects a
`CN=webserver` certificate because its subject is not under that subtree.

A template can fix subject components that are appended after the CN on
every certificate issued under it, whatever the client asked for (the
EJBCA "non-modifiable default value" model, D-332):

```
requested:  CN=webserver.foo.bar
issued:     CN=webserver.foo.bar,DC=foo,DC=bar
```

## 1. Create the template

On the Templates page, fill **Fixed subject components** with
`DC=foo,DC=bar`, or through the API:

```bash
curl -sS -X POST "$HUB/api/v1/templates" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
  "name": "acme-foo-bar",
  "display_name": "ACME (DC=foo,DC=bar)",
  "key_usage": ["digitalSignature", "keyEncipherment"],
  "extended_key_usage": ["serverAuth"],
  "allowed_algorithms": ["RSA", "ECDSA"],
  "validity_period": "P90D",
  "active": true,
  "subject_policy": {
    "fixed_rdns": [
      {"type": "DC", "value": "foo"},
      {"type": "DC", "value": "bar"}
    ]
  }
}'
```

- Write the components in the order you read a DN, most specific first,
  straight after the CN. Kryptkeeper encodes them top of the tree first
  (`DC=bar`, `DC=foo`, `CN=...`), which is what a directoryName constraint
  compares against; `openssl x509 -subject` prints them in that encoded
  order.
- Types: `DC` (one DNS label per entry, IA5String), `O`, `OU`, `L`, `ST`,
  `C` (two upper-case letters). At most 10. `CN` is never fixed.
- When the list is non-empty the subject is exactly the CN plus these
  components. Anything else the request carried (an `O=` in a CSR, say) is
  dropped, so a requester cannot step outside the subtree.
- The same template applies on API issuance, renewal and WSTEP. EST and SCEP
  do not use templates yet (roadmap).

## 2. Bind it to ACME

Either for the default directory (`/acme/directory`):

```
KRYPTKEEPER_ACME_TEMPLATE=<template id>
```

or for one named provisioner directory (`/acme/<name>/directory`), by
setting the provisioner's `template_id` (`POST /api/v1/acme/provisioners`
or `PUT /api/v1/acme/provisioners/{name}`). A provisioner's template replaces
the default one for that directory.

A bound template now governs ACME as a whole, not only who may enroll:
allowed algorithms, minimum key size, EKUs and name policy apply too, and a
validity shorter than 90 days shortens ACME certificates. A request that
breaks the template gets an ACME `badCSR` error naming the rule. If the
template cannot be read, ACME refuses to issue (fail closed).

## 3. Point the client at it

Nothing changes on the client. win-acme, for example:

```
wacs.exe --source manual --host webserver.foo.bar ^
  --baseuri https://kryptkeeper.example/acme/foo-bar/directory
```

## What the CA checks before signing

Every issuance (any protocol) is checked against the name constraints of
the issuing CA and of its ancestors that Kryptkeeper holds: directoryName
on the subject, and DNS, IP, email and URI on the SANs. A certificate that
would be invalid is refused instead of signed, for example:

```
issuance policy "issuing CA name constraints": rule name_constraints:
subject "CN=webserver.foo.bar" is not under a permitted directoryName
(DC=foo,DC=bar); the CA "CN=Constrained Issuing" does not permit it ...
```

That error is what a CN-only ACME request gets from a DN-constrained CA when
the template has no fixed components.

Verified with OpenSSL 3 against a root, an issuing CA permitted
`DirName: DC=bar, DC=foo` and `DNS:foo.bar`, and a certificate issued
through this template: `openssl verify -x509_strict -CAfile root.pem
-untrusted issuing.pem leaf.pem` answers `OK`.

## External CAs

When the issuing CA is external (D-304), Kryptkeeper forwards the CSR and
the upstream builds the subject, so the upstream (an EJBCA end entity
profile, say) must add the components. Bind the same template to the ACME
directory so Kryptkeeper expects `CN=...,DC=foo,DC=bar` back; without it,
a subject longer than the CN is rejected as not what was authorised. An
upstream issuing CA with directoryName constraints verifies normally: the
Go library cannot evaluate those constraints, so Kryptkeeper checks them on
the verified chain itself.
