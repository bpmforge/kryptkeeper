# ACME device attestation (device-attest-01)

Issues a client certificate to a device only when the device proves, with
manufacturer-backed hardware evidence, that it holds the key, and only when you
have said you own it. Meant for Wi-Fi, VPN and zero-trust access.

Spec: [draft-ietf-acme-device-attest-10](https://datatracker.ietf.org/doc/draft-ietf-acme-device-attest/)
(identifier `permanent-identifier`, challenge `device-attest-01`). Decisions:
D-316 (verification) and D-317 (ownership and issuance).

**Status: proven with generated attestation chains, not real devices.** Real-device
proof needs an Apple MDM-managed device (Managed Device Attestation) and a TPM
host whose AIK certificate your attestation CA issued. See the ROADMAP row
"ACME device attestation on real devices".

## What the hub checks

For one order with one `permanent-identifier`, all of these must hold:

1. The attestation verifies and chains to a root **you** configured.
2. It binds this challenge: Apple, SHA-256 of the challenge token; TPM, the key
   authorization.
3. The device identifier in the evidence equals the ordered identifier,
   byte for byte (case-sensitive, assigner included).
4. The identifier is in your device inventory (checked again at finalize).
5. The governing template has `device_attestation: true`.
6. At finalize the CSR key is the attested key, and the CSR names nothing but
   that identifier.

The certificate carries the identifier as an RFC 4043 PermanentIdentifier
otherName in the SAN, CN equal to the device part, and client-auth as its only
extended key usage. Every success and refusal is audited as
`acme.device_attest.accept`, `.reject` or `.issue`, with the reason, format and
ordered identifier. Attestation bytes and other attested attributes are never
logged.

## 1. Configure the roots

No root is built in. Without a root, the identifier type is refused at
newOrder (`unsupportedIdentifier`) and nothing changes for DNS orders.

| Variable | Format | Trust anchor you supply |
|---|---|---|
| `KRYPTKEEPER_ACME_APPLE_ATTESTATION_ROOTS` | `apple` | PEM file with the Apple Enterprise Attestation Root CA, downloaded by you from [Apple's private PKI repository](https://www.apple.com/certificateauthority/private/) and checked against Apple's published fingerprint |
| `KRYPTKEEPER_ACME_TPM_ATTESTATION_ROOTS` | `tpm` | PEM bundle of the CA(s) that issue your AIK certificates (a manufacturer bundle, or your own attestation CA) |

An unreadable or empty file turns that format off and logs a warning. Restart
the hub after changing either.

### What each format must present

**apple** (`attStmt = {x5c: [leaf, intermediate]}`): the leaf's freshness code
(OID 1.2.840.113635.100.8.11.1) is SHA-256 of the challenge **token** (Apple's
Managed Device Attestation text; draft section 5 allows token-only binding for
external attestation authorities, which cannot know the account key). The
identifier is the leaf's serial number (1.2.840.113635.100.8.9.1) or UDID
(1.2.840.113635.100.8.9.2); an order may name either. The attested key is the
leaf's public key. Apple omits serial and UDID under User Enrollment, so those
devices cannot be attested.

**tpm** (WebAuthn section 8.3): `ver 2.0`, `alg` ES256, ES384, RS256 or RS384
(RS1 is refused), `x5c`, `sig` (TPMT_SIGNATURE), `certInfo` whose `extraData` is
the hash of the key authorization, and `pubArea` whose SHA-256-or-stronger name
`certInfo` attests (SHA-1 names are refused). The AIK certificate must meet
WebAuthn 8.3.1 (v3, empty subject, EKU 2.23.133.8.3, not a CA, TPM manufacturer
attribute in the SAN directoryName) **and carry the device serial as an RFC 4043
PermanentIdentifier in its SAN**. A TPM does not know its own serial; your
attestation CA, which enrolled the device, asserts it. An AIK certificate
without one proves a TPM but not which device, and is refused.

Certificate revocation of attestation certificates is not checked.

## 2. Add devices to the inventory

Attestation proves hardware; the inventory proves it is yours.

```bash
curl -sS -X POST "$HUB/api/v1/acme/devices" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"C02XYZ123ABC","label":"finance laptop 7"}'
curl -sS "$HUB/api/v1/acme/devices" -H "Authorization: Bearer $TOKEN"
# the identifier is percent-encoded (it may contain "/assigner-OID")
curl -sS -X DELETE "$HUB/api/v1/acme/devices/C02XYZ123ABC" -H "Authorization: Bearer $TOKEN"
```

pki-admin only; each call is audited (`acme.device.add|list|remove`).
Identifiers are at most 64 bytes, no control characters, optionally followed by
`/` and a dotted-decimal assigner OID (draft section 3.1). The assigner is part
of the identifier: an Apple order must omit it, because Apple evidence carries
none. An identifier is unique across the hub. With `MULTI_TENANCY=on` an entry
belongs to the tenant that added it, only that tenant sees or removes it, and
only a CA of that tenant issues to the device.

## 3. Allow it on a template

Add `"device_attestation": true` to the template (create or replace; it is not
settable by PATCH and a clone does not inherit it). The governing template is
the ACME provisioner's `template_id`, else `KRYPTKEEPER_ACME_TEMPLATE`. With no
governing template, device attestation is not offered: the flag is explicit so
no existing template changes behaviour. The template must be active.

A provisioner may list `device-attest-01` in `challenges`; an empty list offers
every challenge the template allows. Only a hub CA can issue these
certificates: an external CA (W36) cannot carry the PermanentIdentifier SAN and
the order is refused.

## 4. What a client sends

newOrder: `{"identifiers":[{"type":"permanent-identifier","value":"C02XYZ123ABC"}]}`
(exactly one identifier; it cannot be mixed with DNS names). Answer the
`device-attest-01` challenge with `{"attObj": "<base64url CBOR attestation object>"}`
(`fmt` is `apple` or `tpm`; `authData` is ignored). Finalize with a CSR for the
attested key and no names, or only the ordered PermanentIdentifier.

A refused attestation returns `badAttestationStatement` with the failed check as
`detail` and the challenge is spent: start a new order to retry.

## Verifying a setup without hardware

`go test ./internal/acme -run 'Device|TPMGolden'` builds Apple-style and TPM
attestation objects with throwaway keys, configures their roots as trusted, and
covers success, wrong nonce, wrong key at finalize, identifier mismatch, unknown
device, untrusted root and unconfigured roots. The TPM parsers are also checked
against the WebAuthn level 3 section 16.13 test vector.
