# Vendor attestation roots

Drop-in directory for vendor attestation root certificates (PEM, `*.pem`),
embedded into the hub binary at build time (W26-23, FR-P92).

## Provenance rules

- A root PEM may only be added from the vendor's official published source
  (for YubiKey PIV: Yubico's published PIV attestation CA bundle). Never paste a
  certificate from memory, a mailing list, a third-party mirror, or a module cache.
- Record the SHA-256 of each shipped file's DER certificate in the table below,
  together with the URL it was obtained from and the date, in the same commit.
- Roots are data, never fetched at runtime (egress guard).
- Operators may instead point `KRYPTKEEPER_ATTESTATION_ROOTS_DIR` at a directory of
  `*.pem` files; those are added to the embedded set.

An empty root set fails closed: every attestation is refused.

## Shipped roots

None yet. A human adds `yubico-piv-ca.pem` (with its fingerprint row here) in a follow-up commit.

| File | SHA-256 (DER) | Source URL | Obtained |
|---|---|---|---|
