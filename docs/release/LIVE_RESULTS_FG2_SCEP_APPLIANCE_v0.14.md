# Live validation W26-12: SCEP enrollment from a real appliance - v0.14

Date: PENDING-RUN. Hub commit: PENDING-RUN. Kit: `tests/live/scep-appliance/`.
Appliance (F5 BIG-IP VE or Palo Alto VM-Series): PENDING-RUN. Model/version: PENDING-RUN.

## Verdict: PENDING-RUN - NOT validated

No BIG-IP VE or VM-Series image/licence was available to the build agent, so
nothing here has run against a real appliance. Every measured field is
PENDING-RUN. Only the kit was written; its scripts passed `bash -n` and `--help`
and were never run against a hub. Missing from the lab: an owner-supplied
appliance with a network path to the hub (see `tests/live/scep-appliance/README.md`).
The verdict becomes `PASS` only if enroll, replay refusal and expiry refusal were
all observed on a real appliance.

Docs keep saying "software-client verified" (`docs/ops/SCEP.md`) until this
record shows a real PASS. Intune is W20-23 and not covered here.

| Field | Value |
|---|---|
| Appliance vendor / model / version | PENDING-RUN |
| Config path or screenshot (challenge redacted) | PENDING-RUN |
| Hub SCEP CA (RSA) fingerprint SHA-256 | PENDING-RUN |
| Bound CN / DNS names | PENDING-RUN |
| Deviations from README vendor field names | PENDING-RUN |

## Acceptance evidence

| # | Item | Result | Evidence |
|---|---|---|---|
| 1 | Appliance enrolls with a one-time challenge; cert has `source=scep` | PENDING-RUN | `evidence/<cn>/summary.txt` path: PENDING-RUN |
| 1 | `scep.enroll` success audit row (serial, subject) | PENDING-RUN | excerpt: PENDING-RUN |
| 2 | Replay refused (CertRep FAILURE badRequest) | PENDING-RUN | appliance error text: PENDING-RUN |
| 2 | `scep.enroll` denied row for replay (challenge already used) | PENDING-RUN | excerpt: PENDING-RUN |
| 2 | Expired challenge refused (minted with ttl=1m, waited out) | PENDING-RUN | appliance error text: PENDING-RUN |
| 2 | `scep.enroll` denied row for expiry (challenge expired) | PENDING-RUN | excerpt: PENDING-RUN |
| 2 | Packet capture | PENDING-RUN | pcap path: PENDING-RUN; SHA-256: PENDING-RUN |

No challenge secret may appear in this document or in any evidence file.
