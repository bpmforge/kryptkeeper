# W26-12: SCEP enrollment from a real F5 BIG-IP VE or Palo Alto VM-Series

Status: **kit only, never run against a real appliance.** The record is
`docs/release/LIVE_RESULTS_FG2_SCEP_APPLIANCE_v0.14.md` (verdict `PENDING-RUN`).
Until that record shows a real PASS, `docs/ops/SCEP.md` keeps saying
"software-client verified" (micromdm/scep, `tests/live/protocols/run.sh`).

SCEP flow, rules, renewal (W26-30) and audit rows: `docs/ops/SCEP.md`.
Intune is W20-23; it is not covered here.

## What you must supply

- A BIG-IP VE (licensed) or a VM-Series, with a network path to the hub.
- A host running the hub: `go`, `curl`, `openssl`, `python3`.
- `KK_SCEP_HUB_ADDR`: the IP or DNS name the appliance reaches the hub at.
  It goes into the hub TLS SANs, so use the same name in the appliance config.

SCEP needs an RSA issuing CA. `hub-up.sh` creates one (`RSA-2048`) and starts
the hub with `KRYPTKEEPER_SCEP_ENABLED=true` and `KRYPTKEEPER_SCEP_CA_ID`;
an ECDSA CA is refused at startup.

## Run order

1. `KK_SCEP_HUB_ADDR=<addr> ./hub-up.sh` (foreground; keep it open). It prints
   the SCEP URL `https://<addr>:<port>/scep`, the hub TLS CA path and the SCEP CA
   fingerprints. Import the hub TLS CA into the appliance trust store.
2. `./mint-challenge.sh <cn> [dns,...] [ttl]`. The secret is printed once, to the
   terminal only. Never paste it into evidence files or the results doc.
3. Enroll from the appliance (vendor config below).
4. `./collect-evidence.sh <cn>` and confirm `source=scep` and a `scep.enroll`
   success row.
5. **Replay:** retry enrollment with the same challenge. Expect a FAILURE CertRep
   (`badRequest`) and a denied row. Then
   `./collect-evidence.sh <cn> --expect-replay-denied`.
6. **Expiry:** `./mint-challenge.sh <cn2> "" 1m`. The API accepts any positive
   Go duration up to 24h (no floor above zero in
   `internal/bootstrap/handlers_scep_challenges.go`), so 1m is the practical
   minimum. Wait it out (do not edit the hub clock), enroll, expect refusal, then
   `./collect-evidence.sh <cn2> --expect-expiry-denied`.
7. Fill the results doc: appliance model and version, hub commit (printed by
   `hub-up.sh`), config screenshots or paths, pcap path and SHA-256, audit row
   excerpts (no secrets).

`collect-evidence.sh` writes `evidence/<cn>/` (gitignored). Scripts take `--help`
and need no hub for that.

## Per-vendor configuration

Verify field names against the vendor release in use and note any deviation in
the results doc.

### F5 BIG-IP VE

System > Certificate Management > Traffic Certificate Management > SSL
Certificate List > Create. Choose Issuer `SCEP` and set: SCEP URL, Challenge
Password = the minted secret, Common Name = the bound CN.

Packet capture on the BIG-IP:
`tcpdump -ni 0.0 -s0 -w /var/tmp/scep.pcap host <hub>`

### Palo Alto VM-Series

Device > Certificate Management > SCEP profile: Server URL, CA-Cert Fingerprint,
Challenge = Fixed with the minted secret, CN. Then Generate certificate using the
profile.

Capture: Monitor > Packet Capture, or a span on the management interface.

## Evidence checklist

- [ ] appliance model, version, licence type
- [ ] config screenshot or export (challenge redacted)
- [ ] `evidence/<cn>/summary.txt` after enroll (source=scep, success row)
- [ ] replay refusal: appliance error text + denied audit row
- [ ] expiry refusal: appliance error text + denied audit row
- [ ] pcap path and `shasum -a 256`
- [ ] hub commit

## Traps

- Challenges are shown once; never write them to a file.
- `tests/live/f5-citrix/` belongs to W19-11 (blocked); do not use it.
- Without an owner-supplied licence or image, leave W26-12 `todo` and escalate.
