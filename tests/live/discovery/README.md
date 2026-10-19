# W24-01: seeded TLS discovery corpus

Serves 43 known endpoints (`ground-truth.json`) from one fixture container on a
private /24 and checks what the hub's discovery recorded against them.

| class | count | what is served |
|---|---|---|
| tls10 / tls11 | 4 / 4 | TLS 1.0 / 1.1 only (expected finding `DEPRECATED_TLS_VERSION`) |
| tls12 / tls13 | 6 / 6 | TLS 1.2 / 1.3 only, CA-signed |
| selfsigned | 6 | self-signed leaf (`SELF_SIGNED`) |
| expired | 5 | `NotAfter` yesterday (`EXPIRED`) |
| mlkem_hybrid | 5 | TLS 1.3, `X25519MLKEM768` preferred (`hybrid_negotiated`) |
| sni_only | 4 | cert chosen by SNI; scanning by IP gets the default cert |
| not_tls | 3 | plain HTTP on 443 (`NOT_TLS`) |

Two clone listeners on :8443 and :9443 are reached by the full scan's `ports`
list; they are reported as `extra-ports` and are neither in the recall
denominator nor false positives.

## Run

    bash tests/live/discovery/run.sh            # podman only, ~5-10 min
    KK_EVIDENCE_DIR=/some/dir bash tests/live/discovery/run.sh   # keeps report.json, scan.json, audit.json

Steps: fast /24 scan (timed, must finish in 300 s), two full /27 scans with
`ports:[8443,9443]`, `compare.py` (recall >= 0.95, false-positive rate <= 0.02,
0 posture mismatches), then an egress-denied target (`.200`) must be refused
with HTTP 400 and leave a `discovery.scan.create` failure audit entry.

`KK_SOURCE_ONLY=1 . run.sh` loads `setup_network`, `start_fixture`,
`start_hub [extra hub.env lines]`, `wait_scan`, `create_scan` without running
`main` (W24-07 reuses them).

No key material is committed: corpusd generates every key and certificate in
memory per run and only writes the SHA-256 of each served leaf (`served.json`).
