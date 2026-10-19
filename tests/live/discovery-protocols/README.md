# W24-03: live protocol-scan harness

One container runs real postfix (25, 587), dovecot (IMAP 143 STARTTLS, POP3
110 STLS), PostgreSQL (5432, `ssl=on`), OpenLDAP (389 StartTLS), xrdp (3389,
`security_layer=tls`) and sshd (22), each with its own throwaway P-256 cert
generated at start. A containerised hub runs a `full` scan against the
container's IP and `compare.py` checks, per protocol, that the stored endpoint
carries the served leaf fingerprint (SSH: every host-key algorithm the server
has a key for). Expected values are read from the servers' own files, never
from the hub.

    bash tests/live/discovery-protocols/run.sh     # podman only
    KK_EVIDENCE_DIR=/some/dir bash ...             # keeps report.json and scan.json

Output: one line per protocol (`smtp 2/2`, `imap 1/1`, `pop3 1/1`,
`postgres 1/1`, `ldap 1/1`, `rdp 1/1`, `ssh 1/1`) and `TOTAL 8/8`; exit 1 on
any miss (per-protocol recall < 0.95).

## xrdp versus the stub
xrdp is unreliable without systemd. The harness runs real xrdp and, if port
3389 is not listening within 20 s, builds `rdpstub/` (stdlib Go: X.224
confirmation then `tls.Server`) and copies it into the container. The mode
used is printed (`rdp:stub` in the table) and written to `report.json` as
`rdp_mode`. A stub run is a PASS but is labelled; see the run record for which
mode actually ran.
