# W30-20: zero default egress UAT

Proves a default-config hub + agent make no outbound connections, and that
enabling an egress feature reaches only the hosts published in the
machine-readable block of `docs/ops/DATA_RESIDENCY.md`
(`<!-- egress-hosts:begin -->` ... `end`). The script reads that block; it
hard-codes no host.

## Run

```
bash tests/live/egress/run.sh --short                    # default config, 10 min
bash tests/live/egress/run.sh --ct                       # CT on, Cert Spotter off  => exactly {crt.sh}
bash tests/live/egress/run.sh --ct --second-source       # CT on, Cert Spotter on   => {crt.sh, api.certspotter.com}
bash tests/live/egress/run.sh --inject-unlisted          # self-test, MUST exit non-zero
timeout 91800 bash tests/live/egress/run.sh --soak       # 25 h wall clock (manual / weekly self-hosted runner)
```

`--minutes N` overrides the window. Requires podman, Go, python3, openssl.
Image build (apt) and the Go builds happen before the capture window starts.

## How it observes

- `podman pod create --network none`: loopback only, so nothing can leave.
- `sink.py` (in the pod) answers every DNS A/AAAA with loopback and logs the
  qname, the TLS SNI on :443 and the Host header on :80 to `observed.jsonl`.
  Hub and agent get `nameserver 127.0.0.1` via a bind-mounted `resolv.conf`.
- Hub and agent run under `strace -f -e trace=connect`; any non-loopback
  `inet_addr`/`inet_pton` destination is a literal-IP dial and fails the run
  (`connect-hub.log`, `connect-agent.log`).
- Hub env is the `tests/live/agent/run.sh` env plus every scheduler forced to
  1 minute (`RENEWAL_POLL`, `SLO`, `ANOMALY`, `MESH`, `EXCEPTION_EXPIRY`,
  `OWNERSHIP_ORPHAN`, `AGENT_RENEWAL` sweeps).
- Verdict: `observed` (dns + sni + host names, minus `localhost` and the pod's
  own container names) must equal the expected set; a failure prints
  `diff expected observed`. Default run expects the `enabled_by=default` rows
  (none), so any name at all fails.

## Reading a failure

`observed.jsonl` (kind/host/time of each name) and `connect-*.log` are copied
to `tests/live/egress/out/` (override with `EGRESS_ARTIFACT_DIR`); CI uploads
them. An unexpected host means a new egress path: add it to the residency
table (with its opt-in) or remove the dial.

## Limits (read before trusting a green run)

- **No clock injection.** Go reads time through the vDSO, so libfaketime does
  not work and there is no clock hook. "25 h forced scheduler run" is a true
  25 h wall-clock run with 1-minute sweeps; an in-process clock hook would be
  a separate code ticket.
- **CT cannot be exercised in 10 minutes.** `ctmonitor.Start` ticks every
  `KRYPTKEEPER_CT_SCAN_HOURS` (integer hours, minimum 1) and has no scan at
  boot, so `--ct` sets 1 hour and defaults to a 65-minute window. A
  scan-on-start or minutes override would shorten it (separate code ticket).
- The container image build needs registry and apt access.

## Results

PENDING-RUN. Not executed by the author: the authoring environment had no
outbound network, so `apt-get` in the image build failed (verified); the
sink, DNS wire format and verdict parser were unit-checked on the host only.
Run, then paste the final `=== W30-20 egress summary ===` line for each:

```
bash tests/live/egress/run.sh --short
bash tests/live/egress/run.sh --ct
bash tests/live/egress/run.sh --ct --second-source
! bash tests/live/egress/run.sh --inject-unlisted
```
