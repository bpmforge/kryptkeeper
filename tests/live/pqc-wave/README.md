# W31-11: live PQC wave harness

Live drill (not part of `go test`, not in CI). A hub built from this checkout runs in podman
with Postgres (reusing `../ca-revoke/fixture.sh`, like `../pqc`) next to three nginx+sshd
endpoints (`kkw31-11-ep-a`, `-ep-b`, `-ep-fail`, alpine:3.22, OpenSSL 3.5.x; fallback base
ubuntu:25.10). Served serials are read with `openssl s_client` inside the endpoint containers,
never from the hub.

## Prerequisites
podman (running machine on macOS), Go, python3, curl, ssh-keygen, host `openssl` (only for CSRs).
No host OpenSSL >= 3.5 is needed: the ML-DSA-capable OpenSSL is the one in the endpoint image.

## Run
    bash tests/live/pqc-wave/run.sh      # HUB_PORT (default 18451); KK_KEEP_GOING=1 runs past a FAIL

Writes `RESULTS.md` here. Containers are prefixed `kkw31-11-` and removed on exit.

## What PASS means today
The production wave deliverer is `unsupportedWaveDeliverer` (D-103 generate-without-deliver;
ML-DSA private-key export does not exist). So the harness asserts the real behaviour:
two-principal propose/approve (self-approval refused), ML-DSA-65 successors issued, every member
bound to a target reported `delivery_unsupported` citing D-103, the unbound member `migrated`
with `delivery=none`, every endpoint still serving its previous serial, wave not `done`, audit rows.

## What PENDING means
`PENDING` lines are legs that need a real deliverer: the served serial changing to the ML-DSA
cert (`ep-a`, `ep-b`) and the injected-failure rollback (`ep-fail`). They are never printed as
PASS. Once the export follow-up lands, replace them with the spec's serial-change and rollback
assertions (set the failing target's `verify_host_port` to `ep-a:443`).
