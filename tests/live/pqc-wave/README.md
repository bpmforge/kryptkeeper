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

## What PASS means
The production deliverer is `keystoreWaveDeliverer` (W31F-06): the ML-DSA successor key is exported
as PKCS#8, installed over ssh through the renewal install path, and verified by the hub's TLS dial.
The run asserts two-principal propose/approve (self-approval refused), ep-a and ep-b serving the
ML-DSA-65 successor serial (read by `openssl s_client` in the endpoint container), ep-fail (its
target's `verify_host_port` set to ep-a:443) rolled back with its old serial and key file intact,
the wave `regressed`, and audit rows including `key.export_for_delivery` with no key material.
Only ssh targets with nginx/apache profiles are delivered; other modes report `delivery_unsupported`.

## W40-01: haproxy and Kubernetes legs
`bash tests/live/pqc-wave/run-w40.sh` (needs kind) delivers to two ssh haproxy endpoints (one misdirected, rolls back) and a kind TLS Secret; see `docs/release/LIVE_RESULTS_PQC_W40_v1.1.md`.

## Apache and Kubernetes Secret rollback (gap P13)
`bash tests/live/pqc-wave/run-apache-k8s.sh` (needs kind) delivers to an Apache httpd endpoint, rolls back a second Apache and a kind TLS Secret after forced verify failures; see `docs/release/LIVE_RESULTS_PQC_APACHE_K8S_ROLLBACK_v1.1.md`.
