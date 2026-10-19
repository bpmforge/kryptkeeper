# UAT: compose quickstart, timed run (v0.13)

Status: **DRAFT, not final.** The clean-machine run (acceptance 1 of W25-02, US-048 AC1) has not been done. It needs a host with no cached layers and a real network-off restart; both are human-paired. Every `TBD` below is filled only from a real clean run. The smoke-run section records what was actually measured on a warm developer machine and must not be read as the verdict.

## Host (clean run)

| Item | Value |
|---|---|
| OS / arch | TBD |
| Runtime + version | TBD |
| `docker images` / `podman images` empty before start | TBD (must be yes) |
| Network | TBD |

## Procedure

1. `git clone <repo> && cd kryptkeeper`
2. `cp env.example .env`; set `APP_BOOTSTRAP_TOKEN` and `KRYPTKEEPER_KEYSTORE_PASSPHRASE` (they must differ)
3. `KK_TIMINGS_OUT=timings.txt bash tests/live/compose/run.sh` (runs `compose up -d --build`, waits for health, then creates root + issuing CA, issues one cert and runs `openssl verify`), or the manual UI path.

## Results (clean machine)

| Phase | Seconds | Cumulative |
|---|---|---|
| stack_up (`compose up -d --build`) | TBD | TBD |
| hub_healthy | TBD | TBD |
| dashboard_ok | TBD | TBD |
| cert_verified | TBD | TBD |
| offline restart (`down && up -d --pull never`, network off) | TBD | n/a |

Verbatim `openssl verify` output: TBD

Verdict: PASS if cumulative `cert_verified` <= 900 s. **TBD**

## Smoke run (warm machine, NOT the verdict)

Run 2026-10-15, `bash tests/live/compose/run.sh` with `KK_TIMINGS_OUT` set. Host: macOS 27.0.1 arm64, Podman 6.1.3 with docker-compose 5.6.0 as the compose provider. Base images and the Go/Node build caches were already warm, so these numbers understate a clean machine.

```
TIMING: stack_up 166s
TIMING: hub_healthy 206s
TIMING: dashboard_ok 208s
TIMING: cert_verified 213s
/tmp/kk-compose-tls.Q7yO9m/leaf.pem: OK
PASS: openssl verify OK
PASS: wrong CA rejected
ALL PASS
```

Restart without pull or build (egress NOT cut, so this is not the offline proof): `compose up -d --pull never --no-build` after `down` brought the dashboard to HTTP 200 and the hub to `healthy` within 33 s. `docker images` was not empty, and network was not disabled.
