# HA chaos harness (W23-28) and soak (W23-29)

Two hub replicas on one Postgres 16 and one keystore volume, podman only.

```bash
bash tests/live/ha/run.sh                 # chaos, about 4 minutes after the image exists
bash tests/live/ha/run.sh --skip-build    # reuse localhost/kryptkeeper:kkha-w23
bash tests/live/ha/run.sh --keep          # leave the stack up (ports 18081 A, 18082 B, 55432 Postgres)
```

`run.sh` generates the Postgres password, bootstrap token and keystore
passphrase, starts Postgres, then A (the only replica with
`KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT`), waits until A holds the
`renewal-scheduler` lease row, then starts B. It tears the project down with
its volumes on exit. `go test ./...` never starts any of this: every test skips
unless `KK_LIVE_HA=1` (chaos) or `KK_HA_SOAK=1` (soak).

## What the chaos tests check

1. `TestHAConcurrentIssuanceNoDuplicateSerials`: 8 workers, 400 issuances split
   across A and B, at least 99% must be 201, no transport failures, then
   `GROUP BY ca_id, serial_number HAVING COUNT(*) > 1` returns no rows and
   `idx_cert_serial_ca` exists.
2. `TestHALeaseTakeoverAfterKill`: `podman kill -s KILL` on A (the lease
   holder), B keeps issuing, the `renewal-scheduler` row must change holder.
   The bound is `3 x poll + 10 s` (190 s at `RENEWAL_POLL_MINUTES=1`): the
   lease is `max(2 x poll, 1 min)` and the standby retries on its own tick, so
   the board's "within 2x poll" is the lease length, not the worst case. The
   measured value is logged.
3. `TestHANoDuplicateRenewalsOrAlerts`: no `predecessor_fingerprint` shared by
   two certificates and no duplicate non-rule `renewal_notification_sent`
   success per certificate. The log prints how many rows the queries examined.
4. `run.sh` restarts A and checks `/readyz` 200 on both.

## What this does NOT prove

- The duplicate-renewal and duplicate-alert checks are close to vacuous here:
  the certificates are 30 days old at most, the scheduler only renews
  certificates with a managed target, and no notification channel is
  configured, so the queries normally examine 0 rows. They would catch a
  duplicate if one were written (checked by hand on seeded duplicates), and the
  serial check is the substantive one.
- Plain HTTP (`KRYPTKEEPER_TLS_DISABLE`), loopback, one machine.
- Postgres here is a single instance. A failover is simulated in the soak, not
  a promotion.
- The compose file departs from a stock install in three ways the product
  needs for two replicas; each is a real finding, see
  `docs/release/HA_SOAK_v0.11.md`:
  `max_connections=300` (one hub holds about 60 idle connections, so two exceed
  Postgres' default of 100), a shared `templates.json` volume (the template
  store has only a file provider, so templates do not replicate through
  Postgres), and a root-owned-volume chown init container (the image runs as
  uid 65532).
- `APP_TRUSTED_PROXY_CIDRS` trusts the podman gateway so the soak prober can
  send a distinct `X-Forwarded-For`; the per-IP CRL/OCSP rate limits
  (30/min, 200/min) are therefore not exercised.

## Soak (W23-29)

```bash
bash tests/live/ha/run.sh --soak --skip-build           # full: about 32 to 37 minutes
bash tests/live/ha/run.sh --soak --short --skip-build   # plumbing dry-run, about 90 s
```

Writes `soak-result.json` (counts, timings, per-criterion pass/fail, the
injector log, `/readyz` status changes, load average samples) and `soak.log`
(gitignored). The numbers in `docs/release/HA_SOAK_v0.11.md` are copied from
that JSON.

Timeline from the start of the timed phase (after 50 probe serials are issued
and primed on both replicas): 8 workers pace 10,000 issuances at one per 180 ms
through a client-side balancer that only uses replicas whose last `/readyz`
(probed every second) was 200; `t=8m` SIGKILL replica A, `t=9m` start it;
`t=15m` abrupt Postgres restart (`podman restart -t 0`); `t=22m` disconnect B
from the database network, reconnect at `t=23m30s`; `t=5,10,...,30m` revoke a
fresh certificate on A and poll B's `/ocsp` every second until it reads
Revoked. Every 500 ms a prober fetches the CRL and asks OCSP for one of the 50
primed serials.

Availability is reported for three paths: via the readiness-gated balancer
(the pass criterion, as specified), directly to either replica with one
failover (an L4 balancer that does not use `/readyz`), and OCSP for serials
nobody has queried before (the database path, a known limit).

## What the soak does NOT prove

- The Postgres "failover" is an abrupt restart of one instance: connections
  drop and in-flight transactions abort, but there is no standby and no
  promotion. Postgres HA is bring-your-own.
- The primed OCSP set is only primed until the next revocation: any revoke on
  either replica changes the stamp and both replicas drop their whole OCSP
  response cache, so those serials then need the database again.
- A replica refuses to start while Postgres is down (`core database
  unavailable`), so the harness never restarts A during the Postgres restart;
  under an orchestrator this is a restart loop, not an outage of the other
  replica.
- The machine is shared and loaded; the JSON records the load average. Rerun
  on the target hardware before quoting numbers elsewhere.
