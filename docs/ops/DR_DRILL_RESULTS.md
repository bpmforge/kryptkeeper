# DR drill and rolling-upgrade results

Recorded evidence for the high-availability and disaster-recovery targets. Rows are appended by
the two scripts below with `--record`; an operator reviews the diff before committing. Nothing in
this file is estimated: a column is either a number a script printed or `PENDING-RUN`.

## Committed targets

| Target | Value | Status |
|---|---|---|
| RPO (Postgres async streaming replication, active/passive) | <= 5 min | Committed target. Measured rows below |
| RTO (kill of the active site to first successful issuance on the DR site) | <= 15 min | Committed target. Measured rows below |
| Rolling upgrade, 2 replicas, 50 rps, 10 min | 0 responses in 5xx, 0 duplicate scheduler actions | Committed target. PENDING-RUN, see the upgrade table |

Topology: one active hub with a Postgres 16 primary, plus a cold-standby hub site with a Postgres
16 async streaming replica (`pg_basebackup -R -X stream`). `synchronous_commit` stays at the
default (`on`) with no synchronous standby, so the measured RPO is honest for asynchronous
replication. See [REFERENCE_ARCHITECTURES.md](REFERENCE_ARCHITECTURES.md) and
[DATA_RESIDENCY.md](DATA_RESIDENCY.md); both cite this file and keep their rows labelled
"Committed target" until a passing row exists here.

## Method

- Failover drill: [`tests/live/k8s/dr-failover.sh`](../../tests/live/k8s/dr-failover.sh), podman
  only. A marker writer issues one certificate per second (`dr-marker-<epoch>`) through the active
  hub for the steady period (default 120 s). Then the active hub and the Postgres primary are
  killed back to back (`T_kill`), the standby is promoted, the DR hub is started against it, and
  the first successful issuance on the DR hub ends the clock.
  - `RTO = T_first_201_on_DR - T_kill`.
  - `RPO = T_kill - epoch(last marker present in the DR database)`; the lost-marker count is
    printed alongside. The value has one-second granularity.
  - PASS needs `RTO <= 900 s` and `RPO <= 300 s`.
  - Run: `bash tests/live/k8s/dr-failover.sh --record` (add `--skip-build --image <ref>` to reuse a
    local image).
- Rolling upgrade: [`tests/live/k8s/rolling-upgrade.sh`](../../tests/live/k8s/rolling-upgrade.sh).
  A kind cluster (podman provider) runs BYO Postgres and the chart at `replicaCount=2` on the
  previous release image. Sixty seconds into a 600 s, 50 rps vegeta attack from an in-cluster pod
  (authenticated `GET /api/v1/certificates?limit=25`, never `/readyz`), `helm upgrade --wait`
  rolls the current tree in with the chart's shipped PDB and rolling strategy. Assertions: zero
  5xx, zero transport errors, both pods Ready on the new image, and no duplicate
  `certificate.renew_execute` / `renewal_notification_sent` audit rows since the load began. A
  migration the previous image cannot run against fails the 5xx check; that is the finding and the
  assertion is not weakened. Run: `bash tests/live/k8s/rolling-upgrade.sh --record`.

## Failover drill results

| Date (UTC) | Git sha | Postgres | Replication lag at kill | RPO | RTO | Markers lost | Verdict | Notes |
|---|---|---|---|---|---|---|---|---|
| 2026-10-16 | 0ce44149 | 16.15 | 0.000s / 0 bytes | 1s | 2s | 0 of 119 | PASS | image localhost/kryptkeeper:kkdr-0ce44149; events: BLOCKED: producer missing |
<!-- DR-RESULTS-ROWS -->

## Rolling upgrade results

| Date (UTC) | Git sha | Upgrade | rps | Duration | Requests | 5xx | Duplicate scheduler actions | Verdict |
|---|---|---|---|---|---|---|---|---|
| PENDING-RUN | n/a | n/a | 50 | 600s | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
<!-- UPGRADE-RESULTS-ROWS -->

PENDING-RUN reason (2026-10-16): the authoring host was offline for module and registry access, and
the load generator (vegeta, pinned in the script) was not installed or in the Go module cache. Run
the command above on a host with network access; it needs no credentials, only `kind helm kubectl
podman go`. Replace the placeholder row with the printed one.

## Audit and alert events

The drill asserts `ha.failover` (audit) and `scheduler.failover` / `backup.stale` (alerts) behind
`--require-events` (default on). None of the three has an emitter in `internal/`, `cmd/` or
`charts/` (only `ha.replica_not_ready` exists), so the script prints
`BLOCKED: producer missing` and does not fake them. Board acceptance 3 stays open until a code
ticket adds the emitters (lease takeover emits `ha.failover` and `scheduler.failover`; a
backup-age sweep emits `backup.stale`) and the drill's echo-receiver wiring for the two alerts is
completed.

## Known limits

- **Keystore replication is modelled, not measured.** CA private keys live in the software
  keystore on disk, not in Postgres. The drill bind-mounts one host directory into both sites, which
  assumes the keystore is replicated out of band (for example an RWX volume or cloud KMS). The
  replication lag of that layer adds to RPO and is not measured here. File-backed templates ride
  the same mount. A KMS-backed variant is a follow-up.
- **Async replication can lose the last commits by design.** The RPO column is bounded by
  replication lag at the moment of the kill (sampled once, just before the kill) plus the one-second
  marker cadence, not a guarantee.
- **RTO excludes human detection and decision time.** The clock starts at the kill and covers
  promotion, DR hub start, and the first issuance. A real incident adds paging and the decision to
  fail over.
- **Single-host podman.** Network latency between sites is effectively zero, so replication lag is
  a lower bound on what a cross-region link would show.
- **DR hub reuses the same image as the active hub.** The image reference and tree sha are
  recorded in each row's Notes.
