# W22-08: live SIEM UAT

Proves the hub's SIEM forwarding reaches real receivers in all three wire
forms within 5 s, and that a dead receiver is counted as a failure without
losing the audit row.

```
bash tests/live/siem/run.sh
```

Needs `podman` (skips with exit 0 when absent unless `KK_UAT_REQUIRE=1`) and
network access to pull the pinned images on first run. Prints
`[siem-uat] PASS=<n> FAIL=<m>`, exits 1 on any FAIL. `KK_UAT_KEEP=1` keeps the
work dir (hub log, syslog file). `KK_SIEM_HOST_IP` overrides the private
address used for the Elasticsearch webhook (default: `en0`).

## Topology

| Piece | Image / process | Bind |
|---|---|---|
| Elasticsearch (webhook receiver) | `docker.io/elastic/elasticsearch:8.15.3`, single-node, security off | host private IP, free port |
| Syslog collector | `docker.io/linuxserver/syslog-ng:4.11.0-r0-ls211`, TCP, writes raw lines | `127.0.0.1`, free port |
| Hub | built from this tree, throwaway data dir and token | `127.0.0.1`, free port |

Containers are named `kk-w22-siem-*`, removed by an exit trap, and the work dir
lives under `$HOME` (podman on macOS only mounts `/Users`).

## Phases

1. `SIEM_FORMAT=json`, webhook to Elastic plus syslog/tcp. Asserts the doc in
   `siem-uat` (`event_type=role.create`, `resource_type`, `resource_id`,
   `severity`, `timestamp`) and the RFC 5424 line, each timed from just before
   the triggering `POST /api/v1/roles`.
2. `SIEM_FORMAT=cef`, syslog only (the CEF webhook body is `text/plain`, which
   Elasticsearch rejects). Asserts a `CEF:0|` line with the RFC 5424 header.
3. Back to json; both receivers are removed. Asserts
   `kryptkeeper_siem_send_failures_total` rises and the `role.create` audit
   rows from before and after the kill are still listed.

## Deviations and findings

- **Splunk HEC was not exercised.** The hub sends `SIEM_WEBHOOK_TOKEN` as
  `Authorization: Splunk <token>`; no token is set here, so that header path
  is covered only by the W19-07 stand-in.
- **Syslog image.** The spec's rsyslog tag does not exist and
  `balabit/syslog-ng:4.8.0` is amd64-only (segfaults under qemu on Apple
  Silicon), so the multi-arch linuxserver build is used.
- **Elastic is published on a private IP, not loopback.** The hub's egress
  guard refuses loopback webhook destinations (`egressAllowLoopback` is a
  Go-test-only seam; the run log shows `egress: destination blocked:
  127.0.0.1`). A loopback SIEM URL therefore cannot work in production either;
  reported, not fixed. The ES port is reachable from the local network for the
  duration of a run (empty throwaway index, no secrets).
- **RFC 5424 regex.** The spec's `... role_create - ` matches only the CEF form;
  the json form carries `[kryptkeeper@99999 ...]` structured data after the
  msgid, so the harness accepts `-` or that SD-ID.
- **Latency is load dependent.** Observed 0.05 s to 3.3 s; one run on a busy
  machine (full Go suite running) missed the 5 s budget for both receivers
  before a rerun passed. The harness keeps polling 25 s past the budget so a
  miss reports a real latency rather than a bare timeout.
