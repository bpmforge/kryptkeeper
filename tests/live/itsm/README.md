# W32-18: ITSM connectors, approval bridge and CMDB sync, live proof

Drives a real hub (built from this tree, started on `:8098`) against a ServiceNow
Table API and a Jira REST v3 API, in two modes:

| Mode | ITSM side | Status |
|---|---|---|
| `KK_ITSM_MODE=stub` (default) | `stub_itsm.py`, a Python **stand-in** written from the documented API shapes | runs here; results are stand-in results |
| `KK_ITSM_MODE=real` | a ServiceNow Personal Developer Instance and a Jira Cloud site | **PENDING-RUN**: no instance or account was available when this was written |

The stand-in is **not** ServiceNow and **not** Jira. A stand-in PASS proves the hub's
half of the conversation (credential store, egress-guarded connectors, queue,
backoff, approval bridge, CMDB job, audit) against the call shapes the connectors
use. It cannot catch a mismatch between those shapes and the real services; that
is exactly what the real-mode run is for. Never quote a stand-in row as a
ServiceNow or Jira result.

## Files

| File | What |
|---|---|
| `run.sh` | the runbook script (legs below) |
| `stub_itsm.py` | the stand-in: ServiceNow `incident` + `change_request` + `sysapproval_approver` + `cmdb_ci`, Jira issue/transitions/comment/search, an F5 iControl subset with a TLS verify listener, plus `/_ctl/*` controls |
| `seed_hosts.sh` | issues 100 certificates `host-001..100.itsm.test` and (stub) loads 100 CIs |
| `RESULTS.md` | recorded runs; real-mode rows stay PENDING-RUN until a credential holder fills them |

## Run

Stub mode (needs `go`, `python3`, `curl`, `openssl` and a private LAN address; about 10 minutes because the hub's drain ticker is a fixed 60 s):

```
bash tests/live/itsm/run.sh
KK_RECORD=1 bash tests/live/itsm/run.sh     # also appends a row to RESULTS.md
KK_ITSM_FULL_OUTAGE=1 bash tests/live/itsm/run.sh   # holds the outage for a real wall-clock hour
```

The hub's egress guard refuses loopback and the connectors accept plain `http`
only for loopback, so the stand-in serves HTTPS on the Mac's LAN IP
(`KK_ITSM_STUB_HOST` overrides detection, `KK_ITSM_STUB_PORT` the port 9098) and the
hub is started with `SSL_CERT_FILE` pointing at the stand-in's throwaway certificate
(on macOS Go only honours that with `GODEBUG=x509sslcertoverrideplatform=1`, because go.mod's `go 1.26`
defaults the setting to 0; the script sets it).

Real mode (the credential holder runs this; nothing is ever written to git or logs).
Optional `KK_SNOW_APPROVER_SYSID` is the sys_user sys_id of the person who will approve the
ServiceNow change; without it the ServiceNow approval half of leg 3 is PENDING-RUN. Leg 4
is PENDING-RUN in real mode (it needs a push target of your own).

```
export KK_SNOW_URL=https://<instance>.service-now.com   # wake a hibernating PDI first
export KK_SNOW_USER=<itil integration user>
export KK_SNOW_PASSWORD=...
export KK_JIRA_URL=https://<site>.atlassian.net
export KK_JIRA_EMAIL=svc@example.com
export KK_JIRA_TOKEN=<Atlassian API token>
export KK_JIRA_PROJECT=KK
export KK_JIRA_APPROVER_ACCOUNT=<accountId of the human who will approve the ticket>
# optional: KK_JIRA_ISSUE_TYPE (Task) KK_JIRA_APPROVED_STATUS (Approved) KK_JIRA_DONE_STATUS
KK_ITSM_MODE=real KK_RECORD=1 bash tests/live/itsm/run.sh
```

The script refuses to start if any required variable is unset, runs with `set +x`,
never uses `curl -v`, and passes credentials to the hub only through
`POST /api/v1/credentials` (the temporary request file is deleted immediately).
Real mode tags every ticket (`[kk-live]` prefix in the summary) and closes the
ones it made on exit. Before leg 5 load the 100 hosts in `<workdir>/seed/hosts.txt`
into the instance's `cmdb_ci` (fields `fqdn`, `owned_by`, `support_group`); the
script prints the file path. Jira needs a project whose workflow has a status
named like `KK_JIRA_APPROVED_STATUS` and a transition into a status of category done.

## Legs and what each proves

| Leg | Board acceptance | What is asserted |
|---|---|---|
| 1 setup | | credential stored, one connection per system through the real API with `event_classes` as `[{class, ticket_type}]` (ServiceNow `approval_pending` => `change_request`), the response never carries the credential, `POST /itsm/connections/{id}/test` ok on both (stub: a wrong credential reports `ok=false`), `itsm.connection.test` audited |
| 2 idempotency | 1 | one event id submitted 5 times leaves one queue row and exactly 1 incident and 1 issue, each carrying CN, serial, expiry, risk, deep link; a crash-after-create replay (row reset to pending) adopts the ticket via `Find`, still 1 each |
| 3 approval | 2 | approvals raised through `POST /certificates` reach the ITSM by the hub's own `approval_pending` path (rule => delivery worker => `itsm.Channel` => `Submit` => approval link); Jira issue set to the approved status by a mapped accountId, and a ServiceNow `change_request` approved by a mapped sys_user (incident `approval` field + `sysapproval_approver` row), each => hub approval `approved` within 2 x 60 s + 5 s slack, certificate issued, `itsm.approval.approve` and `approval.approve` (channel itsm) audit rows; an unmapped approver leaves the approval pending and is audited `unmapped_approver` |
| 4 recovery | 2 | a verified renewal driven through `POST /renewal/execute` (stand-in F5 push target + TLS verify dial) => the hub calls `ResolveByFingerprint`: incident `state=6`, issue in a done status category, both carrying the resolve comment, within 300 s; queue rows `resolved`, `itsm.ticket.resolve` audited. Stub mode only (PENDING-RUN in real mode: the push target is the customer's) |
| 5 cmdb | 2 | 100 certificates + 100 CIs => 100/100 `ownership_source=cmdb` with owner populated, 100 `certificate.ownership_update` audit rows |
| 6 outage | 3 | ITSM down: 40 events stay queued, none dropped, next attempt about 5 min out, `itsm_unreachable` alert, 0 tickets; ITSM back: all 40 created, each exactly once |

## How events enter the hub

* Legs 2 and 6, and the tickets that leg 4 resolves, are queue rows the harness inserts
  (`INSERT ... ON CONFLICT DO NOTHING`, the statement `Store.InsertEvent` runs). The
  `renewal_failed` / `expiry_no_owner` producers fire from the daily renewal sweep, which
  the harness does not drive.
* Leg 3 uses the hub's own path. The harness adds one enabled `itsm` rule row per
  connection while its approvals are raised, then deletes it. That row is the only direct
  write: `POST /notifications/rules` and the table CHECK both refuse channel `itsm`, so no
  supported way to configure the route exists (finding 1). Everything after it is product
  code, including the approval link (the old harness wrote the link row itself).

## Findings: what the product cannot yet do, so the harness works around it

These are reported, not hidden. Each is why a leg is partial or skipped.

1. **Only `approval_pending` is driven through a notification rule.** Rules with channel
   `itsm` (target = the connection id) are created through `POST /notifications/rules`
   (W32-33). The `renewal_failed` and `expiry_no_owner` producers use the same rules but
   fire from the renewal sweep, so the harness still inserts their queue rows directly.
2. **Auto-resolve is proven only with a stand-in push target.** `ResolveByFingerprint` is
   now called after a verified renewal (W32-26); the harness drives that through a
   stand-in F5 (`stub_itsm.py` serves the iControl calls `agentinstall/f5.go` makes plus a
   TLS listener for the verify dial). A real ssh/F5/Citrix/k8s/IIS target is customer-side.
3. **The connection test runs one read-only `Find`**, so it proves credential, egress and
   connector path but not create/resolve permissions; leg 2 proves create.
4. **No hub-level proposer/approver negative over ITSM** is driven: the proposer in
   this harness is an API-key principal, which cannot also be a mapped user row.
   Unit tests cover it.
5. **The drain ticker (60 s) and CMDB interval (24 h, run at start) have no env knob**,
   so waits are real time and leg 5 restarts the hub to trigger a sync.
6. **Outage drain is accelerated in stub mode** (next attempt advanced to now); the
   5 min .. 6 h schedule itself is proven by `TestDrain_OneHourOutage_ZeroLoss`.
   `KK_ITSM_FULL_OUTAGE=1` holds the outage for a real hour then waits for the natural
   backoff. A real ServiceNow/Jira cannot be taken down on demand, so real mode SKIPs this leg.
7. **Stand-in fidelity limits.** The stand-in does not model Jira issue types (the
   `ticket_type` for Jira is accepted by the hub but not checked on the issue), ServiceNow
   ACLs, or approval rule engines; "approved" is set directly on the record.

## Recorded results

See `RESULTS.md`. Real-mode rows are PENDING-RUN.
