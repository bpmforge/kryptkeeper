# W32-18 recorded results

Stand-in rows are NOT ServiceNow or Jira results. Real-mode rows stay PENDING-RUN until
the credential holder runs `KK_ITSM_MODE=real KK_RECORD=1 bash tests/live/itsm/run.sh`
(env vars in README.md) and pastes the numbers in.

## Run log

| Date | Commit | ITSM side | Result | Notes |
|---|---|---|---|---|
| 2026-10-16 | af96e3f2 + W32-18 | STAND-IN (`stub_itsm.py`) | 33 PASS, 0 FAIL, 2 SKIP | first run; superseded below (recovery was SKIP, events inserted directly) |
| 2026-10-16 | f5db5085 + W32-18 follow-up | STAND-IN (`stub_itsm.py`, now incl. ServiceNow change_request/approval and an F5) | 63 PASS, 0 FAIL, 1 SKIP | real hub on :8098, macOS, about 10 min; connection test route, event_classes arrays, Jira and ServiceNow approval legs through the hub's own `approval_pending` path, recovery via a verified F5 renewal |
| not yet run | | REAL ServiceNow PDI + Jira Cloud | PENDING-RUN | needs instance, itil user, Jira site + API token; see README.md |

## Per-leg status

All "Stand-in" cells are results against `stub_itsm.py`, not ServiceNow or Jira.

| Leg | Acceptance | Stand-in | Real ServiceNow / Jira |
|---|---|---|---|
| 1 setup: credential, connections, no credential leak, event_classes round-trip | | PASS | PENDING-RUN |
| 1a `POST /itsm/connections/{id}/test` ok on both, wrong credential => ok=false, audited | | PASS | PENDING-RUN |
| 2 idempotency: 5 submissions of one id => 1 incident, 1 issue, fields present | 1 | PASS (queue row inserted by the harness) | PENDING-RUN |
| 2b crash-after-create replay adopts the ticket | 1 | PASS (still 1 each) | PENDING-RUN |
| 3j Jira approval via ticket within 2 poll intervals; event and link created by the hub (`approval_pending` path) | 2 | PASS (60 s, limit 125 s; audit `itsm.approval.approve` + `approval.approve` channel itsm) | PENDING-RUN (needs a human to set the status) |
| 3s ServiceNow approval of a `change_request` (approval field + sysapproval_approver, mapped sys_user) | 2 | PASS (60 s, limit 125 s; same audit rows); ticket confirmed a change_request, 0 incidents | PENDING-RUN (needs a human and `KK_SNOW_APPROVER_SYSID`) |
| 3n unmapped approver stays pending, audited `unmapped_approver` (both systems) | 2 | PASS | PENDING-RUN |
| 3p proposer-as-approver negative | 2 | SKIP (proposer is an API-key principal, cannot be a mapped user row; Go unit tests) | SKIP |
| 4 recovery: verified renewal => incident state=6 and issue done within 300 s, resolve comment, rows `resolved`, 2 audit rows | 2 | PASS via a STAND-IN F5 push target (resolved 0 s after the renewal response; limit 300 s) | PENDING-RUN (needs a customer push target) |
| 5 CMDB: 100/100 owners populated, 100 `certificate.ownership_update` audit rows | 2 | PASS | PENDING-RUN (needs 100 CIs loaded into cmdb_ci) |
| 6 outage: 40 events queued, alert raised, 0 tickets, then 0 loss and 0 dupes | 3 | PASS, ACCELERATED (next attempt advanced to now; scheduled 296 s ahead during the outage); the 1-hour wall clock was not run | SKIP (cannot take a real service down) |
| 6f outage held for 1 h wall clock (`KK_ITSM_FULL_OUTAGE=1`) | 3 | PENDING-RUN (about 2 h) | n/a |

Backoff schedule (5 min base, 6 h cap) is proven by Go test `TestDrain_OneHourOutage_ZeroLoss`, not by this harness.
