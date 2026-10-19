# ServiceNow connector (W32-11)

Implements `itsm.Connector` on the ServiceNow Table API (`incident`). Register kind `servicenow`;
the credential-store entry is JSON `{"username":"...","password":"..."}` (basic auth).
`Connector` is also the authenticated client W32-13 (CMDB sync) builds on.

## Required roles
Integration user with `itil` (create/read/update incidents). No admin role needed.
Base URL must be `https://<instance>.service-now.com` (plain http only for loopback tests).

## Field mapping
| Incident field | Value |
|---|---|
| `short_description` | `Certificate renewal failed: <CN>` (`approval_pending` -> "Certificate approval pending", else "Certificate alert") |
| `description` | `CN`, `Serial`, `Expires` (RFC3339), `Risk`, `Link` (deep link), one per line |
| `correlation_id` | `Event.ID` (the idempotency key; looked up by `Find` before every create) |
| `correlation_display` | `Kryptkeeper` |
| `urgency` / `impact` | `2` for risk high/critical, else `3` |
| `category` | `software` |

`TicketRef.Key` is the incident `sys_id`; `TicketRef.URL` is `<base>/nav_to.do?uri=incident.do?sys_id=<id>&number=INCnnnn`.
Resolve is one PATCH: `state=6`, `close_code="Solved (Permanently)"`, `close_notes` and `work_notes` = comment.
Already resolved (6) or closed (7) incidents count as success.

Errors: network, 408, 429, 5xx -> `itsm.ErrTemporary` (a hibernating PDI wake-up rides the queue); other 4xx -> `itsm.ErrPermanent`.

## Ticket types (W32-28)
A class whose `ticket_type` is `change_request` opens a `change_request` record (same mapping, no `category`);
anything else opens an `incident`. The table is part of the ref: `TicketRef.URL` is
`<base>/nav_to.do?uri=change_request.do?sys_id=<id>&number=CHGnnnn`, and `Exists`/`Resolve`/`Approval` read the table
from it (a ref without it is an incident, so rows stored earlier keep working). `Find` has no type, so it searches
`incident` and then `change_request` by correlation id; a 403/404 from the `change_request` search is "no match" so an
integration user without change read access can still open incidents.
Change resolve is one PATCH: `state=3` (Closed), `close_code="successful"`, `close_notes` and `work_notes` = comment;
a change already Closed (3) or Canceled (4) is success. The integration user needs `itil` plus `change_manager`/`itil`
write access to `change_request` to open and close changes.

## Live check (status: PENDING-RUN, stub-only so far)
Needs a ServiceNow Personal Developer Instance and an `itil` integration user.
1. Create the credential in the hub, then a connection `kind=servicenow`.
2. Force a failed renewal 5 times with the same event id; confirm exactly one incident with CN, serial, expiry, risk, link.
3. Complete the renewal; confirm state=Resolved within 5 minutes.
4. Record the instance version and date in the PR.
Unit coverage runs against an httptest stub: `go test ./internal/notifications/itsm/servicenow/...`.
