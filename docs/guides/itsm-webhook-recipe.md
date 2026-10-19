# Alerts into ServiceNow or Jira with the signed webhook

Kryptkeeper's native ITSM connectors are not required to get alerts into a
ticketing system. The hub already sends a signed webhook; a small receiver
verifies it and calls the ticket tool's REST API. This recipe is that receiver,
with the two ticket flows. It uses only Python 3 (standard library) and `curl`.

Read [`docs/ops/WEBHOOK_VERIFY.md`](../ops/WEBHOOK_VERIFY.md) first. It is the
reference for the headers and the signature, and the verifier below is the same
logic.

## 1. When to use this

Use it when you want alert tickets today and the connector path (ticket
creation, status sync and approval mapping) is not enabled in your deployment.
What you get: one ticket per alert event, safe against retries and replays.
What you do not get: ticket status flowing back into Kryptkeeper (see
[section 6](#6-approval-round-trip-is-manual-in-this-mode)).

Prerequisites:

- A running hub and an admin bearer token, exported as `$KK_TOKEN`.
- A host that can run Python 3 and be reached by the hub over HTTP(S), and can
  reach your ServiceNow instance or Jira site. Put TLS in front of it in
  production; the hub only needs the URL.
- A shared secret: `export WEBHOOK_SECRET="$(openssl rand -hex 32)"`.

## 2. Configure the hub

Set the receiver URL and the signing secret as runtime settings (both are
write-only secrets). `HUB` is your hub base URL, for example `https://hub.example.com`.

```bash
curl -sS -X PUT "$HUB/api/v1/config/notifications.webhook_url" \
  -H "Authorization: Bearer $KK_TOKEN" -H 'Content-Type: application/json' \
  -d '{"value":"https://bridge.example.com/kk"}'
curl -sS -X PUT "$HUB/api/v1/config/notifications.webhook_secret" \
  -H "Authorization: Bearer $KK_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"value\":\"$WEBHOOK_SECRET\"}"
```

Each answers `204`. The receiver must not be a loopback address: the hub's
outbound guard refuses `127.0.0.1` for webhooks ("egress: destination blocked").
Private LAN addresses are allowed. The same settings are on the Integrations page. They take
effect on the next send, with no restart. Without a secret the hub still sends
the timestamp and event id headers but no signature, and the receiver below
rejects those.

Every delivery carries three headers, which the verifier uses:

| Header | Use |
|---|---|
| `X-Kryptkeeper-Timestamp` | Unix seconds; part of the signed message |
| `X-Kryptkeeper-Event-Id` | Stable across retries; the dedupe key |
| `X-Kryptkeeper-Signature` | `v1=<hex>[,v1=<hex>]`, HMAC-SHA256 over `timestamp + "." + raw body` |

## 3. The verifier

Python, standard library only. It signs and checks the exact raw bytes, rejects
unsigned and stale (more than 300 s) requests, compares in constant time and
accepts any `v1=` entry, which is what makes a secret rotation work: during the
24-hour window the hub sends `v1=<new>,v1=<previous>`, so a receiver holding
either secret still verifies.

```python
import hmac, hashlib, time

def verify_webhook(secret: bytes, headers, body: bytes, now=None) -> bool:
    sig = headers.get("X-Kryptkeeper-Signature")
    if not sig:
        return False
    ts = headers.get("X-Kryptkeeper-Timestamp", "")
    try:
        ts_int = int(ts)
    except ValueError:
        return False
    if abs((now or time.time()) - ts_int) > 300:
        return False
    want = "v1=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(p.strip(), want) for p in sig.split(","))
```

The bridge below wraps it. `TICKET_TARGET` selects `servicenow` or `jira`;
`TICKET_API` is the instance base URL; `TICKET_AUTH` is the full
`Authorization` header value for the ticket tool. To accept both secrets during
a rotation, give `WEBHOOK_SECRET` the new one and add the previous value as
`WEBHOOK_SECRET_PREVIOUS`; the loop in `do_POST` tries each.

Save as `itsm_bridge.py`:

```python
import json, os, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
# verify_webhook() from above goes here, unchanged.

SECRETS = [os.environ["WEBHOOK_SECRET"].encode()]
if os.environ.get("WEBHOOK_SECRET_PREVIOUS"):
    SECRETS.append(os.environ["WEBHOOK_SECRET_PREVIOUS"].encode())
TARGET, API, AUTH = os.environ["TICKET_TARGET"], os.environ["TICKET_API"].rstrip("/"), os.environ["TICKET_AUTH"]
SEEN = set()  # in-memory; the ticket-side lookup below survives restarts

def call(method, path, body=None):
    req = urllib.request.Request(API + path, method=method, headers={
        "Authorization": AUTH, "Accept": "application/json", "Content-Type": "application/json"},
        data=None if body is None else json.dumps(body).encode())
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read() or b"{}")

def exists(event_id):
    if TARGET == "servicenow":
        q = urllib.parse.quote("correlation_id=" + event_id)
        return bool(call("GET", f"/api/now/table/incident?sysparm_query={q}&sysparm_limit=1").get("result"))
    q = urllib.parse.quote(f'labels = "kk-{event_id}"')
    return bool(call("GET", f"/rest/api/3/search/jql?jql={q}&maxResults=1").get("issues"))

def create(event_id, ev):
    title, text = ev.get("Subject") or "Kryptkeeper alert", ev.get("Message", "")
    if TARGET == "servicenow":
        return call("POST", "/api/now/table/incident", {
            "short_description": title, "description": text, "correlation_id": event_id})
    adf = {"type": "doc", "version": 1, "content": [
        {"type": "paragraph", "content": [{"type": "text", "text": text or title}]}]}
    return call("POST", "/rest/api/3/issue", {"fields": {
        "project": {"key": os.environ["JIRA_PROJECT"]}, "issuetype": {"name": "Task"},
        "summary": title, "description": adf, "labels": [f"kk-{event_id}"]}})

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if not any(verify_webhook(s, self.headers, body) for s in SECRETS):
            return self.reply(401, b'{"error":"bad signature"}')
        event_id = self.headers["X-Kryptkeeper-Event-Id"]
        if event_id in SEEN or exists(event_id):
            return self.reply(200, b'{"status":"duplicate"}')
        create(event_id, json.loads(body))
        SEEN.add(event_id)
        self.reply(200, b'{"status":"created"}')

    def reply(self, code, payload):
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(payload)

ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "9195"))), Handler).serve_forever()
```

A non-2xx answer makes the hub retry, so the bridge answers `401` for a bad
signature and lets an API error from the ticket tool surface as a `5xx`
(retried). A duplicate answers `200` so the hub stops retrying.

### Check the receiver by hand

With the bridge running on port 9195 (section 4 or 5), send it signed and
unsigned events without the hub. `--data-binary` keeps the body byte-for-byte,
which the signature depends on.

```bash
BODY='{"ID":"evt-demo-1","Subject":"Certificate expiring","Message":"api.example.com expires in 7 days","Priority":"high"}'
TS=$(date +%s)
SIG=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print $NF}')

# signed: expect 200 {"status":"created"}; run it again for {"status":"duplicate"}
curl -sS -w ' -> %{http_code}\n' -X POST http://127.0.0.1:9195/kk \
  -H "X-Kryptkeeper-Timestamp: $TS" -H "X-Kryptkeeper-Event-Id: evt-demo-1" \
  -H "X-Kryptkeeper-Signature: v1=$SIG" --data-binary "$BODY"

# unsigned: expect 401
curl -sS -w ' -> %{http_code}\n' -X POST http://127.0.0.1:9195/kk \
  -H "X-Kryptkeeper-Timestamp: $TS" -H "X-Kryptkeeper-Event-Id: evt-demo-2" --data-binary "$BODY"

# stale (10 minutes old, correctly signed for that timestamp): expect 401
OLD=$(( $(date +%s) - 600 ))
SIG=$(printf '%s.%s' "$OLD" "$BODY" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print $NF}')
curl -sS -w ' -> %{http_code}\n' -X POST http://127.0.0.1:9195/kk \
  -H "X-Kryptkeeper-Timestamp: $OLD" -H "X-Kryptkeeper-Event-Id: evt-demo-3" \
  -H "X-Kryptkeeper-Signature: v1=$SIG" --data-binary "$BODY"

# rotation: two signatures, new first; the bridge still holds only the old secret: expect 200
NEW_SECRET=$(openssl rand -hex 32); TS=$(date +%s)
S_NEW=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$NEW_SECRET" | awk '{print $NF}')
S_OLD=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print $NF}')
curl -sS -w ' -> %{http_code}\n' -X POST http://127.0.0.1:9195/kk \
  -H "X-Kryptkeeper-Timestamp: $TS" -H "X-Kryptkeeper-Event-Id: evt-demo-4" \
  -H "X-Kryptkeeper-Signature: v1=$S_NEW,v1=$S_OLD" --data-binary "$BODY"
```

To see what the hub itself sends, use the product's test endpoint, then look at
your ticket tool or the receiver log:

```bash
curl -sS -X POST "$HUB/api/v1/notifications/test-delivery" \
  -H "Authorization: Bearer $KK_TOKEN" -H 'Content-Type: application/json' \
  -d '{"channel":"webhook","target":"unused","message":"hello from the hub"}'
```

The body the hub signs is the notification event as JSON with the fields `ID`,
`Channel`, `Target`, `Subject`, `Message`, `Priority` and `CreatedAt`.

## 4. ServiceNow flow

```bash
export TICKET_TARGET=servicenow
export TICKET_API=https://example.service-now.com
export TICKET_AUTH="Basic $(printf '%s:%s' "$SN_USER" "$SN_PASSWORD" | base64)"
python3 itsm_bridge.py
```

1. The hub POSTs the signed alert to the bridge.
2. The bridge verifies it, then looks the event up with
   `GET /api/now/table/incident?sysparm_query=correlation_id=<event id>`. If an
   incident exists it stops.
3. Otherwise it creates one: `POST /api/now/table/incident` with
   `short_description`, `description` and `correlation_id` set to the event id.
   `correlation_id` is the idempotency key, so a retry or a replay cannot make a
   second incident. Add `caller_id` or `assignment_group` to the body in
   `create()` if your instance requires them.
4. Resolve the incident from your own process or by hand:

```bash
curl -sS -X PATCH "$TICKET_API/api/now/table/incident/$SYS_ID" \
  -H "Authorization: $TICKET_AUTH" -H 'Content-Type: application/json' \
  -d '{"state":"6","close_code":"Solved (Permanently)","close_notes":"Certificate renewed"}'
```

`state` 6 is Resolved on a stock instance, and the `close_code` strings are
instance-specific. Verify both in your tenant. Use a service account limited to
the `incident` table.

## 5. Jira flow

```bash
export TICKET_TARGET=jira
export TICKET_API=https://example.atlassian.net
export JIRA_PROJECT=OPS
export TICKET_AUTH="Basic $(printf '%s:%s' "$JIRA_EMAIL" "$JIRA_API_TOKEN" | base64)"
python3 itsm_bridge.py
```

1. The hub POSTs the signed alert to the bridge, which verifies it.
2. Dedupe: the bridge searches for the label `kk-<event id>` with
   `GET /rest/api/3/search/jql?jql=labels = "kk-<event id>"`.
3. Otherwise it creates the issue with `POST /rest/api/3/issue`. The
   description must be Atlassian Document Format (the `adf` object above), and
   the same `kk-<event id>` label is the idempotency key.
4. Resolve: list the transitions, then post the one whose name means done.

```bash
curl -sS "$TICKET_API/rest/api/3/issue/$ISSUE_KEY/transitions" -H "Authorization: $TICKET_AUTH"
curl -sS -X POST "$TICKET_API/rest/api/3/issue/$ISSUE_KEY/transitions" \
  -H "Authorization: $TICKET_AUTH" -H 'Content-Type: application/json' \
  -d '{"transition":{"id":"31"}}'
```

The transition id (`31` here) comes from the first call and differs per
workflow. Jira Cloud search endpoints and field requirements change; confirm
them against your site's API docs. Never put the API token in a command line
you share.

## 6. Approval round trip is manual in this mode

A ticket being approved or closed does **not** call Kryptkeeper. The person who
approves a renewal still approves it in the Kryptkeeper UI. Only the connector
path maps ticket approval back to Kryptkeeper; this recipe is one-way, from
Kryptkeeper to the ticket.

## 7. Verified run (recorded)

Every command above was run once on 2026-10-16 against the hub built from
commit `60558730`, with `tests/live/notifications/echo_receiver.py` standing in
for the ServiceNow instance and the Jira site. The echo receiver records the
request shape the bridge sends; it does not behave like either product, so this
proves the signing, verification, dedupe and request construction, not a
live-instance ticket. Live-instance proof is tracked as W32-18.

Environment: hub on `127.0.0.1:8199` (`AUTH_MODE=bootstrap`,
`KRYPTKEEPER_TLS_DISABLE=true`, `APP_NOTIFICATION_PROVIDER=delivery`, the same
variables as `tests/live/notifications/run.sh`); echo receiver on
`127.0.0.1:9194`; bridge on `127.0.0.1:9195`. This build refuses loopback receiver
URLs for webhooks (row 2), so the hub was pointed at the host's LAN address
(`$LAN_IP`, shown as a variable) instead. `tests/live/notifications/run.sh`
itself could not be run here: it publishes Mailpit on privileged port 587, which
rootless podman on this machine refuses, so its webhook step was run by hand as
below. All rows passed.

| # | Step | Command (abridged; full text in the section named) | Observed |
|---|---|---|---|
| 1 | Start the echo receiver (stands in for the instance) | `python3 tests/live/notifications/echo_receiver.py echo.jsonl 9194` | Listening on `127.0.0.1:9194`; `curl http://127.0.0.1:9194/x` returns `{"ok":true}` |
| 2 | Hub sends to a loopback URL (section 2 note) | `PUT notifications.webhook_url` = `http://127.0.0.1:9194/webhook`, then `POST /api/v1/notifications/test-delivery` | Hub log: `egress: destination blocked: 127.0.0.1` on every attempt; nothing reaches the receiver. A stock install refuses loopback. |
| 3 | Hub sends to a LAN URL; all three headers (section 2) | Same, URL `http://$LAN_IP:9196/webhook` (a 15-line TCP forwarder exposes the loopback-only echo receiver on the LAN address) | `204`, `204`; test-delivery `status":"queued","dispatched":true`; receiver log: `POST /webhook` with `x-kryptkeeper-event-id: notif-1792201479396988000`, `x-kryptkeeper-timestamp: 1792201479`, `x-kryptkeeper-signature: v1=af6fbca1...9337` and body `{"ID":"notif-1792201479396988000","Channel":"webhook","Target":"unused","Subject":"Kryptkeeper notification","Message":"guide-marker-1",...}` |
| 4 | Set the signing secret (section 2) | `PUT notifications.webhook_secret` | `204` |
| 5 | Start the bridge in ServiceNow mode (section 4) | `TICKET_TARGET=servicenow TICKET_API=http://127.0.0.1:9194 ... python3 itsm_bridge.py` | Serving on `:9195` |
| 6 | Correctly signed event (section 3, "signed") | `curl ... -H "X-Kryptkeeper-Signature: v1=$SIG" --data-binary "$BODY"` | `{"status":"created"} -> 200`. Receiver log: `GET /api/now/table/incident?sysparm_query=correlation_id%3Devt-demo-1&sysparm_limit=1`, then `POST /api/now/table/incident` body `{"short_description": "Certificate expiring", "description": "api.example.com expires in 7 days", "correlation_id": "evt-demo-1"}` |
| 7 | Repeated event id (dedupe) | the same command again | `{"status":"duplicate"} -> 200`; no new request at the receiver |
| 8 | Unsigned event | no `X-Kryptkeeper-Signature` header | `{"error":"bad signature"} -> 401` |
| 9 | Stale event (600 s old, validly signed) | `OLD=$(( $(date +%s) - 600 ))` ... | `{"error":"bad signature"} -> 401` |
| 10 | Rotation, two signatures | `X-Kryptkeeper-Signature: v1=$S_NEW,v1=$S_OLD` | `{"status":"created"} -> 200` (the receiver holds only the old secret) |
| 11 | Hub to bridge to ServiceNow, end to end (section 4) | `PUT notifications.webhook_url` = `http://$LAN_IP:9195/kk`, then `test-delivery` (message `guide-marker-sn`) | Receiver log: `GET .../incident?sysparm_query=correlation_id%3Dnotif-1792201507344555000...`, then `POST /api/now/table/incident` with `"correlation_id": "notif-1792201507344555000"` and `"description": "guide-marker-sn"` |
| 12 | ServiceNow resolve (section 4) | `curl -X PATCH "$TICKET_API/api/now/table/incident/$SYS_ID" ... -d '{"state":"6",...}'` | `{"ok":true}`; receiver log: `PATCH /api/now/table/incident/abc123` with the `state`, `close_code` and `close_notes` body. (`echo_receiver.py` answers only GET and POST, so this row used its own `Handler` with `do_PATCH` added, in a throwaway wrapper.) |
| 13 | Bridge in Jira mode, hub end to end (section 5) | `TICKET_TARGET=jira ... JIRA_PROJECT=OPS python3 itsm_bridge.py`, then `test-delivery` (message `guide-marker-jira`) | Receiver log: `GET /rest/api/3/search/jql?jql=labels%20%3D%20%22kk-notif-1792201513517138000%22&maxResults=1`, then `POST /rest/api/3/issue` with project `OPS`, an ADF `description` containing `guide-marker-jira` and `"labels": ["kk-notif-1792201513517138000"]` |
| 14 | Jira transitions (section 5) | `curl .../issue/$ISSUE_KEY/transitions`, then `curl -X POST ... -d '{"transition":{"id":"31"}}'` | `{"ok":true}` twice; receiver log: `GET /rest/api/3/issue/OPS-1/transitions`, `POST /rest/api/3/issue/OPS-1/transitions` body `{"transition":{"id":"31"}}` |

Not exercised: the ticket tool's own answers (the echo receiver returns
`{"ok":true}` to everything, so the server-side duplicate lookup in `exists()`
never finds a ticket here; the in-memory `SEEN` set did the deduping in row 7),
and the secret rotation on the hub side (row 10 sends the two signatures by
hand; the hub's own rotation is covered in `WEBHOOK_VERIFY.md`).

