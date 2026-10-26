# Writing a plugin

A plugin is a WebAssembly module the hub runs in a sandbox. Its `kind` (D-321)
says what it does; this guide is written for the **delivery** kind, which
installs renewed certificates on a device Kryptkeeper has no built-in support
for, and the section [Plugin kinds](#plugin-kinds) says how the others differ. The design and the rules it runs under are in
[`docs/design/DELIVERY_PLUGINS.md`](../design/DELIVERY_PLUGINS.md).

## 1. Start from the example

Copy [`plugins/example`](../../plugins/example). It is a complete plugin for
a simple HTTPS device API: `main.go`, `manifest.json` and `go.mod`.

## 2. Implement three operations

```go
func init() { delivery.Register(myDevice{}) }

func (myDevice) Validate(h *delivery.Host, req abi.ValidateRequest) error
func (myDevice) Push(h *delivery.Host, req abi.PushRequest) (abi.PushResult, error)
func (myDevice) Rollback(h *delivery.Host, req abi.RollbackRequest) (abi.RollbackResult, error)
```

### Validate

Checks reachability and permissions without changing anything.

### Push

Uploads and binds the certificate.
- **Outcome:** report one of the outcomes in `abi` (`installed`,
  `write_failed`, `binding_failed`, ...).
- **RollbackHandle:** return what Rollback needs to restore the previous
  state, for example the previous certificate's name.
- **Verified:** you cannot set it. The hub checks what the device serves.

### Rollback

Restores the state that the RollbackHandle describes. Set `RolledBack`
only if the device really is back. The operator is told exactly what you
report.

## 3. Reach the device through the Host only

| Call | Needs |
|---|---|
| `h.HTTP` | `network` in the manifest. HTTPS only, to the credential's host or listed hosts. |
| `h.Run`, `h.WriteFile`, `h.ReadFile`, `h.Exists` | `remote_exec`, plus `file_write` paths. Escalation also needs `elevated_exec` (see below). |
| `h.Logf` | Nothing. Lines are capped, PEM blocks are withheld, and credential secrets are redacted. |

Without `elevated_exec`, `h.Run` refuses (a) privilege-escalation programs
by basename, however the path is spelled: `sudo`, `doas`, `su`, `pkexec`,
`runuser`, `setpriv`, `chroot`, `nsenter`; (b) shells and interpreters given an
inline command (`sh -c`, `bash -lc`, `python3 -c`, `perl -e`, `ruby -e`,
`node -e`, `cmd /c`, `powershell -Command`); and (c) wrappers that launch
either (`env sudo ...`, `busybox sh -c ...`, `nohup`, `timeout`, `xargs`, ...).
Exec a concrete program with an argv (`nginx -t`, `systemctl reload nginx`), or
declare `elevated_exec` so the operator approves it.

The plugin has no filesystem, environment or sockets of its own. Anything
the manifest does not declare is refused, and the operator sees every
capability before approving the plugin.

## 4. Build and test

```bash
GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o plugin.wasm .
```

Then grade the plugin with the conformance kit:

1. Write a mock of your device that implements `conformance.Device`.
2. Run `conformance.Suite` against it. See
   `tests/plugins/conformance/exampledevice_test.go`.

The suite checks verified delivery, rollback on a verify mismatch, honest
reporting of a failed rollback, and that upload and bind failures leave the
device unchanged.

## 5. Publish

Set `artifact.sha256` in `manifest.json` to the SHA-256 of the built
`plugin.wasm`. The hub refuses a module that does not match.

## Plugin kinds

`kind` in `manifest.json` says which operations the hub will ask of a plugin.
It defaults to `delivery` when absent, so every manifest written before kinds
existed is still valid. The hub refuses an operation the kind does not define
before it starts the module, and refuses `issuer` (reserved for 1.2) and any
kind it has no operations for yet.

| Kind | Operations | Runs today | Package |
|---|---|---|---|
| `delivery` | `validate`, `push`, `verify`, `rollback` | yes | `sdk/delivery-go/delivery` |
| `notify` | `notify.send` | yes | `sdk/delivery-go/notify` |
| `ticket` | `ticket.create`, `ticket.exists`, `ticket.resolve` | yes | `sdk/delivery-go/ticket` |
| `dns01` | defined by W38-08 | no | |

| `ticket` | defined by W38-09 | no | |
| `dns01` | `dns01.present`, `dns01.cleanup` | yes | `sdk/delivery-go/dns01` |
| `inventory` | defined by W38-05 and W38-09 | no | |
| `credentials` | `credentials.get` | yes | `sdk/delivery-go/credentials` |

Every kind runs in the same sandbox and keeps the same guarantees: https only
to granted hosts, 128 MiB of memory, a deadline per call, a fresh instance for
each operation, and credential values redacted from anything the plugin says.
Only a `delivery` plugin may declare `receive_private_key`, `trust_store`,
`remote_exec`, `elevated_exec` or `file_write`; every other kind must declare a
`network` grant and gets nothing that touches a private key or a managed host.

`provide_credentials` is a Critical capability that belongs to the `credentials`
kind alone: "This plugin returns credentials the hub uses to log in to your systems."
A credentials plugin must declare it and every other kind is refused if it does,
so enabling a credentials plugin always needs a second person.

The SDK module is still `github.com/bpmforge/kryptkeeper/sdk/delivery-go`
(D-321); the plugin kinds are packages inside it.

### The notify kind

A notify plugin delivers one alert to a chat or incident service. Start from
[`plugins/pagerduty`](../../plugins/pagerduty).

```go
func init() { notify.Register(myService{}) }

func (myService) Send(h *delivery.Host, req abi.NotifySendRequest) (abi.NotifySendResult, error)
```

The request carries `event_class`, `severity` (`critical`, `high`, `medium`,
`low`), `title`, `body`, `fields` (non-secret context rows), `deep_link` and
`dedupe_key`. The result is `delivered`, `provider_id` and
`retry_after_seconds`.

- Return `Delivered: false` with a short reason (use `notify.Refused`, which
  never echoes the response body) when the service answers but does not take
  the alert, and an error for a transport failure. The hub treats both as a
  failed channel delivery.
- An `event_class` ending in `.resolved` (`abi.ResolvedSuffix`) means "clear
  the alert with this `dedupe_key`". Services that can close an alert (PagerDuty
  resolve, Opsgenie close) should; chat services post it as one more message.
- Keep `dedupe_key` stable into the service's own de-duplication field, so a
  retry folds into one alert.
- Read `Retry-After` with `notify.RetryAfter` and return it as
  `retry_after_seconds`.
- Declare `network` with `hosts_from_credential` naming a url field of
  `credential_schema`, mark keys and webhook URLs `secret`, and declare no
  `receive_private_key`. Webhook URLs usually carry their credential, so mark
  them secret and never log them.
- Grade it with `conformance.NotifySuite` against a mock of the service; see
  `tests/plugins/conformance/notify_test.go`. The suite checks delivery, repeat
  de-duplication, resolve, a 5xx, a 429 with `Retry-After`, and that no
  credential or PEM block appears in events, results or errors.

Operators route alerts to it with a notification rule on channel `plugin`;
see [`docs/ops/NOTIFICATION_PLUGINS.md`](../ops/NOTIFICATION_PLUGINS.md).

### The ticket kind

A ticket plugin opens, checks and closes tickets in an ITSM or help desk. Start
from [`plugins/zendesk`](../../plugins/zendesk). It mirrors the hub's native
connector, minus approvals (D-326).

```go
func init() { ticket.Register(myDesk{}) }

func (myDesk) Create(h *delivery.Host, req abi.TicketCreateRequest) (abi.TicketCreateResult, error)
func (myDesk) Exists(h *delivery.Host, req abi.TicketExistsRequest) (abi.TicketExistsResult, error)
func (myDesk) Resolve(h *delivery.Host, req abi.TicketResolveRequest) (abi.TicketResolveResult, error)
```

| Op | Request (besides the credential) | Result |
|---|---|---|
| `ticket.create` | `event`: `id`, `class`, `cn`, `serial`, `risk`, `deep_link`, `fingerprint`, `not_after`, `ticket_type` | `key`, `url` |
| `ticket.exists` | `key`, `url` | `exists` |
| `ticket.resolve` | `key`, `url`, `comment` | none |

- Every result may carry a failure: `failure` (`temporary` or `permanent`),
  `detail` and `retry_after_seconds`. Use `ticket.Failed(resp, why)`, which
  classifies 408, 429 and 5xx as temporary and every other non-success as
  permanent, reads `Retry-After`, and never echoes the response body (services
  reflect requests, and the request carries the credential). The hub retries a
  temporary failure on the ITSM queue's backoff and marks the event failed on a
  permanent one. A plugin that returns an error instead is retried as temporary.
- `create` returns a `key` the service will accept again in `exists` and
  `resolve`. A result without a key is a permanent failure. `url` is kept only if
  it is plain https. Stamp `event.id` on the ticket (Zendesk `external_id`, a tag)
  so a person can trace it back.
- `exists` must answer `{exists:false}`, not a failure, for a ticket that is gone
  (404, or a deleted or trashed flag) and for the probe key `abi.ProbeTicketKey`
  (`"0"`), which the hub sends for "test connection". A refused credential or an
  outage is a failure: answering `false` for it would make the hub recreate a
  ticket that still exists.
- Build the API path from the credential and `key` only, after checking the key is
  a ticket id; never from `url`.
- `resolve` closes the ticket and records `comment`. Prefer an internal note, so
  the requester is not emailed by the hub.
- There is no find op and there are no approval ops in 1.1: approval sync stays
  native (ServiceNow, Jira), and a plugin connection cannot carry the
  `approval_pending` class. A ticket made just before a hub crash is therefore not
  adopted on retry (see [`docs/ops/ITSM.md`](../ops/ITSM.md)).
- Declare `network` with `hosts_from_credential` naming the credential's
  subdomain `base_url` field, mark API keys `secret`, and declare nothing that
  touches a private key.
- Grade it with `conformance.TicketSuite` against a mock of the service; see
  `tests/plugins/conformance/ticket_test.go`. The suite checks create, exists
  before and after an external delete, the probe key, a non-numeric key,
  resolve with its comment, 500, 429 with `Retry-After`, 401, that an outage in
  `exists` is an error rather than `false`, and that no credential or PEM block
  appears in events, results or errors.

Operators connect it with an ITSM connection of kind `plugin`; see
[`docs/ops/ITSM.md`](../ops/ITSM.md).

### The other kinds

`dns01`, `inventory` and `credentials` are accepted by the manifest parser and
have typed conformance stubs (`DNS01Suite`, `InventorySuite`,
`CredentialsSuite`) that skip, naming the ticket that fills them in. The hub does
not install a plugin of those kinds yet.

### The dns01 kind

A dns01 plugin publishes and removes the TXT record an ACME DNS-01 challenge
needs at a DNS provider. Start from
[`plugins/digitalocean-dns`](../../plugins/digitalocean-dns) (one record per
value) or [`plugins/ns1-dns`](../../plugins/ns1-dns) (one record set per name).

```go
func init() { dns01.Register(myProvider{}) }

func (myProvider) Present(h *delivery.Host, req abi.DNS01PresentRequest) (abi.DNS01PresentResult, error)
func (myProvider) Cleanup(h *delivery.Host, req abi.DNS01CleanupRequest) (abi.DNS01CleanupResult, error)
```

`dns01.present {fqdn, value, ttl}` returns `{record_id, zone}`; `dns01.cleanup
{fqdn, value, record_id}` returns `{removed}`. `fqdn` is
`_acme-challenge.<name>` with no trailing dot and `value` is the challenge
digest (not a secret). The plugin only writes and deletes: the hub checks that
the record is visible with its own resolvers before the CA validates, so a
plugin cannot make a challenge pass.

- Return the `zone` that holds the record. The hub uses it to find the
  authoritative name servers, and refuses a zone that is not the name or one of
  its parents. `record_id` is opaque and comes back to `cleanup`.
- `ttl` is a hint (60). Raise it to the provider's own minimum (GoDaddy: 600).
- Providers that keep every TXT value of a name in one record set (GoDaddy, NS1,
  Akamai) must not delete the set while another value is in it: a certificate
  for `example.com` and `*.example.com` puts two values at one name. Implement
  `dns01.RRSet` and call `dns01.PresentRRSet` and `dns01.CleanupRRSet`, which
  read, change and write the set keyed by value and treat "already gone" as
  success.
- Cleanup is idempotent. Never echo a provider's response body in an error: it
  can reflect the request, which carries the credential.
- Call `dns01.CheckName` (the SDK's `Handle` already does): the name goes into
  URL paths, so only letters, digits, `-`, `_` and `.` are accepted.
- Declare `network` with a fixed `hosts` list when the provider has one API
  host, or `hosts_from_credential` when it is per account (Akamai) and check the
  host in the plugin too. Mark API keys `secret`. A dns01 plugin declares no
  `receive_private_key`, `trust_store`, exec or `file_write` capability.
- Grade it with `conformance.DNS01Suite` against a mock of the provider's API;
  see `tests/plugins/conformance/dns01_test.go`. The suite checks the record and
  zone, a name below the zone, cleanup of one of two values at a shared name
  (with a foreign value beside them), idempotent cleanup, a name outside the
  provider's zones, 5xx, 429 and refused credentials leaving no record, hostile
  names, and that no credential or PEM block appears in events, results or
  errors.

First-party plugins (each is `High` tier: network to the vendor host, enabled
by a second person):

| Plugin | Provider | Host | Credential fields |
|---|---|---|---|
| `kryptkeeper.digitalocean-dns` | DigitalOcean DNS API v2 | `api.digitalocean.com` | `api_token` |
| `kryptkeeper.godaddy-dns` | GoDaddy Domains v1 | `api.godaddy.com` | `api_key`, `api_secret` |
| `kryptkeeper.ns1-dns` | NS1 (IBM NS1 Connect) | `api.nsone.net` | `api_key` |
| `kryptkeeper.akamai-edgedns` | Akamai Edge DNS API v2, EdgeGrid signed | the credential's `host` (`*.akamaiapis.net`) | `host` (`https://` plus the `.edgerc` host), `client_token`, `client_secret`, `access_token` |

Operators use one through an ACME connector with `dns_provider: "plugin"`; see
[`docs/ops/ACME_UPSTREAM.md`](../ops/ACME_UPSTREAM.md#dns_provider-plugin-a-signed-dns-plugin).

### The other kinds

`ticket`, `inventory` and `credentials` are accepted by the manifest parser and
have typed conformance stubs (`TicketSuite`, `InventorySuite`,
`CredentialsSuite`) that skip, naming the ticket that fills them in. The hub
does not install a plugin of those kinds yet.
