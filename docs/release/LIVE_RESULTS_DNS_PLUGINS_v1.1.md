# Live results v1.1: DNS-01 plugins (DigitalOcean, GoDaddy, NS1, Akamai Edge DNS), W38-08

Date: 2026-10-25. Branch `worktree-agent-a6d8c153e8f2d5f3d` (on `feat/v1.1-integrations`). Evidence is repeatable with the
commands below.

## Verdict: PASS against local stand-ins; no real DigitalOcean, GoDaddy, NS1 or Akamai account and no public CA was used

## What ran

**One plugin, a full ACME order.** The real wasm of `plugins/digitalocean-dns` (5.2 MB, built by
`bash scripts/build-plugins.sh`) was installed into a hub plugin manager on a freshly migrated SQLite database and
enabled. The hub's real ACME connector (`acmeIssuerConnector`, `dns_provider: "plugin"`, `challenge: "dns-01"`,
`dns_propagation: "authoritative"`) then ordered a certificate for `shop.example.test` from the repo's own ACME server.

- The "vendor" is a local TLS server shaped like the DigitalOcean DNS API v2 (Bearer auth, `GET /v2/domains/{d}`,
  `POST /v2/domains/{d}/records` answering 201 with `domain_record.id`, `DELETE .../records/{id}` answering 204). The
  plugin reaches it by its real name, `api.digitalocean.com`: the sandbox's fixed-host grant is enforced, and the
  test's HTTP client only redirects the dial to the stand-in and trusts its certificate.
- The ACME server's DNS-01 validator and the connector's propagation check both read what the plugin wrote at that
  stand-in. So the challenge only passes if the plugin really published the digest, at the right name, in the
  zone it reported.
- The credential went through the production path: an `api_token` credential holding `{"api_token": ...}`, resolved by
  `buildPluginEnv`, tenant-checked against the connector.

```bash
bash scripts/build-plugins.sh
go test ./internal/bootstrap/ -run 'ACMEDNS01|DNSPluginConfig' -count=1 -v
go test ./tests/plugins/conformance/ -run 'DigitalOcean|GoDaddy|NS1|Akamai' -count=1 -v
```

## Results: the full order

| Check | Result |
|---|---|
| The order issues a certificate through the plugin (create TXT, hub propagation check, CA validates, finalize) | PASS |
| The stand-in saw a `POST` (create) and a `DELETE` (cleanup), every request carried `Authorization: Bearer <token>` and `Host: api.digitalocean.com` | PASS |
| No challenge record is left at the vendor after the order | PASS |
| Audit rows `delivery_plugin.dns01_present` and `delivery_plugin.dns01_cleanup`, outcome success, with version and module hash | PASS |
| No audit row contains the vendor token | PASS |
| Vendor answers 500: the order fails with an error naming the plugin, no token in it, no record left, a failure audit row | PASS |
| Vendor rejects the token: the error says the token was refused and does not contain the token | PASS |
| Credential belongs to another tenant: refused as "does not exist", the vendor is never contacted | PASS |
| Plugin disabled, plugins turned off, no plugin host wired, or the plugin is a notify plugin: the order fails before any plugin call | PASS |

## Results: the four plugins against `DNS01Suite`

Each plugin's wasm is loaded by the hub's runtime and graded against a mock of its vendor's API that checks request
shape (auth scheme, paths, body fields, minimum TTL, relative or fully qualified names) and answers the way the vendor
documents. The Akamai mock recomputes the EdgeGrid signature of every request itself (30 second window, nonce replay,
POST-only body hash) and counts rejections; the suite fails if there is one.

| Check | DigitalOcean | GoDaddy | NS1 | Akamai |
|---|---|---|---|---|
| Publishes the value at the name and reports the zone | PASS | PASS | PASS | PASS |
| A name below the zone resolves to the zone | PASS | PASS | PASS | PASS |
| Cleanup removes exactly the published value | PASS | PASS | PASS | PASS |
| A shared name (wildcard + base name + a foreign value) keeps every other value through cleanup | PASS | PASS | PASS | PASS |
| Presenting the same value twice does not lose it | PASS | PASS | PASS | PASS |
| Cleanup is idempotent, also without a record id | PASS | PASS | PASS | PASS |
| A name outside the provider's zones is refused | PASS | PASS | PASS | PASS |
| 500, 429 and refused credentials are errors and leave no record | PASS | PASS | PASS | PASS |
| Hostile names or values (path, query, CRLF, quote) never reach the provider | PASS | PASS | PASS | PASS |
| No credential value or PEM block in events, results or errors (the mock reflects text on a 401) | PASS | PASS | PASS | PASS |

Also proven: an Akamai credential whose `host` is outside `akamaiapis.net` is refused before anything is signed or sent.
The EdgeGrid implementation matches the vendor's published test vectors (signing key, content hash, and the full
signed `Authorization` header for a POST with a query string and a JSON body, from
`akamai/AkamaiOPEN-edgegrid-python`).

## Vendor sources

Endpoints, auth and body shapes were read from the vendors' own documentation or official clients; each plugin's
`main.go` cites the exact pages.

| Vendor | Source |
|---|---|
| DigitalOcean | `docs.digitalocean.com/reference/api/reference/domains/` and `.../domain-records/`; `github.com/digitalocean/openapi` operations `domains_create_record`, `domains_list_records`, `domains_delete_record` |
| GoDaddy | `developer.godaddy.com/en/docs/references/rest/domains/v1/` (record-add, record-get, record-replace-type-name, record-delete-type-name, get); `.../api-users/auth` (credential types); `.../api-users/domains/manage/dns` (minimum TTL 600) |
| NS1 | the vendor's Go client `github.com/ns1/ns1-go` v2 (`rest/record.go`, `rest/zone.go`, `rest/client.go`), which links the IBM NS1 Connect API reference |
| Akamai | `techdocs.akamai.com/edge-dns/reference/` (post-zones-zone-names-name-types-type, get-zone-name-type, put-zones-zone-names-name-types-type, delete-zone-name-type, get-zone, use-change-lists); `techdocs.akamai.com/developer/docs/authenticate-with-edgegrid`; `AkamaiOPEN-edgegrid-python` and `-golang` for the algorithm details the prose omits |

## Findings during the build

- GoDaddy's current documentation lists the classic `sso-key` developer key as deprecated for Domains through 2026 and
  recommends personal access tokens (Bearer), which authenticate the v3 API. The v1 reference pages used here say they
  require bearer auth without naming the header format, so whether v1 DNS records accept a PAT is not established.
  The plugin uses `sso-key` as the ticket specified; a v3 plugin is a ROADMAP row.
- GoDaddy `DELETE /records/{type}/{name}` removes every record of that type and name, and Akamai and NS1 hold all TXT
  values of a name in one record set. A certificate for `example.com` and `*.example.com` puts two values at one name,
  so all three plugins read-modify-write keyed on value; the suite's shared-name case guards it.
- EdgeGrid hashes the body for POST only, so an Edge DNS `PUT` signs an empty content hash. The prose documentation
  does not say this; the vendor's reference implementations do.
- DigitalOcean's reference states no minimum TTL; the plugin sends the hub's 60 seconds with a floor of 30 and a
  rejection would surface as a 422 with its status. GoDaddy's minimum of 600 seconds is documented, so with that plugin
  the record can stay cached for ten minutes.

## Not proven here (ROADMAP, Needs partner hardware)

- A real DigitalOcean, GoDaddy, NS1 or Akamai account: token scopes and rejection wording, GoDaddy PUT body schema
  (items carry `data` and `ttl` only), NS1 answer handling on a zone with filters or linked records, Akamai
  EdgeGrid clock-skew handling and a zone in a non-default contract or group, vendor rate-limit behaviour, and TXT
  record visibility delay at each vendor's authoritative servers.
- A run against a public CA (Let's Encrypt staging) through a plugin.

Tracked on the ROADMAP row "DNS-01 through the DigitalOcean, GoDaddy, NS1 and Akamai Edge DNS plugins" (W38-08).
