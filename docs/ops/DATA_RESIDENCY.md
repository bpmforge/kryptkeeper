# Data residency and outbound connections

Nothing leaves the deployment unless a feature below is enabled. The default state is no
outbound connections; the W30-20 egress capture (`tests/live/egress/run.sh`) is the
check for that claim and its result is PENDING-RUN until that capture has been executed.
Operator-configured destinations (your SMTP relay, webhook URLs, OIDC issuer) are hosts
you chose, so they are not fixed names. The fixed names the product can contact are in the
machine-readable block at the end of this file.

All outbound HTTP to operator-supplied URLs (notification webhooks, inventory sources, ACME
upstream) goes through the guarded client described in [EGRESS.md](EGRESS.md).

| Feature | Destination | Data sent | Enabled by | Default |
|---|---|---|---|---|
| Certificate Transparency monitoring | `crt.sh` | the monitored domain names | `KRYPTKEEPER_CT_DOMAINS` or config key `ct.domains` | off |
| CT second source | `api.certspotter.com` | the same domain names | automatically with CT, unless `KRYPTKEEPER_CT_SECOND_SOURCE=off` (optional key `KRYPTKEEPER_CT_CERTSPOTTER_KEY`) | off (on whenever CT is on) |
| Email | operator SMTP server | alert content | `SMTP_HOST` | off |
| Slack | operator webhook URL | alert text | `SLACK_WEBHOOK_URL` | off |
| PagerDuty | `events.pagerduty.com` (override `KRYPTKEEPER_PAGERDUTY_EVENTS_URL`) | alert summary, routing key | `PAGERDUTY_ROUTING_KEY` | off |
| Generic webhook | operator URL | alert JSON | `WEBHOOK_URL` | off |
| SIEM | operator URL / syslog address | audit events (JSON or CEF) | `SIEM_WEBHOOK_URL` / `SIEM_SYSLOG_ADDR` | off |
| OIDC SSO | the issuer's discovery and JWKS URLs (HTTPS only) | none (fetch only) | `APP_OIDC_ISSUER` / `APP_OIDC_DISCOVERY_URL` | off |
| Cloud inventory and cloud-KMS keys | AWS regional endpoints; `login.microsoftonline.com` and `<vault>.vault.azure.net`; `certificatemanager.googleapis.com`, `cloudkms.googleapis.com`, GCE metadata `metadata.google.internal` | API calls with the operator's cloud credentials | `KRYPTKEEPER_CLOUD_SCOPES`; cloud-KMS keystore (`KRYPTKEEPER_KMS_PROVIDER`) | off |
| Commercial CA inventory sources | `www.digicert.com`, `privateca.googleapis.com`, AWS ACM PCA regional endpoint (`acm-pca.<region>.amazonaws.com`); Sectigo and Entrust at the `base_url` you configure | inventory pulls | inventory source configuration | off |
| ACME upstream (renew at the original CA) | the configured `directory_url` (for example Let's Encrypt) | CSR, identifiers; HTTP-01 or DNS-01 validation | ACME connector configuration ([ACME_UPSTREAM.md](ACME_UPSTREAM.md)) | off |
| ACME DNS-01 helpers | `api.cloudflare.com` (Cloudflare DNS provider); `cloudflare-dns.com` (DoH propagation check, only for DNS-01 orders, in mode `doh` or in the default mode `auto`, which tries authoritative, then DoH, then resolver; the host changes if `dns_doh_url` is set) | TXT record names | ACME connector DNS settings | off |
| Discovery, SSH/WinRM install, Kubernetes | the targets the operator lists | probes and installs | discovery and target configuration | off |
| Hub to agent / MCP / cert-manager issuer | the hub URL | inventory, tasks | agent configuration (`KRYPTKEEPER_HUB_URL` for the MCP server) | off (internal) |

Notes:

- The CT second source is the one row whose default differs from "off": once CT domains are
  set, both `crt.sh` and `api.certspotter.com` receive the domain names. Set
  `KRYPTKEEPER_CT_SECOND_SOURCE=off` to keep only `crt.sh`. The egress capture therefore
  expects `{crt.sh}` with the second source off and `{crt.sh, api.certspotter.com}` with it on.
- Azure vault hosts are per-vault subdomains of `vault.azure.net`, and AWS endpoints are
  regional, so neither is a single fixed name in the machine-readable block.
- Whether the product, with every feature off, makes zero outbound connections is what the
  W30-20 capture measures. Result: PENDING-RUN.

## Source of each row

| Row | Code |
|---|---|
| crt.sh | `internal/ctmonitor/monitor.go:86` (default base), `:224` (`KRYPTKEEPER_CT_DOMAINS`) |
| Cert Spotter | `internal/ctmonitor/monitor.go:230-232` (opt-out env), `internal/ctmonitor/source_certspotter.go:36` |
| CT config key | `internal/bootstrap/config_store.go:73`, `cmd/kryptkeeper/main.go:453-457` |
| PagerDuty | `internal/notifications/delivery/delivery.go:262`, override `cmd/kryptkeeper/main.go:1168` |
| SMTP / Slack / webhook | `internal/bootstrap/config_store.go:51,62,63` |
| SIEM | `internal/bootstrap/siem_integration.go:84-85` |
| OIDC | `internal/bootstrap/auth_config.go:141-144`, `internal/bootstrap/auth_oidc.go:122-131` |
| Azure | `internal/cloudinventory/azure_keyvault.go:161-166`, `internal/keystore/cloudkms_azure.go:159` |
| GCP | `internal/cloudinventory/gcp_certmanager.go:119,190`, `internal/keyinventory/gcp.go:31`, `internal/keystore/cloudkms_gcp.go:32,140` |
| Cloud scopes / KMS provider | `internal/bootstrap/config_store.go:77`, `cmd/kryptkeeper/main.go:160` |
| DigiCert / GCP CAS / AWS PCA | `internal/connectors/digicert.go:58`, `internal/bootstrap/inventory_source_commercial.go:242,344` |
| ACME directory | `internal/bootstrap/connector_acme.go:44,117` |
| Cloudflare DNS / DoH | `internal/bootstrap/connector_acme_dns01.go:35`, `internal/bootstrap/connector_acme_dnscheck.go:32,40` |

<!-- egress-hosts:begin -->
ct|KRYPTKEEPER_CT_DOMAINS|crt.sh
ct-second-source|KRYPTKEEPER_CT_DOMAINS|api.certspotter.com
pagerduty|PAGERDUTY_ROUTING_KEY|events.pagerduty.com
azure|KRYPTKEEPER_CLOUD_SCOPES|login.microsoftonline.com
gcp-certmanager|KRYPTKEEPER_CLOUD_SCOPES|certificatemanager.googleapis.com
gcp-kms|KRYPTKEEPER_KMS_PROVIDER|cloudkms.googleapis.com
gcp-metadata|KRYPTKEEPER_CLOUD_SCOPES|metadata.google.internal
digicert|inventory-source|www.digicert.com
gcp-cas|inventory-source|privateca.googleapis.com
acme-dns01-cloudflare|acme-connector-dns|api.cloudflare.com
acme-dns01-doh|acme-connector-dns|cloudflare-dns.com
<!-- egress-hosts:end -->
