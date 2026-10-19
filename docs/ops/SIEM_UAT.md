# SIEM live UAT (W22-08)

Run: `bash tests/live/siem/run.sh` (podman required; see
`tests/live/siem/README.md` for topology, pinned images and findings).

Splunk HEC was **not** exercised; Elasticsearch 8.15.3 and syslog-ng 4.11 were.

## Result matrix (measured, last run 2026-10-15, `PASS=14 FAIL=0`)

| Form | Receiver | Latency from trigger | Budget |
|---|---|---|---|
| JSON | Elasticsearch (webhook) | 0.65 s | 5 s |
| JSON in RFC 5424 | syslog-ng (TCP, octet-counted) | 0.67 s | 5 s |
| CEF in RFC 5424 | syslog-ng (TCP) | 0.05 s | 5 s |
| Receiver killed | counter `kryptkeeper_siem_send_failures_total` 0 -> 1, both audit rows kept | within 15 s | 15 s |

Latency varies with host load (0.05 s to 3.3 s over five passing runs; one
loaded run missed the budget before a clean rerun). Re-run to refresh numbers.

## Operator notes

- Webhook destinations on loopback are refused by the egress guard; use a
  private (RFC 1918) or public address.
- CEF webhook bodies are `text/plain`; point `SIEM_WEBHOOK_URL` at a receiver
  that accepts that, or use syslog for CEF.
- The JSON syslog form carries `[kryptkeeper@99999 ...]` structured data; the
  CEF form uses `-` there.
