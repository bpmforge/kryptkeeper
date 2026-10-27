# Live CT monitoring result (P5, W24-22 harness), 2026-10-26

**Result: PASS.** The real `ctmonitor` (crt.sh plus Cert Spotter, real SQLite
store, recording notification channel) found certificates for
`kryptkeeper.io` that this hub did not issue, raised one notification per
finding, stayed silent on a re-scan, and did not renotify an acknowledged
finding.

- Code: dev `main` 66b2f9c0 (v1.1.0) on branch `fix/v1.1-trust-leaks`.
- Host: the maintainer's Mac (M4 Max), public internet, no Cert Spotter key.
- Command: `KK_LIVE_CT_DOMAIN=kryptkeeper.io KK_LIVE_CT_WAIT=20m bash tests/live/ct/run.sh`
- The certificates found are the Cloudflare edge certificates for the domain
  (issuer Google Trust Services WE1), which is the case the monitor exists
  for: a certificate for your domain from a CA you did not run.

```
=== CT LIVE RESULT ===
date: 2026-10-26T14:18:38Z
domain: kryptkeeper.io
sources: crtsh,certspotter
elapsed_to_first_finding: 17s
finding: id=crtsh:29986675827 issuer="C=US, O=Google Trust Services, CN=WE1" serial=0095ee5897fc803c8b13737ce2868d9eac
new_findings: 6
notifications: 6
source_errors_seen: 2
rescan_silent: true
acknowledged_silent: true
=== END ===
```

## What this does not prove

- The inventory exclusion (`KK_LIVE_CT_KNOWN_SERIAL`) was not exercised:
  no certificate for this domain is in a hub inventory.
- The monitor reads aggregators (crt.sh, Cert Spotter), not RFC 6962 logs
  directly. Two transient source errors were tolerated during polling.
- Delivery to a real channel (Slack, email): the notifier is a recording
  channel, as in the harness design.
- Behaviour on a large domain portfolio.
