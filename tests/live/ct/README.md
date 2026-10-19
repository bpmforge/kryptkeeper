# Live CT test against crt.sh (W24-22)

Proves, with the real `ctmonitor` (crt.sh plus Cert Spotter, real SQLite
store, real `ChannelNotifier` over a recording channel), that a certificate
issued for a domain you control by a CA that is NOT this hub becomes exactly
one finding and one notification, that a re-scan stays silent, that an
inventoried serial yields no finding, and that an acknowledged finding never
renotifies. CI never runs it; without `KK_LIVE_CT=1` it skips with a reason.

## Run
1. Issue a certificate for `<domain>` from another CA, e.g.
   `certbot certonly --manual --preferred-challenges dns -d <domain>`.
   Do NOT issue it from this hub. Wait for CT propagation (minutes to hours).
2. `KK_LIVE_CT=1 KK_LIVE_CT_DOMAIN=<domain> bash tests/live/ct/run.sh`
3. Paste the `=== CT LIVE RESULT ===` block (also written to
   `tests/live/ct/last-run.md`, git-ignored) into
   `docs/release/LIVE_RESULTS_CT_v0.12.md`.

## Env
| Var | Required | Meaning |
|---|---|---|
| `KK_LIVE_CT` | yes (`1`) | gate |
| `KK_LIVE_CT_DOMAIN` | yes | domain you control |
| `KK_LIVE_CT_EXPECT_ISSUER` | no | substring expected in the finding issuer |
| `KK_LIVE_CT_KNOWN_SERIAL` | no | serial of a second cert pretended to be in inventory; must give no finding |
| `KK_LIVE_CT_WAIT` | no | max wait for CT propagation (default `30m`) |
| `KK_LIVE_CT_POLL` | no | poll interval, the test's "scan interval" (default `60s`) |
| `KRYPTKEEPER_CT_CERTSPOTTER_KEY` | no | Cert Spotter API key |
| `KRYPTKEEPER_CT_SECOND_SOURCE=off` | no | crt.sh only |
| `KK_CT_RESULT_FILE`, `KK_CT_GO_TIMEOUT` | no | result path, go test timeout (default `60m`) |

## Not proven
- Slack/SMTP delivery: the notifier is a recording channel (UC-I01 owns channels).
- crt.sh is slow and flaky; errors are tolerated while polling and counted.
- `len(NewFindings)==1` is not forced: a domain with several unknown certs raises
  several findings; the test asserts one notification per finding and that none
  is for the known serial.
