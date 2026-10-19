# Evidence-pack mail UAT (W28-13)

Proves the scheduled evidence-pack mailer against a real SMTP sink (Mailpit), including the failure path.

## Prerequisites

- `podman` (running machine: `podman machine start`), `go`, `python3`, `openssl`, `curl`
- `sqlite3` (optional; clears the scheduler lease row between hub restarts)
- Free host ports: hub 8101, Mailpit HTTP 8125, Mailpit SMTP 1125

## Run

```bash
bash tests/live/evidence-mail/run.sh            # ~2-3 min
KK_UAT_PACK_OUT=/tmp/pack.pdf bash tests/live/evidence-mail/run.sh   # also keep the mailed PDF
KK_UAT_KEEP=1 bash tests/live/evidence-mail/run.sh                   # keep $WORK and hub data
```

Exit code is non-zero if any step prints `FAIL`.

## What each step proves

| Step | Proves |
|---|---|
| 1 | Mailpit is up and the mailbox is empty |
| 2 | Hub boots with SMTP pointed at Mailpit; 5 certs imported so the pack is non-trivial |
| 3 | A due schedule (`enabled:true`, no `last_sent_at`) is created; hub restart runs `scan()` at startup |
| 4 | The pack arrives with one `application/pdf` attachment named `compliance-soc2-YYYY-MM-DD.pdf`, starting `%PDF`, over 1000 bytes |
| 5 | No duplicate after 10 s (`MarkSent` worked) |
| 6 | With Mailpit stopped: exactly 3 `evidence scheduler: send <id> failed` log lines (W28-20), an audit row `evidence.delivery_failed` with no recipient address, no `sent` log; after Mailpit returns, the still-due schedule delivers |

## Notes

- `POST /api/v1/reports/evidence/schedules` must include `"enabled": true`; omitted, the schedule is stored disabled and never sent.
- `EVIDENCE_RETRY_DELAY_SECONDS=2` keeps the 3 attempts fast; production default is 30.
