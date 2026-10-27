# Kryptkeeper v0.9.0 live harness results

Latest run: **v0.9.0-rc.7** (`main` at `2f9e766`), 2026-10-11 (all times in this file are UTC), by the
release coordinator's re-check. Each row names the harness path and the real client it drives. Other
release docs cite this file for every live number. Re-run the harness and update this file before quoting
a newer result. Earlier runs (rc.5 at `5ec48ff`, and `26e17ca`) are kept below as history.

## rc.7 (main at `2f9e766`, 2026-10-11 UTC)

Run sequentially on a worktree of `2f9e766`, plain `bash <harness>/run.sh`, no leftover containers.

| Harness | Result (rc.7) | Real client or peer |
|---|---|---|
| `tests/smoke/run.sh` | 331/331 | hub binary, curl, local OIDC JWKS stub |
| `tests/live/acme/run.sh` | 28 passed, 0 failed | certbot, lego |
| `tests/live/protocols/run.sh` | ALL STEPS PASSED | openssl EST, SCEP, CMP, OCSP, CRL |
| `tests/live/tls/run.sh` | ALL STEPS PASSED | globalsign/est over the hub's self-issued TLS |
| `tests/live/sshca/run.sh` | ALL STEPS PASSED | OpenSSH sshd and ssh client |
| `tests/live/autopilot/run.sh` | ALL PASS (29 checks) | nginx hosts and the agent, unattended |
| `tests/live/agent/run.sh` | 18 passed, 0 failed | Linux container agent |
| `tests/live/ssh-install/run.sh` | ALL PASS (nginx and apache, including rollback) | OpenSSH, nginx, apache |
| `tests/live/plugins/run.sh` | ALL STEPS PASSED (27 checks) | built-from-source example plugin, mock appliance, cosign |
| `go test ./...` | 50 packages ok | none (unit and integration) |
| `KRYPTKEEPER_TEST_POSTGRES_DSN=... go test -p 1 ./...` (postgres:16-alpine, database `kk_rc7_test`) | 50 packages ok | PostgreSQL 16 |
| `make test-race` | 50 packages ok, 0 fail | none |
| Upgrade spot-check, SQLite rc.1 and rc.2 to rc.7 and PostgreSQL 16 rc.4 to rc.7 | PASS, schema 76 (A1 31 assertions, A2 29, B3 28, 0 FAIL) | the rc images; see [`UPGRADE_TEST_v0.9.md`](UPGRADE_TEST_v0.9.md) |

## rc.5 (main at `5ec48ff`, 2026-10-11 UTC)

Recorded in [`UPGRADE_TEST_v0.9.md`](UPGRADE_TEST_v0.9.md) ("Live set on rc.5"), run sequentially,
each under `perl -e 'alarm 1500; exec @ARGV'`, container leftovers none.

| Harness | Result (rc.5) |
|---|---|
| `tests/smoke/run.sh` | 331/331 |
| `tests/live/acme/run.sh` | 28 passed, 0 failed |
| `tests/live/protocols/run.sh` | ALL STEPS PASSED |
| `tests/live/tls/run.sh` | ALL STEPS PASSED |
| `tests/live/sshca/run.sh` | ALL STEPS PASSED |
| `tests/live/autopilot/run.sh` | ALL PASS (29 checks) |
| `tests/live/agent/run.sh` | 18 passed, 0 failed |
| `tests/live/ssh-install/run.sh` | ALL PASS |
| `tests/live/plugins/run.sh` | ALL STEPS PASSED |
| `make test-race` | 50 packages ok, 0 fail |
| Postgres store round-trip tests (`KRYPTKEEPER_TEST_POSTGRES_DSN`, `-p 1`) | not recorded in the rc.5 pass; run on rc.7 above |

## History: `26e17ca` (2026-10-11 UTC)

Tree: `main` at `26e17ca`. Superseded by the rc.5 and rc.7 tables above.

| Harness | Result (2026-10-11) | Real client or peer |
|---|---|---|
| `tests/smoke/run.sh` | 331/331 | hub binary, curl, local OIDC JWKS stub |
| `tests/live/acme/run.sh` | 28 passed, 0 failed | certbot, lego |
| `tests/live/protocols/run.sh` | ALL STEPS PASSED | openssl EST, SCEP, CMP, OCSP, CRL |
| `tests/live/tls/run.sh` | ALL STEPS PASSED | globalsign/est over the hub's self-issued TLS |
| `tests/live/sshca/run.sh` | ALL STEPS PASSED | OpenSSH sshd and ssh client |
| `tests/live/autopilot/run.sh` | ALL PASS (29 checks) | nginx hosts and the agent, unattended |
| `tests/live/agent/run.sh` | 18 passed, 0 failed | Linux container agent |
| `tests/live/ssh-install/run.sh` | ALL PASS (nginx and apache, including rollback) | OpenSSH, nginx, apache |
| `tests/live/plugins/run.sh` | ALL STEPS PASSED (27 checks) | built-from-source example plugin, mock appliance, cosign |

Notes:

- The plugins harness runs on a podman network since PR #102; the 2026-10-09 run (26 checks) predates it.
- Per-case counts are given only where the harness reported them. "ALL STEPS PASSED" means the script
  reached its final step with no failure; it does not state a case count.
- Not run in this pass: `tests/live/acme-upstream` (needs a Cloudflare token and Let's Encrypt staging),
  the Windows lab (WinRM/IIS, WSTEP/XCEP), Kubernetes, service mesh, notifications, PKCS#11, Compose.
  Their last recorded results are dated in the UAT plan.

## Upgrade test

Latest: rc.7 spot-check (SQLite rc.1 to rc.7, PostgreSQL 16 rc.4 to rc.7) and the full rc.5 matrix
(nine scenarios on both engines), both PASS. Method, per-scenario results and findings are in
[`UPGRADE_TEST_v0.9.md`](UPGRADE_TEST_v0.9.md). Earlier runs (rc.1/rc.2 to main on `72712ba`, rc.4) are
kept there as history.
