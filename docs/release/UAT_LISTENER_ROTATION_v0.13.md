# UAT W25-17: hub listener-cert renewal leaves agents connected

Ticket W25-17 (FR-P57). Harness: `tests/live/tls/listener-rotation.sh`.

- Date: 2026-10-15/16, macOS arm64, podman 6.1.3. Hub, agent and an nginx proxy are containers on one private network; hub, healthcheck and agent are built from this tree (commit `6b10c595`, no uncommitted changes under `cmd/` or `internal/` at build time) for linux/arm64.
- Renewal trigger used: **file removal + restart**. `grep` of `cmd/kryptkeeper` found no in-process listener-renew hook (`selfIssuedTLSCertificate` runs at process start only), so the harness stops the hub, deletes `/data/tls/tls.crt` and `tls.key` from the persistent volume (CA, keystore and db untouched), and starts the same container again. The system clock is not touched and the agent container is never restarted.
- Agent poll interval 10 s; deadline for the post-renewal poll is 2 x 10 s measured from hub `/readyz`, not from the stop.

## Recorded run (final harness, `RESULT: PASS`)

| check | result |
|---|---|
| leaf serial before (S0) | `FCB53786642835BADE6BC4FF8C0E4B88` |
| leaf serial after (S1) | `9418B58C6133A354CD93F6B121D98BC0` |
| CA SHA-256 fingerprint before = after | `BE:C6:43:97:39:EA:5E:E3:75:02:87:97:79:4F:0C:59:56:49:D6:22:42:18:E6:6B:38:64:01:53:51:F1:E8:48` (unchanged) |
| new leaf verifies against the pre-renewal `hub-ca.pem` | yes, `Verify return code: 0 (ok)`, hostname `localhost`, `-verify_return_error` |
| enrol events E0 -> E1 (`agent.register` success audit events) | 1 -> 1 |
| agent log `registering agent` lines before -> after | 1 -> 1 |
| hub stop to `/readyz` | 1.7 s |
| first accepted agent poll after hub-ready | 9.4 s (limit 20 s) |
| `/healthcheck` in the hub container (`HEALTHCHECK_CA_FILE` set) | exit 0 |
| GET `/healthz` through nginx (`proxy_ssl_verify on`, trusted cert = hub CA) | 200 before and after |
| skip-verify scan of the harness | none; proxy config asserted `proxy_ssl_verify on` |

Agent log after the restart, from the run:

```
01:08:39 hub accepted 2 certificates (1 endpoints)
01:08:49 discovered 2 certificates, 1 endpoints
01:08:49 hub accepted 2 certificates (1 endpoints)
```

Hub log `[TLS]` lines show two self-issuances from the same CA id (`9fe56d03-...`): initial boot and the re-issue after the files were removed.

## Notes

- Test names: `serial_changes`, `new_leaf_verifies_against_old_ca`, `agent_reconnects_without_reenroll`, `healthcheck_verifies`, `nginx_proxy_verifies`, `no_skip_verify_flags`: all PASS.
- An earlier run of the same script (before the final harness) also passed all six checks (S0 `647830FB...` -> S1 `DE8A1EB6...`, first poll 13.6 s after ready) but its audit-based enrol counter read 0 for E0 and E1 because the harness parsed the wrong JSON key (`data`, not `events`); the agent-log counter (1 -> 1) was correct. The parser was fixed and the run above is the re-run.
- The hub CA is read from the hub volume (`podman cp /data/tls/ca.pem`) as the trust anchor, so nothing in the harness needs a verification bypass to bootstrap.
- Agent re-enrolment detection depends on two independent signals (audit events and the agent's own log). Both stayed at 1.
