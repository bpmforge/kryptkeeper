# Live results W27-06: scheduler-driven autopilot in push modes, policy tick - v0.15

Date: 2026-10-16. Hub commit: `80f4cf4c` (branch `kk/w27-c`, hub built from the working tree of that commit; includes W27-02 bindings).
Host: macOS 27.0.1, arm64 (Apple M4 Max), podman 6.1.3 (machine 12 CPU), kind v0.33.0, kubectl client v1.37.1.
Poll interval: `RENEWAL_POLL_MINUTES=1`. Deadline for a scheduled renewal to show up: poll interval + 60 s = 120 s.

## Verdict: PARTIAL - plugin, k8s and policy-tick VALIDATED; IIS NOT RUN

| Leg | Harness | Verdict |
|---|---|---|
| plugin (healthy + `-fail-bind` device) | `tests/live/autopilot/push-modes.sh` | PASS (15/15) |
| k8s on kind (healthy namespace + RBAC-refused namespace) | `tests/live/k8s/autopilot.sh` | PASS (16/16) |
| policy tick 30 -> 45 days | `tests/live/autopilot/policy-tick.sh` | PASS (14/14) |
| IIS | `push-modes.sh` with `MODES=plugin,iis` | NOT RUN |

Board acceptance 4 (IIS and WinRM runs recorded on the current build) is NOT met: no Windows lab host
(`KK_IIS_HOST`, `KK_IIS_USER`, `KK_IIS_PASSWORD_FILE`) was configured, and the scripted IIS flow is not
implemented in the harness (it reports `SKIP ... NOT RUN`); an IIS/WinRM run still has to be done by hand
against the lab from `docs/ops/WINRM_ENABLEMENT.md` and recorded here. No Windows build is claimed anywhere in this file.

## Plugin mode (acceptance 1 and 2)

Hub in a container with the example delivery plugin enabled through the approval queue (second admin approves);
two mock appliances (`tests/live/plugins/mockdevice`) on a podman network; one started with the new `-fail-bind`
flag (PUT `/api/binding` answers 500 after the certificate upload). Each device has a plugin target armed
`auto_renew=true` by a pki-admin, and one 72 h certificate bound to it with `POST /targets/{id}/bindings`.

| Field | Healthy device | `-fail-bind` device |
|---|---|---|
| Served leaf sha256 before | `08d27578a3563255...` | `1af33baf02a924270ee9ac83a6a80e4b1dcaf0792db3fe73d2d25947426bf805` |
| Served leaf sha256 after | `49554d067a6628aa...` (changed) | `1af33baf02a924270ee9ac83a6a80e4b1dcaf0792db3fe73d2d25947426bf805` (byte-identical) |
| Elapsed from setup done | 67 s (limit 120 s) | n/a |
| Audit | `certificate.renew_execute` by `renewal-scheduler`, `install=installed*` | `certificate.renew_execute_partial/_failed`, outcome failure, `attempt=1/5`; 0 success rows |
| renew_execute rows by a non-scheduler actor | 0 | 0 |
| Device tokens / key markers in hub log + audit (27 audit entries) | 0 | 0 |

## k8s mode (acceptance 1 and 2)

kind cluster `kk-ap-<id>` (podman provider), no cert-manager. Namespace `uat-a` has the Role, `uat-b` has none;
both run a `tlsecho` pod serving the namespace Secret via NodePort. Hub is a host process (as `tests/live/k8s/run.sh`),
verify dial through the host's non-loopback address.

| Field | Target A (Role present) | Target B (no Role, write refused with 403) |
|---|---|---|
| Secret leaf before / after | `4c042e4d6186bb0b...` -> `f6122b072127dc95...` | tls.crt sha256 `10d6ccd34b869f969d989bb6577ff52b971a430e57a8087dfbc3a5c21dcd1fbe` before and after (identical) |
| Elapsed (Secret changed) | 3 s after setup done (limit 120 s) | n/a |
| Pod served leaf after | equals the new Secret leaf (kubelet propagation observed, check waited up to 150 s) | sha256 `c83013b460dfafb650e8de46b465af8f30be18eba340af1ee7452e719ce7c4fd` before and after (identical) |
| Audit | `certificate.renew_execute` by `renewal-scheduler`, `install=installed*` | failure row with `attempt=1/5` |
| renew_execute rows by a non-scheduler actor | 0 | 0 |
| SA bearer token / key markers in hub log + audit (22 entries) | 0 | 0 |

The 3 s figure is the scheduler's first tick landing right after the bindings were created (the hub had been up
for about a minute); it is a real scheduler-driven renewal but not a measurement of a full poll interval. The
plugin leg (67 s) is the one that exercised a complete interval.

## Policy tick (acceptance 3)

Hub container, one ssh nginx target (`auto_renew=true`, certificate bound), certificate with 40 days left (39 on
the day of issue), default threshold 30.

| Observation | Value |
|---|---|
| Tick `2026-10-16T16:59:24Z` `last_candidates` | 0 |
| Next tick `2026-10-16T17:00:30Z` `last_candidates` | 0, served leaf unchanged |
| `PATCH /targets/{id}` `renewal_threshold_days=45` | 200, at 13:00:32 |
| Next tick `2026-10-16T17:01:35Z` (64 s after the PATCH) | `last_candidates=1`, `max_threshold_days=45` |
| Hub container `StartedAt` before / after | identical (0 restarts) |
| Result of that tick | scheduler renewed and installed; new leaf `42049897bd5e76873a486e22ebf5ce7f02d4bfc100355b1d8e90608b52c5eb21` served |
| renew_execute rows by a non-scheduler actor | 0 |

Caveat: the first observed tick (16:59:24Z) happened at hub start, before the certificate existed, so on its own it
proves nothing; the second tick (17:00:30Z) is the real "stays at 0 across a full scan".

## Notes and traps

- `plugins/mockdevice` named in the ticket is `tests/live/plugins/mockdevice` on disk; `-fail-bind` was added there (lead decision).
- A rejected attempt is audited from attempt 1; the scheduler retries with backoff (`renewalInstallMaxAttempts=5`); the harnesses stop after the first failure row and assert only attempt 1/5.
- k8s kubelet Secret propagation can take about 2 minutes (`k8sVerifyRetryAttempts`); the harness waits up to 150 s for the independent served-leaf check.
- All secrets are generated per run, kept in temp dirs and removed on exit; no key or token is printed or committed.

To re-run: `bash tests/live/autopilot/policy-tick.sh`, `bash tests/live/autopilot/push-modes.sh` (`MODES=plugin,iis`), `bash tests/live/k8s/autopilot.sh` (about 2 to 3 minutes each).
