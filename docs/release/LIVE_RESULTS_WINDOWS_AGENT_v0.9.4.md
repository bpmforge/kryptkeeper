# Live results: Windows agent, v0.9.4-rc.2 release assets

Date: 2026-10-15 (local EDT, UTC-4; hub times are Z). Validation only; no product
code changed. Method as in `LIVE_RESULTS_WINDOWS_AGENT_v0.9.3.md`: lab-win11
(Windows 11 Enterprise 26100, domain-joined to corp.example.test) driven over NTLM-sealed
WinRM; hub on lab-runner (192.0.2.195:8447, TLS from the hub's own CA, closed
registration with an enrollment secret, agent trusts the CA from a file, no `-k`).
The hub is a linux/amd64 build of the v0.9.4 code (`5024da3e`, the merge that
`v0.9.4-rc.2` was cut from; `origin/main` has since moved only by a CI-packaging
commit).

## Assets under test

Downloaded from the GitHub prerelease `v0.9.4-rc.2`:

| File | sha256 (matches `checksums.txt`) |
|---|---|
| `kryptkeeper-agent_0.9.4-rc.2_windows_amd64.msi` | `c37c625f141005b91f622a6c5d59c0e7182d7880529ba62d7aa9f2124c0eaad7` |
| `kryptkeeper-agent_0.9.4-rc.2_windows_amd64.zip` | `816bc8222b707f9e800752b9cab383b358f74a5ce41fa9468a684ab006e82ae8` |

`cosign verify-blob checksums.txt` (identity
`https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/v0.9.4-rc.2`,
issuer `https://token.actions.githubusercontent.com`): **Verified OK**, on the
host before copying. Both files were hashed again on lab-win11 after an HTTP copy
from lab-runner (`Get-FileHash`): identical. The binary reports
`kryptkeeper-agent 0.9.4-rc.2 (commit cbbf589b..., built 2026-10-15T16:11:27Z)`.
Only the MSI was installed; the zip was hash-checked only.

## Verdict

| Step | Result |
|---|---|
| 1. MSI install, service, enroll, online, heartbeat, version | PASS (version caveat, N1) |
| 2. Renew guard with :80 blocked by firewall | PASS |
| 3. Busy :80 gives the fail-fast message | PASS with a gap (F1: IPv4-only holder is not detected) |
| 4. Install hints refused before any ACME order | PASS |
| 5. Uninstall and cleanup | PASS |

## Step 1: install, enroll, heartbeat: PASS

- `msiexec /i ...msi /qn`: exit **0**. Service `KryptkeeperAgent`: StartMode
  Auto, StartName LocalSystem, State Stopped after install (installer does not
  start it). Uninstall entry "Kryptkeeper Agent 0.9.4". Event source key present.
- `agent.env` written (hub URL, enrollment secret, hub CA file, name
  `lab-win11-live094`, poll 20 s), ACL reduced to SYSTEM and Administrators with
  `icacls`. `Start-Service`: 57 ms, Running/Automatic.
- Event log (Application, `KryptkeeperAgent`): `12:25:21 registering agent
  "lab-win11-live094" (windows)`, `registered: agent_id=717f42c52d4faab2`,
  `agent credentials saved to ...agent.env`, `discovered 19 certificates, 0
  endpoints`, `hub accepted 19 certificates`.
- Hub `GET /api/v1/agents`: `lab-win11-live094`, type windows, status `active`,
  `registered_at 16:25:20Z`, `last_seen 16:25:41Z` (advances every 20 s),
  `inventory_count 19`.
- **N1 (minor): the version is only visible from the binary** (`--version`:
  `0.9.4-rc.2`) and the MSI ARPVERSION (`0.9.4`; the numeric MSI version drops the
  `-rc.2`). The hub API (`/api/v1/agents`) does not carry an agent version, the
  agent's startup log line does not print it, and the exe has no Win32 version
  resource (`FileVersion` empty). An operator cannot confirm which agent build is
  enrolled from the hub.

## Step 2: renew guard, firewall closed on :80: PASS

Firewall untouched. Before and after: Domain/Private/Public profiles enabled,
default inbound `NotConfigured`; no enabled inbound allow rule for TCP 80 and none
named Kryptkeeper. Poll 20 s.

**Fixture limitation (important):** the hub only queues a renew task from an
inventory certificate that matches a reported endpoint by cert path
(`matchRenewalTasks`, `internal/bootstrap/handlers_agents.go`), so any task the
hub generates for a real certificate carries a `CertPath` and is, on Windows,
refused by step 4's check before ACME. To exercise the ACME and guard path I
posted a synthetic inventory (one cert, fingerprint `aa11...`, SAN
`lab-win11.lan.internal`, expiring in 8 days, auto-renewable, empty source) with an
endpoint whose cert path was empty, to `POST /api/v1/agent/inventory` using the
agent's own credentials, every 15 s. That yields a hint-less renew task and also
emulates the hub re-tasking a failed renewal on the next inventory. This is a
fixture; a real Windows agent cannot currently reach this path through hub-driven
tasks. (Consequence: on Windows, hub-driven renewals are always refused at step 4,
which is what the docs say.)

Agent event log, task for fingerprint `aa11`:

```
12:27:22 task task-a45dff...: renew CN=lab-win11.lan.internal (expires 2026-10-23)
12:27:22 acme: http-01 challenge will listen on :80
12:27:33 renew CN=lab-win11.lan.internal: wait authorization: acme: authorization error for lab-win11.lan.internal:
12:28:03 task task-a22b46...   (re-queued; seen at 12:28:03, :23 -> no attempt)
12:28:43 acme: http-01 challenge will listen on :80          <- attempt 2, 70 s after failure 1
12:28:53 renew ...: wait authorization: ... (same text)
12:29:03..12:30:43 task task-89660f... seen every 20 s -> no attempt
12:31:03 acme: http-01 challenge will listen on :80          <- attempt 3, 130 s after failure 2
12:31:13 renew ...: wait authorization: ... (same text)
```

- Exactly one attempt at a time: 3 "will listen" lines, 3 failure lines, strictly
  alternating; **0** occurrences of "Only one usage of each socket address" (v0.9.3
  showed it at a 20 s poll).
- Failure reported to the hub each time: `GET /api/v1/agents/{id}/tasks` shows the
  three tasks `status completed, outcome failed`, `completed_at` 16:27:32Z,
  16:28:52Z, 16:31:12Z, `detail "wait authorization: acme: authorization error for
  lab-win11.lan.internal: "`.
- Backoff: gaps from failure to next attempt 70 s then 130 s: consistent with
  base 1 min doubling, +-20 % jitter (`cmd/kryptkeeper-agent/renewguard.go`:
  `finish`). Polls inside the window saw the queued task and did nothing. The
  fourth attempt (expected after about 3.2 to 4.8 min) came at 12:36:24 after the
  fixture had moved on; not needed for the verdict.
- **N2 (carried over from v0.9.3 F3, unchanged): the ACME error detail is still
  empty** ("...authorization error for lab-win11.lan.internal: " with nothing after
  the colon). The hub's own log in v0.9.3 showed the real cause
  ("http-01 validation fetch failed ... deadline exceeded"); the operator sees only
  the opaque message. Docs now explain the firewall rule, which mitigates it.

## Step 3: busy :80, fail-fast message: PASS, with gap F1

A normal process (PowerShell `TcpListener`, user kkadmin, no setting changes) held
:80 inside one WinRM session (child processes die when the session ends, so the
listener and the observation ran in one call).

- Listener bound **dual-stack `[::]:80`** at 12:38:16; the agent's next attempt:

```
12:39:04 acme: http-01 challenge will listen on :80
12:39:04 renew CN=lab-win11.lan.internal: cannot listen on :80 for the ACME HTTP-01 challenge: port 80 in use or not permitted; see docs/ops/WINDOWS_AGENT.md: listen tcp :80: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.
```

  Reported to the hub as `outcome failed` with the same detail (task
  `task-e40679...`, `completed_at 16:39:04Z`). No ACME order was made (message
  appears the same second as the attempt). Listener stopped afterwards; 0
  listeners left.
- **F1 (gap, observed): an IPv4-only holder is not detected.** With a listener on
  `0.0.0.0:80` (bound 12:34:31, pid 288) the agent's attempts at 12:34:43 and
  12:35:03 got past the pre-check: the agent bound `:: Listen pid=<agent>` on :80
  alongside it (`Get-NetTCPConnection` shows both) and went on to the ACME order,
  failing later with the opaque authorization error. On Windows a Go `net.Listen("tcp",
  ":80")` (dual-stack `[::]:80`) coexists with a separate IPv4 wildcard socket, so
  the fail-fast check passes while IPv4 clients (the hub's HTTP-01 fetch) reach the
  other process. Root cause: `internal/agentclient/acme_renewer.go:224-225`
  (`listenHTTP01` binds only `tcp` `:80`). Fix idea: also probe `tcp4` `0.0.0.0:80`.
  Not verified for IIS (http.sys), which was not available. Severity low to medium:
  the failure is still reported, only with the less helpful message.

## Step 4: install hints refused before ACME: PASS

Fixture task for fingerprint `ee55` whose endpoint carried cert path
`C:\kkval094\fixture.pem` (hub task has `CertPath` set):

```
12:39:44 task task-b68708...: renew CN=lab-win11.lan.internal (expires 2026-10-23)
12:39:44 renew CN=lab-win11.lan.internal: install targets not supported on Windows agent in v0.9; use agentless WinRM/IIS
```

Same second, and no `acme: http-01 challenge will listen` line for this task, so
the refusal precedes the :80 pre-check and any order (code order:
`installUnsupported` is the first statement of `doRenew`,
`cmd/kryptkeeper-agent/main.go`). Hub task history: `outcome failed`, `detail
"install targets not supported on Windows agent in v0.9; use agentless WinRM/IIS"`,
`completed_at 16:39:44Z`. (Hub-side proof that no ACME order was created is not
available: the hub log was discarded with the hub; the evidence is the agent log
and code order.)

## Step 5: uninstall and cleanup: PASS

- `Stop-Service`: 35 ms, 0 listeners on :80. `msiexec /x ...msi /qn`: exit **0**.
  `sc query KryptkeeperAgent` -> 1060 (service gone); no `kryptkeeper-agent`
  process; `C:\Program Files\Kryptkeeper Agent` gone; event-source registry key
  gone; uninstall entry gone. `agent.env` retained by the MSI as documented.
- Then removed: `C:\ProgramData\Kryptkeeper` (agent.env, hub-ca.pem) and
  `C:\kkval094` (msi, zip, msiexec logs). No firewall rules or other settings were
  created or changed; zero rules named Kryptkeeper. No certificates were added to
  stores. Old Application-log entries (including the earlier v0.9.3 run's) remain:
  the event log was not cleared, as that is outside scope.
- lab-runner: hub and the HTTP file server stopped, `~/kkhub` (binary, env, hub data
  and CA, MSI/zip copies) removed, ports 8447 and 8099 not listening. The first
  cleanup attempt's `pkill -f` killed its own SSH shell before the `rm`; the
  directory was removed on a second call. Unrelated pre-existing files under
  `~` on lab-runner were not touched.
- Local: generated hub env, enrollment/admin secrets, agent credential file,
  fixture logs, and the hub binary deleted. No lab or generated secret was printed
  or committed (the agent token was handled in memory by a fixture script reading
  a 600 file).
- Lab note: the hub's `KRYPTKEEPER_CA_NAME` was set to a value with spaces in an
  unquoted env file, so the hub CA got a truncated name; cosmetic, lab-only.

## Summary of findings

| ID | Severity | Finding |
|---|---|---|
| F1 | low-medium | `:80` pre-check misses an IPv4-only holder on Windows (`acme_renewer.go:224-225`). |
| N1 | minor | Agent version not visible via hub API, startup log, or exe resource. |
| N2 | minor (carried) | ACME failure detail reported to the hub is empty after the colon. |

The v0.9.4 fixes behave as specified: renewals never overlap, failures are
reported with outcome `failed`, retries back off and grow, and the install refusal
happens before any ACME work.
