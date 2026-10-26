# Live results: Windows agent, v0.9.3 (origin/main 6561651f)

Date: 2026-10-15. Validation only; no product code changed. Windows host:
lab-win11 (Windows 11 Enterprise 26100, domain-joined to corp.example.test), reached over
NTLM-sealed WinRM (http 5985, `a WinRM helper script`). Hub: the v0.9.3-source
hub built linux/amd64, run on lab-runner (192.0.2.195:8447, TLS from the hub's
own CA, enrollment secret configured, closed registration). Agent and MSI built
from the same commit (windows/amd64, `wixl` 0.106). The MSI was copied to the
host by HTTP from lab-runner (non-secret artefact), checksum compared
(sha256 39643ecf...167e identical on both sides).

## Verdict

| Step | Result |
|---|---|
| 1. Read code/docs; no Windows release assets | PASS (finding F1, F2) |
| 2a. Cross-compile windows/amd64 | PASS |
| 2b. Hub on lab-runner reachable from lab-win11 | PASS (healthz ok; agent connected over TLS, CA from its CA file, no -k) |
| 3a. MSI install on real Windows (`msiexec /i /qn`) | PASS: exit 0, service KryptkeeperAgent, StartMode Auto, LocalSystem, State Stopped (not started by installer, as designed), path `C:\Program Files\Kryptkeeper Agent\kryptkeeper-agent.exe` |
| 3b. agent.env + start service | PASS: `Start-Service` 2.7 s (includes first registration); service Running, StartType Automatic |
| 3c. Enrollment with secret accepted | PASS: log "registered: agent_id=...", ID/token appended to `agent.env` (ACL SYSTEM+Administrators via icacls) |
| 3d. Agent online + heartbeat in hub API | PASS: `GET /api/v1/agents` shows `lab-win11-live093`, type windows, status active, `last_seen` advancing every 20 s (poll interval 20 s) |
| 3e. Inventory/discovery on Windows | PASS: 21 certificates reported (the same 18 the earlier W18-07 run saw from the Windows stores, plus 3 from the test PEM/config paths; breakdown not inspected), 1 endpoint parsed from a test nginx-style conf; hub `inventory_count`=21 |
| 3f. Stop/start, credential reuse | PASS: `Stop-Service` 54 ms, no :80 listener left; start 271 ms; same agent id, hub still lists exactly 1 agent |
| 3g. Hub queues a renew task; agent behaviour | PASS for queueing (task `renew CN=lab-win11.lan.internal` received); renewal itself FAILED, see F3 and F4. The install step (the predicted `sudo` path) was NOT reached: UNVERIFIED |
| 3h. Deploy a cert into the Windows cert store / file target | NOT SUPPORTED by the agent (F5); nothing to verify. Placement via certutil/Cert:\LocalMachine\My: not applicable |
| 3i. Uninstall (`msiexec /x /qn`) | PASS: exit 0; service gone (`sc query` 1060), no process, install dir gone, event-source key gone; `agent.env` retained by the MSI as documented (I then removed it and the staging dirs manually) |
| 4. WiX `.wxs` buildable off Windows | PASS (wixl on macOS; `msiinfo` rows match the Makefile check) and the resulting MSI installed and uninstalled cleanly on real Windows |
| Reboot persistence | NOT RUN this time (StartType Automatic observed; earlier W18-07 run proved it) |

## Findings

**F1 (gap): no Windows binary or MSI in the v0.9.3 release.** `.goreleaser.yaml`
sets `goos: [linux, darwin]` for the agent (and the other three binaries) and has no
MSI step. The v0.9.3 asset list (`gh release view v0.9.3`) has agent archives only for
darwin_arm64, linux_amd64, linux_arm64. `.github/workflows/agent-build.yml` builds
`kryptkeeper-agent-windows-amd64.exe` as a workflow artifact only, not attached to
the release; no workflow runs `make agent-windows-msi`. A Windows operator must
build the MSI themselves, although the MSI itself is good (3a, 3i).

**F2 (ops gap): MSI leaves no firewall/ACL help; stale settings.** `agent.env` is not
removed on uninstall (documented). Before this run lab-win11 still held an old
`C:\ProgramData\Kryptkeeper\agent.env` with an ID/token from the 2026-10-06 run
(it was overwritten here and removed at the end).

**F3 (bug-ish, default Windows install cannot renew via ACME HTTP-01): inbound :80 is
dropped by Windows Firewall.** With no `KRYPTKEEPER_WEB_ROOT`, the renewer opens its
own listener on :80 (`internal/agentclient/acme_renewer.go:185`). Observed on the host:
the agent process owns the :80 listener, but there is no enabled inbound allow rule for
port 80 and Domain/Private/Public profiles are on with default inbound NotConfigured
(block), and the MSI (`packaging/windows/kryptkeeper-agent.wxs`) adds no rule. From
lab-runner: TCP 135 and 5985 to the host open, TCP 80 times out (curl rc 28) while the
agent is listening. Hub log: `acme http-01 validation fetch failed ... context deadline
exceeded`; agent event log: `renew CN=lab-win11.lan.internal: wait authorization: acme:
authorization error for lab-win11.lan.internal: ` (error detail empty, which hides the
cause). I did not add a firewall rule, as that is outside the allowed scope, so a
successful renewal and the install step are UNVERIFIED. The docs
(`docs/ops/WINDOWS_AGENT.md`) do not mention that port 80 must be opened.

**F4 (bug, observed): a pending task is re-dispatched every poll with no in-flight
guard.** `cmd/kryptkeeper-agent/main.go:234` does `go renewAsync(...)` for every
returned renew task on every cycle. With the 20 s poll used here, the first renewal
holds :80 (waiting up to its 5 min timeout) and the next one fails with
`serve http-01 challenge: listen :80 ...: Only one usage of each socket address ...
is normally permitted`. Note the 300 s default poll is close to the 5 min renew timeout,
so overlap is possible by default too, but I only observed it at 20 s. The task also
stays queued after failure, so it is retried forever.

**F5 (design gap, from source; install step not exercised): no Windows deploy target in
the agent.** Renewal installs call `agentinstall.New(agentinstall.NewSudoExecutor())`
(`cmd/kryptkeeper-agent/main.go:266`). The installer supports nginx/apache/haproxy file
placement with `sudo install` (`internal/agentinstall/installer.go`, `executor_sudo.go`);
there is no certificate-store or Windows-path/IIS target in the agent (IIS exists only
in the hub-driven agentless WinRM path, `iis.go`/`executor_winrm.go`). The hub also does
not "push" deployments to agents: the agent pulls tasks and handles only
`Action == "renew"`. The predicted `sudo` failure was therefore not observed (renewal
fails earlier, F3); on Windows it would be expected to fail at the install step.
UNVERIFIED.

## Cleanup

lab-win11: service/files/event-source removed via MSI; `C:\ProgramData\Kryptkeeper`,
`C:\corp-live`, `C:\corp-stage` removed; no firewall or other settings touched;
no certificates were added to the cert stores. lab-runner: hub and HTTP file server
stopped, `~/kkhub` removed, ports 8447/8099 not listening. Local: generated secrets,
env and PowerShell files deleted from the scratchpad. No lab secret was printed.
The hub's data dir (CA, tokens) was on lab-runner only and is gone. lab-dc01 untouched.
