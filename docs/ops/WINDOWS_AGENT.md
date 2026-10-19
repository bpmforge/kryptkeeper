# Windows agent: build, install, run (W18-07)

**Status: verified 2026-10-06 on a real Windows 11 Enterprise VM (build 26100,
domain-joined to the UAT lab, `lab-win11`)** against a lab hub with agent
enrollment closed (the production default). All five checks at the bottom
passed: silent install registers an auto-start LocalSystem service that the
installer does not start; first start self-registers with
`KRYPTKEEPER_AGENT_ENROLLMENT_SECRET` and persists ID/token; the service is
Running again after a reboot without re-registering; `Stop-Service` returns in
0.1s; a malformed `agent.env` refuses to start in ~2s with the file and line in
Event Viewer (Application, source `KryptkeeperAgent`) plus SCM 7024; uninstall
removes the service and the event source and leaves `agent.env`. Agent log lines
go to the Application event log.

## Build (any host with Go and wixl; `apt install wixl` / `brew install msitools`)
```
make agent-windows-msi          # dist/kryptkeeper-agent-windows-amd64.msi
make agent-windows-msi-check    # asserts service registration rows
```
Set `VERSION=v1.2.3` for a real MSI version; a dev build gets 0.0.0, and
MajorUpgrade then refuses to replace a higher version.

## Install
1. `msiexec /i kryptkeeper-agent-windows-amd64.msi /qn`
2. `mkdir C:\ProgramData\Kryptkeeper`, copy `agent.env.example` from the install
   dir (`C:\Program Files\Kryptkeeper Agent`) to `C:\ProgramData\Kryptkeeper\agent.env`, set
   `KRYPTKEEPER_HUB_URL`, `KRYPTKEEPER_AGENT_ENROLLMENT_SECRET` (one of the
   hub's `KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS`; the hub refuses self-registration
   without it), and the hub CA file if the hub's certificate is self-issued.
3. Restrict the file, since the agent appends its token to it:
   `icacls C:\ProgramData\Kryptkeeper\agent.env /inheritance:r /grant SYSTEM:F Administrators:F`
4. Optional recovery policy (wixl cannot declare it):
   `sc.exe failure KryptkeeperAgent reset= 86400 actions= restart/60000/restart/60000/restart/60000`
5. `Start-Service KryptkeeperAgent`. First start registers and saves
   `KRYPTKEEPER_AGENT_ID/TOKEN` to `agent.env`; later starts reuse them.

The service is `Start=auto`, so it returns after a reboot. It is not started by
the installer, because without `agent.env` it would exit immediately.

## Certificate renewal: HTTP-01 needs inbound TCP 80
The agent renews certificates over ACME HTTP-01: for the duration of one
renewal it listens on port 80 and the hub's ACME CA connects to it to fetch
the challenge. Windows Defender Firewall blocks inbound 80 by default and the
MSI does not open it, so without a rule the order fails at the challenge.
Add a rule scoped to the agent program (adjust the path to your install):
```
New-NetFirewallRule -DisplayName "Kryptkeeper Agent ACME HTTP-01" -Direction Inbound `
  -Protocol TCP -LocalPort 80 -Program "C:\Program Files\Kryptkeeper Agent\kryptkeeper-agent.exe" `
  -Action Allow
```
Remove it with `Remove-NetFirewallRule -DisplayName "Kryptkeeper Agent ACME HTTP-01"`.

If something else already owns port 80 (IIS above all), the agent cannot bind
it. It fails the renewal at once with "port 80 in use or not permitted" and
reports that to the hub, instead of an opaque ACME error. For IIS hosts do not
use the agent for renewal: use the hub-driven agentless WinRM/IIS path, or
dns-01 at the hub. Setting `KRYPTKEEPER_WEB_ROOT` to the site's web root
(challenge file instead of a listener) also works when that site is served
over plain HTTP on port 80.

A failed renewal is retried with back-off (1 minute doubling to 1 hour, with
jitter), never concurrently, and its error is recorded in the hub's task
history.

## What the agent inventories
- **Certificate stores:** `LocalMachine\My`, `Root`, `CA` and `TrustedPublisher`
  (opened read-only; certificates only, never keys). Hub source labels are
  `windows-store:MY`, `windows-store:ROOT`, and so on.
- **Files:** PEM/CRT/CER and PKCS#12 (`.pfx`/`.p12`, default passwords
  `changeit` and empty) under the scan paths. Default scan paths on Windows:
  `%ProgramData%\win-acme`, `%ProgramData%\ssl`, `C:\nginx\conf`,
  `C:\Apache24\conf`, `C:\xampp\apache\conf` (missing ones are skipped).
  Set `KRYPTKEEPER_SCAN_PATHS` in `agent.env` to a comma-separated list to
  replace the defaults, e.g. `KRYPTKEEPER_SCAN_PATHS=C:\certs,D:\iis-certs`,
  then `Restart-Service KryptkeeperAgent`.

## Known limits
- **No install step on the Windows agent.** A task that carries install
  hints (a cert path for nginx/apache/haproxy) is refused with "install targets
  are not supported on the Windows agent; use agentless WinRM/IIS", and the
  refusal is reported to the hub (`outcome failed`). Installing into the
  Windows certificate store or an IIS binding is done by the agentless
  WinRM/IIS path. The agent is discovery-only on Windows.
- Runs as LocalSystem (the MSI default). Install-mode "agent" certificate
  installs into the machine store need that; a least-privilege account is a
  follow-up.
- Not code-signed (see `packaging/SIGNING.md`); SmartScreen will warn.
- ARM64 Windows is not built; amd64 runs under emulation.

## Verify on a Windows VM (free Windows 11 or Server evaluation)
1. Install per above; `Get-Service KryptkeeperAgent` is Running; hub shows the agent.
2. Reboot; the service is Running again without intervention.
3. `Stop-Service` returns promptly (the loop honours the SCM stop).
4. Break `agent.env` (a line with no `=`); `Start-Service` fails within seconds and
   Event Viewer (Application, source `KryptkeeperAgent`) names the file and line.
5. Uninstall via `msiexec /x`; the service is gone, `agent.env` is left in place.
