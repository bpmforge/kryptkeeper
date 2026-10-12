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

## Known limits
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
