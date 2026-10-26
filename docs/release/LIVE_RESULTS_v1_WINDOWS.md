# Live results v1: Windows (GPO autoenroll, IIS push)

Date: 2026-10-18. Hub: `lab-hub` 192.0.2.106 on `qa/v1-final` `936b3c7b`. Lab: `corp.example.test`.
Evidence: `docs/release/proof-pack/windows-v1/`. Matrix detail: `LIVE_RESULTS_FG2_WSTEP_MATRIX_v0.14.md`.

## Verdict: GPO autoenroll PASS on fixed hub (first pass FAIL, defect fixed); IIS push FAIL on discovery and install (defect in cmdQuote, 2026-10-18)

## Machine-context GPO autoenrollment

- First pass 12:15Z on `936b3c7b`: lab-win11 (VM 122, Windows 11 Enterprise 26200, 192.0.2.102) and lab-ws22 (VM 125, Server 2022, 192.0.2.104)
  authenticated by Kerberos and fetched XCEP policy, but issuance was refused: RSA-2048 vs `Baseline` (`min_rsa_bits` 3072). Regression
  since the 2026-10-08 proof; fixed by `eb765c4d` + `11faa7c4`.
- Second pass ~13:03Z on `11faa7c4`: after clearing `X509Enrollment` and `gpupdate /target:computer` + `certutil -pulse`, both enrolled
  `CN=<host>.corp.example.test`, RSA-3072, template KKMachine major 3, issuer `CN=KK UAT Lab Root CA`, in 6 s. Audit shows `wstep.enroll success` and
  `xcep.policy success` rows. Thumbprints 782D4CE3... (lab-win11), 3E988FB4... (lab-ws22). Evidence: `proof-pack/windows-v1/kk-*-enroll-ok/`.
- Result: PASS.

## IIS push (agentless, install_mode=iis over WinRM HTTPS), 2026-10-18

**Verdict: PASS on hub `82cdcb5b` (run 3).** Runs 1 and 2 failed on defects since fixed (kept below as history).

Setup: lab-ws22 (192.0.2.104, Server 2022, IIS role). Hub run locally on 127.0.0.1 only (nothing exposed on the LAN), fresh data dir,
`KRYPTKEEPER_WINRM_CA_CERT_FILE` = the exported listener certificate, temp local admin `kk-iis-test`, HTTPS listener per WINRM_ENABLEMENT steps
1-5 (IP SAN `192.0.2.104` confirmed, `AllowUnencrypted` false). The egress guard needed no allowlist. IIS had only `http *:80`, so a self-signed
`https *:443` binding was added as the prior binding to replace (its served leaf: sha256 F7:61:CB:9C:...).

| Step | Result |
|---|---|
| `POST /credentials/{id}/preflight` (windows_password, `ipport=0.0.0.0:443`) | PASS: `level=install`, can_discover and can_install true |
| `POST /discovery/scans` `winrm` | PASS: completed, 24 mapped certs, `server_tech=iis`, `recommended_install_mode=iis` |
| Issue leaf `CN=lab-ws22.corp.example.test` (SAN DNS+IP) from the hub CA, `POST /renewal/execute` | PASS: `install_outcome=installed_verified`, `verified=true`, `new_fingerprint` 3c39449c...c3fd |
| Independent `openssl s_client -connect 192.0.2.104:443 -servername lab-ws22.corp.example.test` from the Mac | PASS: leaf sha256 3C:39:44:9C:...:C3:FD equals `new_fingerprint`; issuer `O=Kryptkeeper, CN=IIS Test Root CA`; SAN `DNS:lab-ws22.corp.example.test, DNS:LAB-WS22, IP:192.0.2.104` |
| Audit | `certificate.renew_execute` outcome success with `key.generate_for_renewal` and `key.zeroize` rows. The `install_outcome` value is carried in the API response; the success row's change summary does not repeat `installed_verified` |
| Rollback: second renewal with `install.verify_host_port` pointed at `192.0.2.104:5986` (serves a different cert) | PASS: `install_outcome=verify_failed`, "served fingerprint does not match renewed cert", audit row `outcome=partial`, `install_outcome=verify_failed`. Port 443 still served 3C:39:...:C3:FD and the HTTP.sys binding kept hash a84b816f... (SHA-1 of that leaf); the rolled-back certificate was not left in `LocalMachine\My` |

Cleanup (verified on host): hub stopped by PID; `kk-iis-test`, HTTPS listener, firewall rule, test https/SSL bindings, all test certs
(`LocalMachine\My` back to 0), `C:\winrm-listener.*` and `C:\ProgramData\Kryptkeeper` removed; service `Basic` back to false; IIS and W3SVC left
running with `http *:80` only. (My first cleanup script's thumbprint filter missed three certs; they were then removed by thumbprint.)

### History: runs 1 and 2 (defects found, fixed)

- Run 1, `91546369`: discovery failed (`undecodable cert line`) and install said "appid required (no prior binding)". Cause: `cmdQuote` quoted base64
  padding (`=`). Fixed by `eb056a6e`.
- Run 2, `eb056a6e`: discovery passed (22 mapped certs; host held 23 distinct thumbprints, delta 1 consistent with the documented
  `crypto/x509` rejection) but install failed at the stage-dir ACL with `'#34' is not recognized`. Cause: `xml.EscapeText` sends `"` as `&#34;` and
  the Server 2022 command line receives it undecoded, so every quoted argument broke. Fixed by `82cdcb5b` (quotes sent literally).
- The Windows agent MSI was built (`make agent-windows-msi`) but not installed: enrolling it would have required exposing the hub on the LAN.
  Per code (`cmd/kryptkeeper-agent/main.go:334`, `docs/ops/WINDOWS_AGENT.md`) the Windows agent refuses install tasks, so it is discovery-only.

## Other

- Server 2025 row BLOCKED, Windows 10 and Server 2019 BLOCKED (no ISO): reasons in the matrix doc.
- VMs created: 125 lab-ws22 (192.0.2.104, domain-joined, IIS role, hub root added to `LocalMachine\Root`). Nothing else created.
- Kit fixes: `capture.ps1` pktmon stderr under WinRM; README notes.

## Windows agent (MSI, enrolled to lab-hub), 2026-10-18

**Verdict: PARTIAL PASS. Install, enroll, heartbeat, version, file discovery, key-safety, install-task refusal and uninstall PASS. One product bug: the agent does not inventory `LocalMachine\My` (F1).**

Hub: `lab-hub` 192.0.2.106, binary `v0.21.0-qa-11faa7c4e1` (older than branch head, not upgraded). Agent: built from `qa/v1-final` HEAD `b26b6d8a`
with `make agent-windows-msi VERSION=v1.0.0` (sha256 `dbfc8ed4...304ad0`; `--version` prints `kryptkeeper-agent v1.0.0 (commit unknown, built unknown)`,
since the Makefile only passes the version). VM: lab-ws22 (Server 2022, 192.0.2.104). Nothing was exposed on the LAN: the MSI went over WinRM
(base64-style chunks, 1581 parts, no file server) and its SHA-256 on the VM matched the Mac's. The hub's TLS chain is trusted by the VM's system store, so no
`KRYPTKEEPER_HUB_CA_CERT_FILE` was needed.

| Step | Result |
|---|---|
| Build MSI, copy over WinRM, hash match | PASS |
| Mint per-agent token `POST /api/v1/agent/enrollment-tokens` (bootstrap token, ttl 4h) | PASS (201; gate did not refuse) |
| `msiexec /i /qn` exit 0; service Auto, LocalSystem, Stopped after install | PASS |
| `agent.env` with `KRYPTKEEPER_ENROLL_TOKEN`, ACL SYSTEM+Administrators; `Start-Service` | PASS: registered, ID/token persisted, spent enrollment token scrubbed from `agent.env` |
| Hub `GET /api/v1/agents`: `lab-ws22-v1qa`, type windows, `active`, `last_seen` advancing every 20 s, `version "v1.0.0"` | PASS (v0.9.4 N1 is fixed: version is now in the API) |
| File discovery with `KRYPTKEEPER_SCAN_PATHS=C:\kkscan` | PASS: PEM and PFX (password `changeit`) reported; PFX with a non-default password skipped, logged "keystore, password unknown" |
| Machine store discovery | `windows-store:ROOT` 16 and `CA` reported; **`LocalMachine\My` NOT reported (F1)** |
| Private key bytes reach the hub | PASS: wire capture below |
| Windows agent refuses install tasks | PASS |
| Uninstall and cleanup | PASS |

### What it inventories

Count on the hub: 30 on first scan (28 distinct from stores + 2 files). A clean re-run after removing chain-cache copies from `LocalMachine\CA` gave 26:
ROOT 16, CA 8, PEM 1, PFX 1. Sources are labelled `windows-store:<ROOT|CA>`, the file path for PEM, `pkcs12:<path>` for PFX. The agent also
walks the three PEM/PFX test files only because `KRYPTKEEPER_SCAN_PATHS` was set (see F2).

### F1 (product bug): `LocalMachine\My` is not inventoried

Repro: on a Windows host put a cert in `Cert:\LocalMachine\My` (here `CN=kk-qa-store-my.corp.example.test`, created with `New-SelfSignedCertificate -CertStoreLocation
Cert:\LocalMachine\My`), install the MSI, start the service. The hub inventory (service run, SYSTEM, and a foreground run as Administrator, both captured)
never contains it; `Cert:\LocalMachine\Root` matched 1:1 (16). Cause: `internal/agentdiscovery/windows.go` opens stores with `windows.CertOpenSystemStore(0, name)`,
which opens the CurrentUser view. Root/CA/TrustedPublisher happen to be merged with the machine stores in that view, `My` is not, so the stores that hold server TLS
certificates (IIS, RDP, services) are missed. Fix: open with `CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, name)`.
The agentless WinRM scanner enumerates `Cert:\LocalMachine\My` correctly (`certEnumScript`), so the two paths disagree.

### Key safety

The agent was run in the foreground against a loopback mock hub on the VM (`127.0.0.1:18080`, PowerShell `HttpListener`, no network exposure) to capture the exact
`POST /api/v1/agent/inventory` body (12379 bytes, 30 certs). Fields per cert: `fingerprint, subject, issuer, not_before, not_after, source, auto_renewable,
dns_names`. The body contains no `PRIVATE` or `BEGIN` marker, and a 28-char slice of the private exponent (`D`) of the exported PFX key is absent. The
wire struct (`agentclient.DiscoveredCert`) has no key field. The hub never sees PFX bytes or passwords.

### Install tasks refused

Mock hub served a renew task with `server_type nginx`, `cert_path`, `key_path`, `reload_method`. Agent log: `task t-install-1: renew CN=kk-qa.corp.example.test` then
`install targets not supported on Windows agent in v0.9; use agentless WinRM/IIS`. Result posted: `outcome failed`, `rolled_back false`, same detail. No ACME
listener on :80, no files written. **F3 (cosmetic):** the message still says "in v0.9" at v1 (`cmd/kryptkeeper-agent/main.go:334`); `docs/ops/WINDOWS_AGENT.md` also says v0.9/v0.10.

### F2 (doc/behaviour): default scan paths are Linux paths on Windows

`main.go` defaults `scanPaths` to `agentdiscovery.DefaultLinuxPaths`, so on Windows no file discovery happens unless `KRYPTKEEPER_SCAN_PATHS` is set; `WINDOWS_AGENT.md`
does not mention the variable or `agent.env.example`. Low severity.

### Cleanup (verified)

`msiexec /x` exit 0: service, process, `C:\Program Files\Kryptkeeper Agent`, event-source key gone; `agent.env` retained as documented, then deleted with
`C:\ProgramData\Kryptkeeper`, `C:\kk` (MSI parts, logs, captures), `C:\kkscan`. All `CN=kk-qa-*` certs removed from every `LocalMachine` store (My back to 0, keys
deleted). Hub: `DELETE /api/v1/agents/{id}` 204 (record gone); revoking the enrollment token returned 409 "already redeemed or revoked" because it was single-use
and already redeemed at registration. Local token file deleted. A PFX password string and the `D` slice used for the leak check were throwaway test values.

### Re-validation after fixes F1-F3 (same day, commit `6408362c`)

**Verdict: PASS.** Agent rebuilt from the fix tree (`make agent-windows-msi VERSION=v1.0.1`, sha256 `6ca86eed...7ceb2f`, matched on the VM after the WinRM
chunk copy; `--version` now prints `kryptkeeper-agent v1.0.1 (commit 7ff9ab2811e1, built 2026-10-18T15:05:17Z)`: the Makefile passes commit and date; the
commit shown is the parent because the MSI was built just before the fix was committed). Hub unchanged (`v0.21.0-qa-11faa7c4e1`), new per-agent token, agent
`lab-ws22-v1qa` enrolled with no `KRYPTKEEPER_SCAN_PATHS` set, `inventory_count 27`, `version v1.0.1`, heartbeating.

- **F1 fixed:** stores are opened with `CertOpenStore(CERT_STORE_PROV_SYSTEM, ... CERT_SYSTEM_STORE_LOCAL_MACHINE|READONLY|OPEN_EXISTING)`. Captured inventory
  body (loopback mock hub, 27 certs): `windows-store:MY` 1 (`CN=kk-qa-store-my.corp.example.test`, the `LocalMachine\My` cert), `ROOT` 16, `CA` 8, files 2. Source label `windows-store:MY` kept.
- **F2 fixed:** with defaults only, the PEM and the PFX (`changeit`) placed in `C:\ProgramData\ssl` were found. Defaults: `%ProgramData%\win-acme`, `%ProgramData%\ssl`,
  `C:\nginx\conf`, `C:\Apache24\conf`, `C:\xampp\apache\conf`; `KRYPTKEEPER_SCAN_PATHS` documented in `docs/ops/WINDOWS_AGENT.md`.
- **F3 fixed:** a nginx-hinted task is refused with "install targets are not supported on the Windows agent; use agentless WinRM/IIS", `outcome failed`.
- **Key safety:** captured body has no `PRIVATE`/`BEGIN` marker and no slice of the throwaway key's private exponent.
- **Gate:** `go build ./...`, `GOOS=windows go build ./...`, `GOOS=windows go vet ./cmd/kryptkeeper-agent/ ./internal/agentdiscovery/`, tests for both touched packages, `make lint` all pass.
  The Win32-constant equality test is Windows-only (`windows_flags_windows_test.go`, compile-checked, not run on this Mac).
- **Cleanup:** MSI uninstalled (exit 0), service and install dir gone, test certs and keys removed (My 0), `C:\kk`, `C:\ProgramData\ssl`, `C:\ProgramData\Kryptkeeper` removed; agent record deleted on the hub (204); token was single-use and already redeemed.
