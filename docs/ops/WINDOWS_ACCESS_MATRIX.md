# Windows access matrix

Every channel by which Kryptkeeper can reach a Windows host to discover or
install certificates — including the ones we have **considered and declined**,
because a thoroughness audit needs the declined column as much as the shipped
one.

Written 2026-08-27 while unblocking the W18 live IIS install against
<windows-host>. Board: W18-06 … W18-09.

## The distinction that governs everything

**Pull channels** — the host fetches its own certificate. No inbound
management port, no credentials stored by Kryptkeeper.
**Push transports** — Kryptkeeper reaches in and installs. Requires an open
port, a stored credential, and an authenticated session.

A domain-joined Windows estate should be served by *pull*. Push is the answer
for the unmanaged, non-domain-joined box. Confusing the two leads to
recommending credentialed push where a domain would rather have autoenrollment.

## Pull channels (shipped)

| Channel | Package | Fits | Status |
|---|---|---|---|
| MS-WSTEP CES | `internal/wstep` | Domain-joined Windows; AD autoenrollment, GPO-driven | Built; **never verified against a real domain-joined client** (W18-08) |
| SCEP | `internal/scep` | Intune/MDM; `handlers_integrations.go` selects SCEP vs WSTEP+XCEP | Built |
| Agent | `cmd/kryptkeeper-agent` | Any Windows host; `walk_windows.go` reads real stores via `CertOpenSystemStore` | Builds for `GOOS=windows`; **no MSI, no service registration, no release artifact** (W18-07) |
| ACME | `internal/acme` | Anything speaking ACME | Built |
| EST | `internal/est` | Standards-based enrolment | Built |

## Push transports

### WinRM / WS-Man — shipped, `internal/agentdiscovery/agentless_winrm.go`

WS-Management (SOAP/XML over HTTP), hand-rolled on stdlib — no PSRP binary
framing, so no dependency. This is the transport behind `discovery_mode=winrm`
and `install_mode=iis`.

**The client speaks HTTP Basic only.** That is not sufficient against a
default-configured Windows host, for two independent reasons:

1. **Auth.** A stock listener offers `Negotiate` (and `Kerberos`) and *not*
   `Basic`. Our request gets a 401 before anything else happens.
2. **Message encryption.** `AllowUnencrypted=false` is a **message-layer**
   requirement, separate from auth. Over HTTP, WinRM rejects an unencrypted
   SOAP body even after authentication succeeds. Real clients satisfy this by
   SPNEGO/NTLM-*sealing* the payload (`multipart/encrypted`).

Both are satisfied at once by **HTTPS on 5986**: TLS is the encryption, so
`AllowUnencrypted` stays `false`, and Basic over TLS is a legitimate
configuration. That is what W14-02 designed for and it needs no new client
code — only a listener certificate and hub-side trust (W18-06, **done and
live-verified 2026-09-10** against a real Windows 11 host: discovery as a
standard user, install as Administrator, both over the trusted HTTPS
listener). Credential privilege level is now checkable before install via
the W18-11 preflight endpoint, and the install path itself (import + bind +
verify in IIS) was proven live in W18-13.

Auth mechanisms, sized:

| Mechanism | Verdict |
|---|---|
| Basic over HTTPS | **The supported path. Shipped and live-verified (W18-06, 2026-09-10).** |
| Basic over HTTP + `AllowUnencrypted=true` | **Lab only.** Password crosses the wire in base64 cleartext and two hardening defaults must be disabled. Never document as production |
| Negotiate / NTLM | Auth alone is insufficient — without sealing, `AllowUnencrypted=false` still rejects the body. `github.com/Azure/go-ntlmssp` (already an indirect dep) is explicitly *"authentication, no key exchange or encryption"*. **W18-09 (2026-10-05): built.** NTLMv2 + RC4 sealing + `multipart/encrypted` framing over plain http, used automatically for `http://` endpoints; Basic is never sent over http. Verified against an independent NTLM implementation and a verifying fixture, **not yet against a real Windows listener** (see `docs/ops/WINRM_ENABLEMENT.md`, HTTP fallback) |
| Kerberos | Domain-joined only; such hosts should use WSTEP pull instead |
| Client certificate | The dogfooding answer — no password on the wire. Needs an HTTPS listener plus `WSMan:\localhost\ClientCertificate` mapping. Folded into W18-06's follow-on |
| CredSSP | Declined. Delegates full credentials to the remote host; unacceptable in a PKI product |

### SSH — shipped for POSIX, **not** a free Windows win

`internal/agentinstall/executor_ssh.go` exists and Windows OpenSSH Server is a
first-class optional feature, so "just use SSH" looks cheap. It is not:

- `install_mode` is a flat CHECK (`'agent','ssh','f5','citrix','k8s','iis','cloud','acme'`).
  `iis` and `ssh` are **mutually exclusive values** — "IIS installer driven over
  SSH" cannot be expressed in the schema today. That is a migration plus a
  routing change in `renewal_executor.go`'s switch.
- The executor is POSIX-shaped: `/tmp/kk-ssh-install-` staging paths and
  single-quote `sh -c` joining (`shellQuote`/`shellJoin`). Against Windows
  OpenSSH's cmd.exe default shell it would need the same wrapping
  `executor_winrm.go` exists to provide.

Not declined — deferred, with the cost recorded so nobody re-proposes it as easy.

## Considered and declined

| Transport | Ports | Why declined |
|---|---|---|
| **DCOM / WMI over MS-RPC** | 135 + ephemeral | The "RPC" path, and genuinely how much of the Windows ecosystem works. In Go without CGO, implementing DCOM activation and the MS-RPC stack is a major undertaking for a transport that reaches nothing WinRM cannot. Revisit only if a customer estate blocks 5985/5986 but allows 135 |
| **SMB / named pipes** | 445 | psexec-style service creation, `ADMIN$` copy, remote registry. Same implementation cost as DCOM, **plus** it is indistinguishable from lateral-movement tradecraft to any EDR on the box. We would be teaching customers to allowlist us for behaviour their security team is paid to block |
| **RDP** | 3389 | Interactive only. Not automatable for unattended renewal |
| **CredSSP** | via WinRM | Delegates the full credential to the remote host. A PKI product does not ship credential delegation as a convenience |

Field note: on <windows-host>, **445 and 3389 were both closed** while 5985 was
open — so on a representative host neither declined transport would have
reached it anyway.

## Reference: reading a host's posture

```powershell
winrm get winrm/config/service
```

```
AllowUnencrypted = false          # message-layer requirement, NOT auth
Auth
    Basic       = false           # why a Basic-only client gets 401
    Negotiate   = true            # what a stock host actually offers
    Certificate = false
CertificateThumbprint             # empty => no HTTPS listener => 5986 closed
```

That block is stock, correctly-hardened Windows. Nothing about it is
misconfigured — a Basic-only client is simply the wrong shape for it.
