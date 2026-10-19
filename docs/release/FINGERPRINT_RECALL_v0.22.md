# Fingerprint recall and privileged agentless proof, v0.22

Measured on 2026-10-18 by `tests/live/fingerprint-corpus/run.sh` and
`tests/live/agentless-sudo/run.sh`, against real servers in containers, with the
scanner and hub built from this branch. Nothing here is a projection.

## 1. Fingerprint corpus

17 listeners across 13 technologies (nginx, Apache httpd, Tomcat on a JKS, OpenLDAP
over StartTLS and LDAPS, Postfix, Dovecot on four ports, MySQL, SQL Server, PostgreSQL,
Redis TLS, Vault, a Kubernetes API stand-in, a WinRM/http.sys stand-in). Ground truth
is `expected.json`, written from what compose starts, never from the scanner. Each
scan targets bare hostnames on the container network, so the catalogue sweep (full) and
the port sweep (deep, ports 1-9999 plus the catalogue) both had to find the services.

| | full | deep |
|---|---|---|
| expected / correct / wrong / missed | 17 / 17 / 0 / 0 | 17 / 17 / 0 / 0 |
| **recall** | **100%** | **100%** |
| **precision** (correct / all non-unknown claims, unexpected endpoints included) | **100%** | **100%** |
| **high-confidence wrong answers** | **0** | **0** |
| confidence of the correct answers | high 2, medium 12, low 3 | high 2, medium 12, low 3 |
| TLS stack (deep, 10 implicit-TLS listeners) | n/a | 10 correct, 0 unknown, 0 wrong |

Release gate (recall >= 90%, zero high-confidence wrong): **passes in both modes.**

Read the number with these in mind:

- **Recall at medium or better is 14 of 17 (82%).** PostgreSQL, Redis TLS and Vault are
  right only because their well-known port is a weight-10 signal; they stay `low` and
  would never drive an install recommendation. Their HTTP or protocol tells are not read
  (Vault's port is not HTTP-probed; Redis and PostgreSQL need an authenticated or
  protocol-specific exchange).
- **High confidence is two cases:** SQL Server (TDS PRELOGIN plus the
  `SSL_Self_Signed_Fallback` certificate) and the WinRM stand-in (HTTPAPI header plus the
  401 Negotiate challenge).
- **The corpus is self-authored** (D-271). It proves the tells work on these builds, not
  that recall holds on an arbitrary estate. Treat 100% as an upper bound.
- On arm64 the SQL Server 2022 image segfaults under emulation, so the corpus runs Azure
  SQL Edge (the same TDS engine, native arm64); amd64 runners use the server image.
- The Kubernetes and WinRM entries are stand-ins that serve the documented responses of
  kube-apiserver and http.sys; they are not those products.

### What running the corpus found and fixed

| Found | Fix |
|---|---|
| Tomcat 10 sends no `Server` header and no cookie for an empty root, so it was missed | its 404 error report (`<h3>Apache Tomcat/x</h3>`) is now a body tell |
| SQL Server's default certificate has a **negative serial number**; Go refused to parse it, so every default SQL Server failed the handshake | `go.mod` enables `x509negativeserial` (parse leniency only, D-270); regression test patches a real certificate |
| the JSSE signature in the TLS stack table was a wrong prediction | corrected from a real Tomcat/JDK 17 (`0017,0023,ff01`) |
| `wait` in the harness gave later services no attempt once the deadline passed (made 7 healthy services look down) | per-target concurrent wait with at least one attempt each |

TLS stack table (`testdata/tls_stack_table.json`): openssl (two signatures), go (two) and
jsse are now `verified:true`. schannel, boringssl, gnutls and nss remain unverified.
Stock Tomcat with tcnative reads as `openssl`, not `jsse`.

Confirmed against real containers (recorded in the W34-03/04/05 specs): the OpenLDAP
rootDSE tell over StartTLS and LDAPS, the MySQL greeting/SSLRequest framing, and the TDS
PRELOGIN plus TDS-framed TLS handshake.

## 2. Privileged agentless scan on a hardened host

One hardened image (sshd `PermitRootLogin no`, key auth only, `Defaults requiretty`,
nginx master as root with a root:root 0600 key, Tomcat as `tomcat` with a root:root 0600
JKS and PKCS12 under `/opt/ssl`), three containers (helper, nopasswd raw allowlist,
password), a real hub container, the scan account `kkscan`. The sudoers drop-in and the
helper are the ones the hub's own privilege-bundle endpoint returns.

Per mode, asserted live: unprivileged scan reports INSUFFICIENT_PRIVILEGE naming the
keystores and the fix; with the bundle installed the privileged scan reads the JKS and
PKCS12 certificates; the nginx key is never read (its bytes appear in no hub log, audit
row or database file); listener correlation yields `nginx` and `tomcat` at **high**
confidence; PRIVILEGED_INSTALL_PATH is raised on the JKS; a renewal replaces the nginx
certificate through privexec; a failing `nginx -t` rolls back with the old certificate
still served and the file byte-identical; and, in password mode, the sudo password is in
no hub log, audit row or data file.

**Result: ALL PASS, 50 checks (helper, nopasswd and password), 0 failed.** The sudoers
and helper installed were the hub-generated bundle each time (the nopasswd rule was
fetched with `scan_paths=/opt/ssl`; with the install directory alone it correctly cannot
read the keystores). In nopasswd mode the scan still reports INSUFFICIENT_PRIVILEGE for
`/etc/ssl/private`, a root-only directory the rule does not cover, and never for the
keystore or install directories.

Deviation from the ticket text: the unprivileged scan does not name the nginx key as
unreadable. The key's ownership is available to `stat` without privilege, and the scan
never reads keys, so it is not an unreadable path; the keystores are.

### What running it found and fixed

| Found | Fix |
|---|---|
| a failed remote read lost `cat`'s stderr, so an unreadable keystore showed as "exit status 1" and was missing from INSUFFICIENT_PRIVILEGE | the SSH executor keeps the first line of stderr |
| helper mode: a missing scan root made the helper print "not a directory", which the scanner read as a file path and tried to `read-cert` | a failed helper `list` is rewritten to find's own diagnostics |
| helper mode returns a keystore's certificates as PEM, but the scanner parsed it as a binary keystore ("bad magic") | PEM output is parsed as certificates |
| the helper opened PKCS12 keystores (the default type on JDK 11+) with an empty password only | it tries `changeit` first, as the hub does unprivileged |
| `golang.org/x/crypto/pkcs12` cannot read the SHA-256 MAC keytool writes ("unknown digest algorithm") | fall back to go-pkcs12 |
| helper mode surfaced every non-ASCII world-readable file (ca-certificates "Főtanúsítvány") as an unreadable path | that one refusal falls back to the account's own read |
| nopasswd/password mode: a root outside the sudoers rule answered "sudo: a password is required", which was read as file paths | refusals are skipped and the root is scanned with the account's own permissions |
| the privilege bundle only covered the install directory, so a nopasswd scan could never read keystores elsewhere | `scan_paths` query parameter |

## 3. Human-only lab items (not coverable in containers)

Active Directory (the rootDSE capability OID, domain controller certificate templates,
AD CS issuance) and 389 Directory Server rootDSE; F5 BIG-IP and Citrix ADC (cookie and
header tells are fixture-tested only); Fortinet, Palo Alto, VMware, iDRAC/iLO and other
appliance certificate tells; Exchange (OWA title and SMTP greeting); schannel, boringssl,
gnutls and nss TLS signatures; real kube-apiserver and http.sys responses; amd64 SQL
Server 2022 on native hardware; Windows posture (WinRM key ACLs, http.sys bindings).

## 4. Not done here

- `tests/live/agent` assertion for the W34-09 agent report: not run; it needs the full
  hub-plus-agent harness and was left alone rather than half-checked.
- Enabling the W33-26 Blocked-state Playwright journey: the hardened `kkscan` host now
  exists, but the journey also needs the compose hub and Playwright run, which was not
  attempted; the `test.fixme` stays.
