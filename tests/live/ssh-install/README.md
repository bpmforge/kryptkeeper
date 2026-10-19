# W19-02 / W27-08 — SSH agentless install UAT (nginx, apache, HAProxy, Tomcat)

Proves the hub's `POST /api/v1/renewal/execute` SSH install path against a
REAL sshd host running real nginx and real apache: renew, install over SSH,
reload, verify the served leaf independently, and prove rollback on a
verify mismatch. This is the Linux twin of the WinRM/IIS loop closed
2026-08-20/2026-09-10 (see `docs/STATUS.md`).

## Run

```
bash tests/live/ssh-install/run.sh
```

Requires `podman` (not docker), `go`, `openssl`, `python3`. Idempotent:
removes and rebuilds its own containers, PASS/FAIL per step, non-zero exit
on any failure, cleans up (containers, hub process, temp dirs) on exit via
a trap — including on failure.

## What it builds

- One Containerfile (`ubuntu:24.04` + `openssh-server`, `nginx`, `apache2`)
  run as TWO containers from the same image (`ROLE=nginx` / `ROLE=apache`
  selects which server actually serves TLS — both default to :443, so one
  container can only run one). Ports: `2222`/`2223` -> sshd, `8443`/`8444`
  -> the server's TLS vhost.
- A placeholder self-signed cert/key baked in at build time at
  `/etc/ssl/kk/server.crt|key` (the paths the install profile also names),
  so the "before" state is a known, non-hub-issued identity.
- Host keys and the SSH keypair used to reach the containers are both
  generated at **run time**, never committed: `run.sh` generates a fresh
  ed25519 keypair per invocation into a `mktemp` dir and deletes it on
  exit; the container entrypoint deletes and regenerates its own sshd host
  keys at every container start (see `entrypoint.sh` comment for why —
  `openssh-server`'s own `apt` postinst already bakes one set into the
  image, which would give both containers the SAME host key otherwise).
- A hub built from this checkout (`go build ./cmd/kryptkeeper`), run with
  `AUTH_MODE=bootstrap`, `APP_CERTIFICATE_PROVIDER=ca`, a fresh sqlite data
  dir under `/tmp`, and `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true`.

## HAProxy and Tomcat roles (W27-08)

The same image also carries `haproxy` (Ubuntu 2.8) and Tomcat 10.1 under
`/opt/tomcat` (tarball pinned by version and sha512 in the Containerfile; the
build fails on a checksum mismatch). `ROLE=haproxy|tomcat` selects them. There
is no systemd in the container, so `systemctl-shim.sh` is installed as
`/usr/local/bin/systemctl` and maps exactly `reload haproxy` (haproxy `-sf`
handover) and `restart tomcat` (`catalina.sh stop 10 -force` then `startup.sh`);
any other unit or verb exits non-zero so a wrong unit name fails visibly.

- HAProxy: `haproxy-kk.cfg` binds `*:443 ssl crt /etc/ssl/kk/haproxy.pem`
  (one file, chain then key). Target profile: cert path = key path =
  `/etc/ssl/kk/haproxy.pem`, no reload method (installer default, systemctl).
- Tomcat: `tomcat-server.xml` has one HTTPS connector reading the PKCS#12
  keystore `/opt/tomcat/conf/kk.p12`. Target profile: cert path = key path =
  that keystore; the `ssh_key` credential carries `keystore_password`.
- The keystore password is a **fixture-only constant** (`kk-uat-fixture-pw`,
  protecting a throwaway self-signed key). `run.sh` greps the hub log and the
  audit log for it at the end; it must appear 0 times.
- Both servers additionally run a **config-test failure** case: the live
  config is broken (`invalid-directive` appended to `haproxy.cfg`; `</Server>`
  stripped from Tomcat's `server.xml`), a renewal is executed, and the run
  asserts `install_outcome=config_test_failed`, the old serial is still served
  (both daemons keep their in-memory config), and the installed file's sha256
  is byte-identical to before the attempt. The config is repaired afterwards.
- The host-side TLS read after each install allows up to 60 s (Tomcat's JVM
  restart is slow); the elapsed seconds after the install response are printed.
- `run.sh` prints `checks: N passed` before `ALL PASS`.

Recorded results: `docs/release/LIVE_RESULTS_SSH_INSTALL_v0.15.md`.

## What it proves, per server type (nginx, apache, haproxy, tomcat)

1. `ssh_key` credential (user, private key, **pinned host public key**,
   port) stored via `POST /api/v1/credentials`.
2. `ssh` install-mode target created (`install_server_type`,
   `install_cert_path`/`install_key_path` = the placeholder's paths,
   `install_reload_method: binary` — these containers have no systemd).
3. A certificate issued from the hub's own root CA for
   `kk-uat-<type>.local`.
4. `POST /api/v1/renewal/execute` with the correct `verify_host_port` ->
   asserts `install_outcome: installed_verified`, then independently
   `openssl s_client`-dials the container and asserts the served leaf's
   SHA-256 fingerprint equals the response's `new_fingerprint`.
5. **Negative case / rollback proof**: a second renewal pointed at the
   OTHER container's `verify_host_port` (guaranteed mismatch) ->
   asserts `install_outcome: verify_failed`, then independently re-dials
   the ORIGINAL (correct) port and asserts it is still serving the
   previous good cert from step 4, not the just-rejected one and not the
   original placeholder.

## Real defect found and fixed on this branch (not a fixture-only issue)

`internal/agentinstall/executor_ssh.go`'s `ssh.ClientConfig` never set
`HostKeyAlgorithms`. A real sshd (Ubuntu's default `ssh-keygen -A`) serves
rsa+ecdsa+ed25519 host keys simultaneously, and
`golang.org/x/crypto/ssh`'s default negotiation order prefers RSA over
Ed25519. A caller pinning an Ed25519 host key via `ssh.FixedHostKey` (which
is exactly what `internal/bootstrap/renewal_executor.go` does with the
credential's `host_public_key`) got RSA negotiated instead, and the pinned
key never matched — `ssh: host key mismatch` against a host whose pinned
key was, in fact, correct. Fixed by threading the pinned key's own
algorithm through as `HostKeyAlgorithms`; see
`TestSSHExecutor_HostKeyAlgorithms_RequiredForMultiHostKeyServer` in
`internal/agentinstall/executor_ssh_test.go`, which reproduces the failure
against a two-hostkey in-process test server and proves the fix.

A second real gap: `Installer.Install`'s verify-after-install step dialed
exactly once, immediately after issuing the reload command. Both
`nginx -s reload` and `apachectl -k graceful` return as soon as the signal
is sent, not once new workers are actually serving — dialing immediately
can catch an old worker mid-handover and see the stale cert, which would
roll back a perfectly good install. Fixed with a small bounded
retry-until-match loop (`verifyUntilMatchOrExhausted`,
`internal/agentinstall/installer.go`); existing `TestInstall_Verify*` tests
cover the exhausted-retry path.

## Known limitation

`docs/board/plan.json`'s acceptance bullet calls for a gated
`tests/live/ssh-install/*_live_test.go` Go test with an env switch,
matching this repo's other `*_live_test.go` UAT gates (e.g.
`internal/agentdiscovery/live_winrm_test.go`). This UAT was built as a
shell fixture (`run.sh`) instead, per this ticket's actual execution
instructions. No Go-test wrapper exists yet; `run.sh` is the gate for now.
