# W24-11: live SSH discovery harness

Real sshd container (ubuntu 24.04) planted with self-signed `kk-ssh-*`
certificates: nginx `web1`/`web2`, apache `site1`, a JKS (`app.jks`, two trusted
entries, password `changeit`), plus an unreadable file (`locked.crt`, 600 root)
and an unreadable directory (`/etc/apache2/ssl/locked`, 700 root). Two logins:
`root` and a non-sudo `scanner`. Container B has a different host key.

    bash tests/live/ssh-discovery/run.sh    # podman only, about 4 minutes

Asserted: root scan finds exactly the 7 planted certs (fingerprints from the
container, `source_path` equal to the planted path); scanner finds exactly 5 and
reports one `INSUFFICIENT_PRIVILEGE` (D-254) naming the 2 locked paths; a host-key mismatch fails the job with
both `SHA256:` fingerprints, imports 0 endpoints and writes
`target.hostkey.mismatch`; the scheduler (`KRYPTKEEPER_DISCOVERY_SCAN_INTERVAL=1m`)
creates a second ssh job without a POST; no line of the private key appears in
the hub log or audit dump (`credential string hits: 0`).
Counts cover the `kk-ssh-*` set only because the image also carries the system
CA bundle.

Decisions: JKS rows kept (W24-08 reads `*.jks`); `source_path` asserted with a
prefix match so a JKS entry may carry `path#alias`. The per-run public key is
`podman cp`ed into the container instead of bind-mounted, because a `/tmp`
bind mount is invisible to the podman VM on macOS. The host key is read from
the container (`ssh_host_ed25519_key.pub`) rather than by `ssh-keyscan`.
