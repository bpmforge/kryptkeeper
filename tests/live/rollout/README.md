# W27-16 — Live rollout group UAT (3 nginx nodes, injected flip failure)

Proves cluster-atomic staged rollout (`POST /api/v1/renewal/rollout`, W27-15)
against three REAL nginx + sshd containers.

## Run

```
bash tests/live/rollout/run.sh
```

Requires `podman` (running machine), `go`, `openssl`, `python3`, `ssh`/`ssh-keyscan`.
Takes about 4 to 7 minutes (images, hub build, three rollouts). It builds the
`tests/live/ssh-install` image into a temp context (the Containerfile COPYs
`authorized_keys`, so the generated key is written there, never into the repo),
adds the fault-injection layer from this directory, starts `n1 n2 n3`, builds
the hub from the checkout and drives it over HTTP. Containers, network and
images carry a per-run id and are removed by an exit trap.

## What it proves

1. **Case A, happy path**: all three nodes `installed`, `mode=staged`,
   `halted=false`; each node serves the new fingerprint (`new_fingerprint`);
   canary first (`stat -c %z` of the live cert, n1 <= n2 <= n3); no residue.
2. **Case B, node 3 fails at flip**: `halted=true`, outcomes
   `rolled_back, rolled_back, failed`; the published TLS ports of all three
   nodes serve one byte-identical fingerprint, the OLD one (3 of 3); the
   rejected new certificate is served nowhere; no residue.
3. **Case C, canary fails at flip**: outcomes `failed, skipped, skipped`; all
   three nodes still serve the old fingerprint; no residue.

"No residue" means `/etc/ssl/kk` on every node holds exactly `server.crt` and
`server.key` (no `.kk-staged`, no `.kk-prev`; the image's unrelated
`haproxy.pem` fixture is ignored).

## Fault injection

`nginx-flipfail.sh` is installed as `/usr/local/bin/nginx`, ahead of
`/usr/sbin/nginx` on the sshd PATH (asserted with `command -v nginx`). While
`/etc/kk-fail-reload` exists it fails exactly one `nginx -s reload` (and
removes the marker, so the restore's best-effort reload succeeds); every other
invocation, including `nginx -t`, is the real nginx. Targets use
`install_reload_method: binary`, so the flip's reload is `nginx -s reload`.
Each case re-arms the marker with `podman exec <ctr> touch /etc/kk-fail-reload`.

## Notes

- Case C rolls out the head of the certificate chain (`NF2`), not `NF1`: case B's
  renewal minted `NF2` even though no node kept it, so a second rollout of `NF1`
  returns HTTP 409 `conflict` whose body names `successor_fingerprint` (`NF2`),
  so the operator rolls that one out; the hub never re-mints implicitly
  (W27-15 follow-up). The nodes still serve `NF1` in case C.
- No key material is committed; the SSH keypair is generated per run.

## Last recorded run

Machine-readable: `last-run.json` (written by `run.sh`).

2026-10-16, Darwin arm64 (Apple M4 Max), podman 6.1.3, base commit `8ffc5d86`
plus the W27-16 harness: **ALL PASS**, 252 s. Case A PASS, Case B PASS,
Case C PASS. The release lane copies this into
`docs/release/LIVE_RESULTS_v0.15.md`.
