# W19-06 — AD LDAP sync UAT (Samba AD DC)

Proves the hub's directory-sourced certificate inventory pull against a REAL
Active Directory domain controller.

## What this actually tests (read the code first)

Kryptkeeper has two independent AD-facing surfaces that are easy to conflate:

- `internal/adsync/` (W17-10, `POST /api/v1/adsync/templates`) is a **write**
  path — it publishes kryptkeeper's certificate templates into AD's
  Configuration naming context (`pKICertificateTemplate` objects) so Windows
  clients can auto-enroll. It never reads users, computers, or certificates
  out of AD.
- `internal/bootstrap/inventory_source_adcs_live.go` (W13-04, the `adcs_live`
  `InventorySource`, reached via `POST /api/v1/inventory-sources` +
  `POST /api/v1/inventory-sources/{id}/sync`) is the **read** path — it binds
  over LDAP, runs a paged subtree search for `userCertificate`, and lands
  every parseable DER blob into the hub's estate with `origin=synced`,
  `management_state=external`.

This fixture exercises the read path (`adcs_live`) plus the advisory,
AD-independent `POST /api/v1/adsync/gpo-check` endpoint (which validates a
*submitted* GPO config — it makes no LDAP call of its own).

`adcs_live`'s `Fetch` does not distinguish users from computers or track
per-object identity — it just returns every `userCertificate` value under
`search_base` matching `filter` (default `(userCertificate=*)`). "Sync counts"
below means certificates synced, not directory-object counts.

## Topology

- podman only. Samba AD DC (`docker.io/nowsci/samba-domain`) runs as a
  container publishing 389/636 on `127.0.0.1:3389`/`127.0.0.1:6636` (high
  ports so the fixture doesn't need root).
- The hub runs on the host (as in every other `tests/live/*` fixture) and
  reaches the DC over those published ports.
- Realm `CORP.LOCAL`. Seed: 3 users (alice, bob, carol), 2 computers
  (WKSTN01, WKSTN02), a dedicated `kkhubsync` bind account, and real
  self-signed EC certificates attached to alice's and bob's `userCertificate`
  attribute via `ldapmodify`.
- No secrets committed: the domain admin password and the LDAP bind password
  are generated fresh into a `mktemp` dir on every run.

## Run

```
bash tests/live/ad-ldap/run.sh
```

Idempotent (removes and recreates the container/volume/hub every run),
PASS/FAIL per step, non-zero exit on any FAIL, cleans up on exit via `trap`.

## Gated Go live test

`adldap_live_test.go` is skipped unless `KK_LIVE_ADLDAP=1`. It assumes the DC
and hub from `run.sh` are already up (or an equivalent manual setup) and
proves the acceptance criterion `run.sh`'s single pass can't: attaching a
*new* certificate to a directory object and confirming the very next sync
picks it up, with no hub restart or source re-registration. See the file's
header comment for the required `KK_ADLDAP_*` env vars.

## Run it with a ROOTFUL container engine (resolved 2026-10-06)

Samba AD provisioning stores NT ACLs as `security.NTACL` xattrs, and
**rootless** podman refuses `security.*` xattrs even under `--privileged`.
smbd then panics during sysvol setup (`Security context active token stack
underflow`). This was first blamed on the Mac's podman machine (2026-09-10).
On 2026-10-06 the identical panic reproduced on native amd64 Ubuntu 24.04
under rootless podman, a direct `setfattr -n security.test` was denied
rootless and allowed rootful, and the full fixture plus the gated live test
then passed under rootful podman on the UAT hub VM.

```
printf '#!/bin/sh\nexec sudo podman "$@"\n' > ~/bin/podman-root && chmod +x ~/bin/podman-root
CONTAINER_ENGINE=$HOME/bin/podman-root bash tests/live/ad-ldap/run.sh
```

`CONTAINER_ENGINE` must be a single path (the script quotes it), and the
gated Go test reads the same variable. `run.sh` still fails fast with the
panic diagnosis if it is run rootless.

## Samba is unsupported for adcs_live

The Samba AD DC fixture (`run.sh` here) cannot run the AD CS path:
samba-domain provisioning failed on this fixture (FEATURE_VALIDATION_v0.9
row 88) and Samba has no AD CS role. `adcs_live` is validated ONLY against a
Windows DC via `windows/run.sh` (W24-27; see `windows/README.md`). The Samba
fixture remains useful for the generic LDAP read path.
