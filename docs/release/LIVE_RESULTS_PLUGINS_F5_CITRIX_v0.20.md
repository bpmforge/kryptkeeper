# Live validation W32-06: F5 BIG-IP and Citrix ADC delivery plugins on real appliances - v0.20

Status: **PENDING-RUN - NOT validated.** NOT RUN: no BIG-IP VE or Citrix ADC VPX
licence/VM was available to the build host. The harness is complete and
syntax/shellcheck clean, and refuses to run (exit 2) without appliance env; it has
never executed against a real device. Every measured field below is PENDING-RUN.
No result is claimed. The plugin manifests keep "(not yet verified on a real
device)" until W20-22 renames them after a green run.

Harness: `tests/live/plugins/vendor/run.sh --vendor f5|citrix`
(setup in `tests/live/plugins/vendor/README.md`).

```
set -a; . ../vendor.env; set +a
bash tests/live/plugins/vendor/run.sh --vendor f5
bash tests/live/plugins/vendor/run.sh --vendor citrix
```

Required env: `VENDOR_BASE_URL`, `VENDOR_USER`, `VENDOR_PASS_FILE`,
`VENDOR_TLS_CA_FILE`, `VENDOR_VERIFY_HOST_PORT`, and `F5_CLIENT_SSL_PROFILE` /
`CITRIX_CERTKEY_NAME`; for the rollback leg also `F5_MISMATCH_CLIENT_SSL_PROFILE` /
`CITRIX_MISMATCH_CERTKEY_NAME`.

Dry-run checks that WERE executed on the build host: `bash -n` and `shellcheck`
on `run.sh`; `run.sh --vendor f5` and `run.sh` without env exit 2 with a clear
message and start nothing.

## 1. Run metadata

| Field | F5 BIG-IP VE | Citrix ADC VPX |
|---|---|---|
| Run date | PENDING-RUN | PENDING-RUN |
| Hub commit | PENDING-RUN | PENDING-RUN |
| Plugin id / version | `kryptkeeper.f5-bigip` / PENDING-RUN | `kryptkeeper.citrix-adc` / PENDING-RUN |
| Manifest artifact sha256 | PENDING-RUN | PENDING-RUN |
| Appliance version (`/mgmt/tm/sys/version`, `/nitro/v1/config/nsversion`) | PENDING-RUN | PENDING-RUN |
| Operator | PENDING-RUN | PENDING-RUN |

## 2. Per-check results

| Check | F5 | Citrix | Evidence |
|---|---|---|---|
| Install + enable through approval queue (self-approval 403) | PENDING-RUN | PENDING-RUN | |
| Push + hub post-install verify (`installed_verified`) | PENDING-RUN | PENDING-RUN | |
| Live listener serves the renewed cert (sha256 match) | PENDING-RUN | PENDING-RUN | |
| Forced mismatch detected, hub refuses `installed_verified` | PENDING-RUN | PENDING-RUN | |
| Rollback: previous cert still served (sha256 before == after) | PENDING-RUN | PENDING-RUN | |
| Kill switch (`KRYPTKEEPER_DELIVERY_PLUGINS=off`: API 503, renewal refused) | PENDING-RUN | PENDING-RUN | |
| Credential non-leak (password absent from hub log and audit) | PENDING-RUN | PENDING-RUN | |

## 3. Mock-only checks (NOT repeated on hardware by this harness)

Proven only against `tests/live/plugins/mockdevice` (`tests/live/plugins/run.sh`):
cosign-signed install (trusted key verified; signature over other bytes 400; missing
trusted-keys file stops startup); the startup trusted-key count log line; the
"plugins off" start with a bad trusted-keys path. The second-admin provisioning
mechanism is exercised by both harnesses.

Proven only by `tests/plugins/conformance` scripted failures (no device): upload
failure, bind failure, verify mismatch and rollback-failure paths as scripted fakes;
the rollback-FAILURE path (rollback itself failing) is never forced on a real device
here; plugin sandbox limits (network allow-list, memory, timeout).

Not covered at all: HA pairs / config sync, partitions or admin domains, certificate
chains with intermediates on the appliance, cipher/profile side effects, large-scale
target counts, and appliance versions other than the one recorded.

## 4. Limitations and findings

PENDING-RUN. Known design limits: the forced-mismatch design relies on a second
profile/cert-key not bound to the VIP (see README); a vendor VM licence and the
management CA are human prerequisites; with `KRYPTKEEPER_EGRESS_DENY_PRIVATE=true`
a private-IP appliance is refused by the hub egress guard.

To complete: run both vendors, copy `last-run-<vendor>.json` values into the tables,
flip Status to RECORDED, and commit.
