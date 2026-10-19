# W32-06: F5 BIG-IP and Citrix ADC plugins on a real appliance

Harness: `run.sh --vendor f5|citrix`. It is the `tests/live/plugins/run.sh`
flow (hub container, approval queue with a second admin, credential, plugin
target, renewal, kill switch) pointed at a REAL appliance instead of
`tests/live/plugins/mockdevice`. Results land in
`docs/release/LIVE_RESULTS_PLUGINS_F5_CITRIX_v0.20.md`; machine-readable
output goes to `last-run-<vendor>.json` here (not committed until a real run).

## Prerequisites (human)

| Vendor | Appliance | Licence | Notes |
|---|---|---|---|
| f5 | BIG-IP VE (eval licence from F5) | free 30-day eval | iControl REST on 443; a Client SSL profile (A) bound to a virtual server on a data-plane VIP; a second Client SSL profile (B) bound to nothing |
| citrix | Citrix ADC VPX Express (free licence) | VPX Express | NITRO on 443; a cert-key (A) bound to an SSL vserver; a second cert-key (B) bound to nothing |

* A service account with rights to import/replace the cert-key pair and update
  the profile (F5: Certificate Manager/Administrator; Citrix: a command policy
  allowing `add/update/link ssl certkey`, `save ns config`).
* The management certificate must chain to a CA you pass as
  `VENDOR_TLS_CA_FILE`. TLS verification is never disabled (the manifests
  declare `tls_verify: true`).
* Network: the podman hub container must reach `VENDOR_BASE_URL` (management
  port) and the host running the script must reach `VENDOR_VERIFY_HOST_PORT`
  (the VIP). A private appliance IP is allowed by the egress guard by default;
  with `KRYPTKEEPER_EGRESS_DENY_PRIVATE=true` it is refused, so leave that unset
  for the run.
* Tools on the host: podman (running machine), go, openssl, python3, curl.
  Expected duration 5 to 10 minutes per vendor after the images are built.

## Run

```
cp tests/live/plugins/vendor/vendor.env.example ../vendor.env   # outside the repo; edit
set -a; . ../vendor.env; set +a
bash tests/live/plugins/vendor/run.sh --vendor f5
bash tests/live/plugins/vendor/run.sh --vendor citrix
```

Required env: `VENDOR_BASE_URL`, `VENDOR_USER`, `VENDOR_PASS_FILE` (a file
holding the password; read at run time, never echoed, grepped out of the hub
log and audit trail at the end), `VENDOR_TLS_CA_FILE`,
`VENDOR_VERIFY_HOST_PORT` (VIP the hub dials to verify), and the per-vendor
target field: `F5_CLIENT_SSL_PROFILE` or `CITRIX_CERTKEY_NAME`. Optional:
`VENDOR_CERT_CN` (cert CN/SAN, default `vendor-vip.uat.example`) and the
rollback leg's `F5_MISMATCH_CLIENT_SSL_PROFILE` /
`CITRIX_MISMATCH_CERTKEY_NAME`; without it that leg is recorded
`PENDING-RUN`. Missing required env exits 2 with a clear message and starts
nothing.

## Forced mismatch (rollback evidence)

The recommended-default design: the second target pushes to profile/cert-key
B, which is bound to nothing, but the hub verifies against VIP A, which keeps
serving the previous certificate. The served fingerprint can never equal the
new one, so the hub's post-install verification must fail and roll back. The
script then asserts the hub did not report `installed_verified` and that the
listener still serves the exact certificate it served before the forced
mismatch (sha256 recorded). It prints the raw renewal response so the
rollback fields are captured verbatim in the run log.

## Cleanup

All containers are named `kkw32-plugv-*` and removed on exit, with the
network and the per-run image. The appliance itself is not reset: delete the
imported test cert-key objects by hand.
