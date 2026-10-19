# UAT: air-gap install on an isolated network (W25-14, FR-P61)

Run 2026-10-15 on an M-series Mac, podman machine, kind v0.33.0 (node `kindest/node` v1.37.0),
helm v4.3.0, kindnet CNI. Harness: `tests/live/airgap/run.sh` (README beside it).
Images: public `ghcr.io/bpmforge/kryptkeeper*:0.9.4` (hub, agent, mcp, certmanager, dashboard)
plus `busybox:1.36`, bundled by `scripts/deploy/airgap-bundle.sh build` with a throwaway cosign key.

## Verdict

**Acceptance 1 and 2 met on this run. 0 FAIL.**

| Test | Result |
|---|---|
| `policy_enforced_canary_blocked` | PASS: kindnet enforces the policy; a busybox canary could not reach `1.1.1.1:80`, and could resolve cluster DNS |
| `helm_install_from_tgz_ok` | PASS: `helm install` from `charts/kryptkeeper-0.9.4.tgz` in the bundle, `image.repository=localhost:5001/bpmforge/kryptkeeper`, `config.dbMode=sqlite`, `--wait --timeout 5m`; then upgrade enabling the dashboard from the mirror |
| `readyz_200` | PASS: `https://kryptkeeper:<port>/readyz` through `kubectl port-forward`, verified against the hub CA exported from the keystore PVC (no `-k`) |
| image pulls | PASS: 0 `ErrImagePull`/`ImagePullBackOff` events; every pod image is under `localhost:5001` |
| `zero_outbound_packets` | **PASS: 0 packets** in a 600 s capture that started before `helm install` |
| `capture_control` | PASS: after the window, a deliberate blocked attempt to `1.1.1.1` produced 4 packets under the same filter, so the 0 is meaningful |
| `offline_table_matches_egress_doc` | PASS: 6 features in the table, 6 in `docs/ops/EGRESS.md`, 0 differences |

Capture: `tcpdump -i any -n -w egress.pcap` in the kind node's network namespace, filter
`not (dst net 10.0.0.0/8 or dst net 172.16.0.0/12 or dst net 192.168.0.0/16 or dst net 127.0.0.0/8) and not (ip6 and (dst net ::1/128 or dst net fc00::/7 or dst net fe80::/10 or dst net ff00::/8)) and not port 53`.
Pcap path (removed with the work dir after the run, 24-byte header only): `/tmp/kk-airgap.XBbET9/egress.pcap`.
`KRYPTKEEPER_CT_DOMAINS` unset.

Scope notes: DNS (port 53) goes to cluster DNS inside the cluster and is excluded on purpose;
private and loopback destinations are in-cluster traffic and excluded as in the ticket. The IPv6
terms were added after a first 30 s smoke run counted 1120 packets that were all `::1` loopback
(the kube-apiserver and port-forward path), not egress. Image pulls are performed by containerd
on the node and are not subject to the pod NetworkPolicy; that is why the run also asserts no
pull errors and that all images come from the mirror. The bundle push (signature verification and
registry push) is the connected side and sits outside the capture window.

## Offline behaviour table (from the run)

| Feature | Observed offline behaviour (measured) |
|---|---|
| Certificate Transparency monitor | off: KRYPTKEEPER_CT_DOMAINS unset, crt.sh log lines: 0 |
| ACME upstream connector | not configured (no ACME upstream env on the hub); no outbound packets |
| Notification webhooks / inventory sources | none configured; no outbound packets (a public target would fail at the egress guard) |
| Update checks | none: hub log update-check lines: 0; update-check strings in internal/ and cmd/: 0; 0 packets |
| Bundle signature verification | offline: push verified with --insecure-ignore-tlog (no Rekor lookup) |
| OCSP / CRL | no external OCSP/CRL upstream configured; served from hub CA state; 0 packets |

The table is the output of the 600 s run. The signature-verification row records that
`push` carries `--insecure-ignore-tlog=true`; the verification itself ran on the connected side,
outside the capture window. A later 30 s re-run after two harness edits (cluster-create retry,
key cleanup) also ended ALL PASS with 0 packets.

## Findings

1. `airgap-bundle.sh push` has no way to push to a plain-http registry (podman refuses http even
   for `localhost`). The harness wraps the engine to add `--tls-verify=false`. A lab or
   small-site mirror without TLS cannot use the script as written.
2. The kind node image has no `tcpdump`, so capture runs in a sidecar container sharing the
   node's network namespace (spec said `podman exec` into the node).
3. kind node boot occasionally exceeds kind's wait on a busy podman VM; the harness retries
   cluster creation up to three times.
4. The chart's NetworkPolicy (`networkPolicy.enabled`) restricts ingress only; the egress
   deny in this UAT comes from `netpol-deny-all.yaml`, which is not part of the chart.
