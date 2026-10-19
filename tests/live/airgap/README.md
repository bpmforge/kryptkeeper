# Air-gap install UAT (W25-14)

Installs the W25-13 signed bundle into a kind cluster whose egress is
default-denied and proves the install emits zero outbound packets.

Prerequisites (nothing is installed for you): `kind`, `kubectl`, `helm`, `podman`
(rootful machine running), `jq`, `tcpdump` (reads the pcap), `cosign`, `curl`, `openssl`,
`python3`, `sha256sum`. Internet is needed only for the connected-side steps
(pulling the `0.9.4` images, `registry:2`, `alpine`, `busybox`).

```bash
bash tests/live/airgap/run.sh                       # 600 s capture window
AIRGAP_CAPTURE_SECONDS=30 bash tests/live/airgap/run.sh   # smoke run
```

Env: `AIRGAP_CAPTURE_SECONDS`, `AIRGAP_TAG` (default `0.9.4`), `HUB_IMAGE`/`AGENT_IMAGE`/
`MCP_IMAGE`/`CERTMANAGER_IMAGE`/`DASHBOARD_IMAGE` (tag-form refs), `RESULTS_OUT`
(where the offline behaviour table is written), `KEEP_WORK=1`,
`KK_AIRGAP_LOCAL_IMAGES=1` (build the five images from this checkout and tag them as the refs
above instead of pulling the private ghcr images; no registry credentials are used).

What it does: build + cosign-sign the bundle with a throwaway key, push it to a local
`registry:2` (`kk-airgap-registry`, `localhost:5001`), create cluster `kk-airgap` (kindnet,
which enforces NetworkPolicy; a canary must fail to reach `1.1.1.1` or the run aborts),
apply `netpol-deny-all.yaml`, start `tcpdump -i any` in the kind node's network namespace
(via a throwaway alpine+tcpdump container with `--net container:<node>`, because the kind
node image has no tcpdump), `helm install` the bundled tgz from the mirror, enable the
dashboard, check `/readyz` over verified TLS, idle for the window, assert the filtered pcap
holds 0 packets, then prove the capture works with a control (a blocked attempt must show up).
The cluster, registries and capture containers are removed on exit.

Notes: a Mac cannot capture the kind node's traffic from the host, hence the sidecar.
`airgap-bundle.sh push` cannot push to a plain-http registry, so the harness wraps the
engine to add `--tls-verify=false` for this throwaway registry only.
