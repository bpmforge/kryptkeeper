# helm-kind: chart install at replicaCount=2 on kind (W23-30)

`bash tests/live/helm-kind/run.sh` needs `kind`, `helm`, `kubectl`, `podman`
(podman machine running), `openssl`, `curl`, `python3`; ~8 minutes (image
build dominates). It uses `KIND_EXPERIMENTAL_PROVIDER=podman`, builds the repo
Dockerfile, `kind load image-archive`s it, runs BYO Postgres (`postgres.yaml`),
then: helm lint/template pre-check; `helm install` at replicaCount=1 with
`KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true`; `helm upgrade --set replicaCount=2`
without it; asserts 2 Ready distinct pods; issues 20 leaves through the Service
(port-forward, verified TLS against the chart CA); issues leaves on each pod
directly and checks each pod's `kryptkeeper_cert_issue_total` delta; deletes a
pod and checks the Service keeps answering. Secrets are generated per run.
`KEEP_CLUSTER=1` leaves the cluster up for debugging. Cleanup deletes the
cluster, the local image and the temp dir.

The chart now defaults `APP_TEMPLATE_FILE` to `<persistence.mountPath>/data/templates.json`
(re-run green on that default, 2026-10-16). Harness workaround for a remaining
gap: Postgres runs with `max_connections=300`.

## Does NOT prove
- Multi-node HA: the keys PVC is ReadWriteOnce and two pods share it only on a
  single node. Real HA needs an RWX volume or cloudKMS/pkcs11.
- Service load balancing: `kubectl port-forward` pins one pod (all 20 Service
  issuances landed on one replica); per-replica serving is shown separately.
- A signed/published image (the image is built locally and unsigned).
- Concurrent root creation safety (the harness avoids it by design).
