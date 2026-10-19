# Delivering certificates through External Secrets Operator (Kubernetes Secret path)

Run end to end on a real kind cluster. Every command below was executed;
the output blocks are real, trimmed only where marked.

| | |
|---|---|
| Date executed | 2026-10-16 |
| kind | v0.33.0 (podman provider), node image Kubernetes v1.37.0 |
| kubectl / helm | v1.37.1 / v4.3.0 |
| External Secrets Operator | chart `external-secrets/external-secrets` 2.13.0 (app v2.13.0), CRD `external-secrets.io/v1` served |
| Hub | Kryptkeeper `bfee6473` (branch `kk/w27-b`), run as a local binary |
| Measured sync delay | 28.8 s and 70.2 s from ESO sync to the workload serving the new certificate (section 7) |

The host was heavily loaded during the run (load average about 50 from CI
containers on the same podman machine), so treat the delays as an upper-ish
bound for a small cluster, not a benchmark.

## What this is

The hub already pushes a renewed certificate into a Kubernetes TLS Secret
(`install_mode=k8s`, see the built-in pusher in `internal/agentinstall/k8s.go`).
That works when the hub can write straight into the workload's namespace. If
you would rather keep the hub out of workload namespaces, run External
Secrets Operator (ESO):

```
hub --push--> Secret kk-source-tls (namespace kk-source)
                      |  ESO Kubernetes provider, refreshInterval 15s
                      v
              Secret app-tls (namespace app, kubernetes.io/tls) --mounted--> workload
```

No cloud account and no Vault are needed: the "external" store is a second
namespace in the same cluster. The same `ExternalSecret` shape works against
a real store later by changing the `SecretStore`.

What the hub verifies and what it does not: the hub dials the **workload**
endpoint you name in `verify_host_port` and compares the served fingerprint
with the one it just issued. It reads and writes only the **source** Secret.
It never looks at the ESO-synced Secret. See section 9.

## 0. Prerequisites and variables

Needs `kind`, `kubectl`, `helm`, `podman`, `openssl`, `python3`, `curl`, Go
(to build the hub and the test workload from this repository), and a running
podman machine (`podman machine start`).

```bash
export KIND_EXPERIMENTAL_PROVIDER=podman
export CLUSTER=kk-eso
export SRC_NS=kk-source            # the hub writes here
export APP_NS=app                  # the workload reads here
export SRC_SECRET=kk-source-tls
export APP_SECRET=app-tls
export NODEPORT=30443
export HUB=http://127.0.0.1:8095
export HUB_TOKEN="$(openssl rand -hex 16)"   # hub bootstrap token; never commit it
cd /path/to/kryptkeeper                       # repository root
```

## 1. Create the kind cluster

The extra port mapping lets the hub (running on the host) reach the workload.

```bash
cat > /tmp/kind-config.yaml <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - {containerPort: ${NODEPORT}, hostPort: ${NODEPORT}, protocol: TCP}
EOF
kind create cluster --name "$CLUSTER" --config /tmp/kind-config.yaml
kubectl get nodes
```

```
Set kubectl context to "kind-kk-eso"
NAME                   STATUS     ROLES           AGE   VERSION
kk-eso-control-plane   NotReady   control-plane   15s   v1.37.0
```

`NotReady` this early is normal; it turned `Ready` within the next minute.

## 2. Install External Secrets Operator

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm repo update
helm install external-secrets external-secrets/external-secrets \
  --version 2.13.0 -n external-secrets --create-namespace \
  --set installCRDs=true --wait --timeout 5m
kubectl get crd externalsecrets.external-secrets.io \
  -o jsonpath='{range .spec.versions[*]}{.name} served={.served}{"\n"}{end}'
```

```
STATUS: deployed
...
v1 served=true
v1beta1 served=false
```

The cluster serves `external-secrets.io/v1` only, so the YAML below uses
`v1`. With an older chart that still serves `v1beta1`, change `apiVersion`
accordingly (check with the command above).

## 3. Namespaces and RBAC

Two identities, each with the least it needs:

- `kk-pusher` (in `kk-source`): what the hub authenticates as. It needs
  `get`, `list`, `create`, `update` on Secrets in `kk-source`, plus **`delete`**.
  The hub's rollback of a first-ever push is a DELETE of the Secret; without
  the verb a failed verify cannot be undone (observed: see section 8).
- `eso-reader` (in `app`): what ESO reads with. Read-only on Secrets in
  `kk-source` only, plus `selfsubjectrulesreviews` create, which the ESO
  Kubernetes provider uses to validate the store.

```bash
cat > /tmp/rbac.yaml <<'EOF'
apiVersion: v1
kind: Namespace
metadata: {name: kk-source}
---
apiVersion: v1
kind: Namespace
metadata: {name: app}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: kk-pusher, namespace: kk-source}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: kk-pusher, namespace: kk-source}
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "create", "update", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: kk-pusher, namespace: kk-source}
subjects: [{kind: ServiceAccount, name: kk-pusher, namespace: kk-source}]
roleRef: {kind: Role, name: kk-pusher, apiGroup: rbac.authorization.k8s.io}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: eso-reader, namespace: app}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: eso-reader, namespace: kk-source}
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["authorization.k8s.io"]
  resources: ["selfsubjectrulesreviews"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: eso-reader, namespace: kk-source}
subjects: [{kind: ServiceAccount, name: eso-reader, namespace: app}]
roleRef: {kind: Role, name: eso-reader, apiGroup: rbac.authorization.k8s.io}
EOF
kubectl apply -f /tmp/rbac.yaml

for q in "get secrets -n kk-source --as=system:serviceaccount:app:eso-reader" \
         "create secrets -n kk-source --as=system:serviceaccount:app:eso-reader" \
         "get secrets -n default --as=system:serviceaccount:app:eso-reader" \
         "get secrets -n app --as=system:serviceaccount:kk-source:kk-pusher"; do
  echo "can-i $q -> $(kubectl auth can-i $q)"; done
```

```
can-i get secrets -n kk-source --as=system:serviceaccount:app:eso-reader -> yes
can-i create secrets -n kk-source --as=system:serviceaccount:app:eso-reader -> no
can-i get secrets -n default --as=system:serviceaccount:app:eso-reader -> no
can-i get secrets -n app --as=system:serviceaccount:kk-source:kk-pusher -> no
```

The hub identity cannot touch the workload namespace, and ESO cannot write
anywhere or read outside `kk-source`.

## 4. SecretStore, ExternalSecret and the source Secret

ESO cannot sync a Secret that does not exist yet, and the workload pod will
not start until its mounted Secret exists. So seed the source Secret once
with a throwaway self-signed certificate; the hub's first push replaces it
(which also means the hub's first push is an update, not a create).

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -days 1 -subj "/CN=placeholder" -keyout /tmp/ph.key -out /tmp/ph.crt 2>/dev/null
kubectl -n "$SRC_NS" create secret tls "$SRC_SECRET" --cert=/tmp/ph.crt --key=/tmp/ph.key
rm -f /tmp/ph.key

cat > /tmp/eso.yaml <<'EOF'
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata: {name: kk-source, namespace: app}
spec:
  provider:
    kubernetes:
      remoteNamespace: kk-source
      server:
        url: https://kubernetes.default.svc
        caProvider: {type: ConfigMap, name: kube-root-ca.crt, key: ca.crt}
      auth:
        serviceAccount: {name: eso-reader}
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: {name: app-tls, namespace: app}
spec:
  refreshInterval: 15s
  secretStoreRef: {kind: SecretStore, name: kk-source}
  target:
    name: app-tls
    creationPolicy: Owner
    deletionPolicy: Retain
    template:
      type: kubernetes.io/tls
  data:
  - secretKey: tls.crt
    remoteRef: {key: kk-source-tls, property: tls.crt}
  - secretKey: tls.key
    remoteRef: {key: kk-source-tls, property: tls.key}
EOF
kubectl apply -f /tmp/eso.yaml
kubectl -n "$APP_NS" wait --for=condition=Ready externalsecret/app-tls --timeout=120s
kubectl -n "$APP_NS" get secretstore,externalsecret
kubectl -n "$APP_NS" get secret "$APP_SECRET" -o jsonpath='{.type}{"\n"}'
```

```
externalsecret.external-secrets.io/app-tls condition met
NAME                                        AGE   STATUS   CAPABILITIES   READY
secretstore.external-secrets.io/kk-source   11s   Valid    ReadWrite      True

NAME                                         STORETYPE     STORE       REFRESH INTERVAL   STATUS         READY   LAST SYNC
externalsecret.external-secrets.io/app-tls   SecretStore   kk-source   15s                SecretSynced   True    2s
kubernetes.io/tls
```

The synced Secret is `kubernetes.io/tls` because of `target.template.type`.
`caProvider` reuses the `kube-root-ca.crt` ConfigMap that Kubernetes puts in
every namespace, so no CA needs copying. `refreshInterval: 15s` is only to
make this walkthrough quick; production values are minutes (section 7).

## 5. The workload

The repository ships a TLS echo server used by the k8s live test
(`tests/live/k8s/tlsecho`). It re-reads the certificate from disk on every
handshake, so a refreshed Secret volume is picked up without a reload.

```bash
mkdir -p /tmp/tlsecho
GOOS=linux GOARCH="$(podman info --format '{{.Host.Arch}}')" CGO_ENABLED=0 \
  go build -o /tmp/tlsecho/tlsecho ./tests/live/k8s/tlsecho
cp tests/live/k8s/tlsecho/Containerfile /tmp/tlsecho/
podman build -q -t localhost/kk-eso-tlsecho:latest -f /tmp/tlsecho/Containerfile /tmp/tlsecho
podman save localhost/kk-eso-tlsecho:latest -o /tmp/tlsecho.tar
kind load image-archive /tmp/tlsecho.tar --name "$CLUSTER"

cat > /tmp/workload.yaml <<'EOF'
apiVersion: v1
kind: Pod
metadata: {name: web, namespace: app, labels: {app: web}}
spec:
  containers:
  - name: tlsecho
    image: localhost/kk-eso-tlsecho:latest
    imagePullPolicy: Never
    args: [":8443", "/tls/tls.crt", "/tls/tls.key"]
    ports: [{containerPort: 8443}]
    volumeMounts: [{name: tls, mountPath: /tls, readOnly: true}]
  volumes:
  - name: tls
    secret: {secretName: app-tls}
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: app}
spec:
  type: NodePort
  selector: {app: web}
  ports: [{port: 8443, targetPort: 8443, nodePort: 30443}]
EOF
kubectl apply -f /tmp/workload.yaml
kubectl -n "$APP_NS" wait --for=condition=Ready pod/web --timeout=90s

# The hub refuses loopback and link-local verify addresses (security control,
# not relaxed here), so name the host's primary non-loopback address.
export VERIFY_HOST="$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('192.0.2.1', 9)); print(s.getsockname()[0])")"
echo | openssl s_client -connect "$VERIFY_HOST:$NODEPORT" 2>/dev/null \
  | openssl x509 -noout -subject -fingerprint -sha256
```

```
pod/web condition met
subject=CN=placeholder
sha256 Fingerprint=4E:ED:8B:6B:E8:F4:30:41:E3:DB:22:C0:9F:12:B3:40:55:7E:78:8F:7B:80:81:24:7F:46:15:0A:F4:AB:EB:B9
```

The workload is serving the placeholder certificate, delivered by ESO.

## 6. Hub: credential, target, renewal

Start a hub (env lifted from `tests/live/k8s/run.sh`; plain HTTP and a
throwaway data dir, because the surface under test is the Secret path, not the
hub's own listener):

```bash
mkdir -p /tmp/eso-hub/data
go build -o /tmp/eso-hub/kryptkeeper ./cmd/kryptkeeper
export APP_BOOTSTRAP_TOKEN="$HUB_TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file KRYPTKEEPER_TLS_DISABLE=true \
  APP_CREDENTIAL_STORE_PASSPHRASE="$(openssl rand -hex 16)" \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE="$(openssl rand -hex 16)" \
  KRYPTKEEPER_DATA_DIR=/tmp/eso-hub/data APP_CA_FILE=/tmp/eso-hub/data/cas.json \
  APP_TEMPLATE_FILE=/tmp/eso-hub/data/templates.json \
  APP_CERTIFICATE_FILE=/tmp/eso-hub/data/certificates.json \
  APP_AUDIT_FILE=/tmp/eso-hub/data/audit.json \
  APP_CERTS_SUMMARY_FILE=/tmp/eso-hub/data/certs_summary.json \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="ESO Doc Root CA" \
  APP_BIND_ADDR=127.0.0.1 PORT=8095
/tmp/eso-hub/kryptkeeper > /tmp/eso-hub/hub.log 2>&1 &
until curl -sf -o /dev/null -H "Authorization: Bearer $HUB_TOKEN" $HUB/api/v1/cas; do sleep 1; done
```

Create the template, the Kubernetes credential and the `k8s` target. The
credential carries the `kk-pusher` token and the cluster CA; the token is
minted for one hour and is passed straight into the request, never echoed.

```bash
curlj() { curl -sS -H "Authorization: Bearer $HUB_TOKEN" -H 'Content-Type: application/json' "$@"; }
jget()  { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

CA_ID=$(curlj $HUB/api/v1/cas | jget 'd["data"][0]["id"]')
TEMPLATE_ID=$(curlj -X POST $HUB/api/v1/templates -d '{"name":"eso-server","display_name":"ESO doc server cert","allowed_algorithms":["ECDSA","RSA-2048"],"key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["serverAuth"],"validity_period":"2160h","active":true}' | jget 'd["data"]["id"]')

kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > /tmp/cluster-ca.pem
APISERVER_URL=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
python3 - "$APISERVER_URL" "$(kubectl create token kk-pusher -n "$SRC_NS" --duration=1h)" /tmp/cluster-ca.pem "$SRC_NS" "$SRC_SECRET" > /tmp/cred.json <<'PY'
import json, sys
api, tok, ca, ns, secret = sys.argv[1:6]
print(json.dumps({"name": "eso-source-pusher", "credential_type": "api_token", "payload": {
  "base_url": api, "bearer_token": tok.strip(), "namespace": ns, "secret_name": secret,
  "ca_cert": open(ca).read()}}))
PY
CRED_ID=$(curlj -X POST $HUB/api/v1/credentials -d @/tmp/cred.json | jget 'd["data"]["id"]')
rm -f /tmp/cred.json
TARGET_ID=$(curlj -X POST $HUB/api/v1/targets -d "{\"host\":\"127.0.0.1\",\"discovery_mode\":\"network\",\"install_mode\":\"k8s\",\"credential_ref\":\"$CRED_ID\",\"name\":\"eso-source-secret\"}" | jget 'd["data"]["id"]')
echo "target: $TARGET_ID"
```

Issue a certificate and renew it into the source Secret. `verify_host_port`
points at the **workload**, so the hub reports `installed_verified` only once
ESO and the kubelet have carried the new certificate all the way to the pod:

```bash
issue() {
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout /tmp/app.key -out /tmp/app.csr -subj "/CN=app.example.internal" \
    -addext "subjectAltName=DNS:app.example.internal" 2>/dev/null
  python3 -c "import json;print(json.dumps({'ca_id':'$CA_ID','template_id':'$TEMPLATE_ID','csr_pem':open('/tmp/app.csr').read()}))" \
    | curlj -X POST $HUB/api/v1/certificates -d @- | jget 'd["data"]["fingerprint_sha256"]'
}
FP=$(issue)
RESP=$(time curlj -X POST $HUB/api/v1/renewal/execute \
  -d "{\"fingerprint\":\"$FP\",\"target_id\":\"$TARGET_ID\",\"install\":{\"verify_host_port\":\"$VERIFY_HOST:$NODEPORT\"}}")
echo "$RESP"
```

Observed (first renewal, second renewal took 82 s; fingerprints are public
certificate hashes, not secrets):

```
{"data":{"predecessor_fingerprint":"fbfc4bca...","new_fingerprint":"430c4b82afdd18198ecb89628233d8f8500ba12db495a39127e204e7ff9f0034","renewed":true,"install_outcome":"installed_verified","verified":true}}
```

## 7. Verify, and the sync delay

Independent check, outside the hub: the synced Secret in the workload
namespace holds the hub's `new_fingerprint`, and so does the live endpoint.

```bash
NEW=$(echo "$RESP" | jget 'd["data"]["new_fingerprint"]')
kubectl -n "$APP_NS" get secret "$APP_SECRET" -o jsonpath='{.data.tls\.crt}' | base64 -d \
  | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'
echo | openssl s_client -connect "$VERIFY_HOST:$NODEPORT" 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'
echo "$NEW"
```

All three lines were identical on the second renewal
(`5a9217c2bfaaafb121d2d3e81278c5657187a339c7d7468238330de31c238b9f`).

Measured delay, from a poller that read the clock each time a fingerprint
changed (about 0.5 s resolution, slowed by the loaded host; epoch seconds
are relative to the renewal request being sent):

| Event | Renewal 1 | Renewal 2 |
|---|---|---|
| Hub wrote the source Secret | +2.4 s (poller start-up included) | not observed (write finished before the poller's first read) |
| ESO updated the `app-tls` Secret | +11.1 s | +11.3 s |
| Workload served the new certificate | +40.0 s | +81.5 s |
| Hub returned `installed_verified` | +40.0 s | +82.4 s |
| ESO sync to workload serving (the kubelet leg) | **28.8 s** | **70.2 s** |

Two delays add up, in this order:

1. **ESO**: up to `refreshInterval` after the source changes. Here 15 s, and
   the Secret changed 9 s (renewal 1, from the source write) after the write.
2. **kubelet**: a mounted Secret volume is refreshed on the kubelet's sync
   period plus its Secret cache TTL, so the pod sees the new files up to about
   two minutes later (the comment on `k8sVerifyRetryAttempts` in
   `internal/agentinstall/k8s.go` budgets 135 s for this). We saw 29 s and
   70 s. This leg dominates and you cannot shorten it from ESO.

Plan for `refreshInterval` plus about two minutes, not for the 15 s used here.
The hub's verify loop retries for 90 attempts x 1.5 s = 135 s; with a longer
`refreshInterval` it will run out and report `verify_failed` even though the
rollout later succeeds (section 9).

## 8. Troubleshooting

Each of these was hit or reproduced during this run.

| Symptom | Cause | Fix |
|---|---|---|
| `install_outcome":"verify_failed","install_detail":"verify address is not permitted"` | `verify_host_port` omitted so the hub dialled `host:443` of the target (here `127.0.0.1`), or you named a loopback / link-local address | Pass `install.verify_host_port` with the workload's non-loopback `host:port`. It took the hub about 135 s to give up in this case |
| `... ROLLBACK FAILED (secret may still serve the unverified cert): restore returned HTTP 403` | The hub's Role lacks `delete` and the Secret did not exist before the push (rollback = delete) | Add `delete` to the `kk-pusher` Role, or pre-create the source Secret as in section 4 so rollback is an update. Then check the source Secret by hand: it can hold an unverified certificate |
| `install_outcome":"write_failed"` with `HTTP 500 ... etcdserver: request timed out` | The kind control plane was starved of CPU by other containers. The write **had** landed despite the 500 (the source Secret held the new certificate afterwards) | Re-run the renewal; check the source Secret's fingerprint before assuming nothing changed |
| ExternalSecret `SecretSyncedError`, message `could not get secret data from provider` | ESO's identity cannot read the source namespace. Reproduced by deleting the `eso-reader` RoleBinding: status flipped to `SecretSyncedError` within 20 s and back to `SecretSynced` about 20 s after `kubectl apply -f /tmp/rbac.yaml` | Restore the RoleBinding. `kubectl -n app describe externalsecret app-tls` shows the reason |
| SecretStore not `Valid` | Wrong `remoteNamespace`, wrong ServiceAccount name, or the `selfsubjectrulesreviews` rule is missing | `kubectl -n app describe secretstore kk-source` |
| ESO pods not Ready | Chart still installing or images not pulled | `kubectl -n external-secrets get pods` |
| Workload pod stuck `ContainerCreating` | Mounted Secret `app-tls` does not exist yet (ExternalSecret not synced) | Seed the source Secret (section 4) and wait for `SecretSynced` |

## 9. Limits

- **Verify tests the workload, not the ESO target.** `installed_verified`
  means the pod you named is serving the new certificate. The hub never reads
  the `app-tls` Secret and cannot tell a stuck ESO from a slow kubelet. If you
  name no reachable workload endpoint, there is nothing to verify against and
  the hub dials `host:443` of the target, which fails for loopback.
- **Rollback is for the source Secret only.** If verify fails the hub restores
  the source Secret. ESO then syncs the old certificate back into
  `app-tls` on its next refresh, and the pod follows after the kubelet delay.
  The hub's `rolled_back` is about the source Secret, not about what the
  workload serves at that moment.
- **Short verify window versus long refresh.** The hub gives up after about
  135 s. Pick a `refreshInterval` well inside that if you want the hub's
  verified result to be meaningful, or accept `verify_failed` followed by a
  later automatic convergence.
- **Deletion policy.** `deletionPolicy: Retain` keeps `app-tls` if the
  ExternalSecret is deleted or the source Secret disappears; `Delete` removes
  it, which would take the workload's certificate away. `creationPolicy:
  Owner` means ESO owns `app-tls` and overwrites manual edits.
- **Key material crosses a namespace boundary.** The private key sits in the
  source Secret as well as the synced one; give the `kk-source` namespace the
  same access controls as the workload's.
- **Tokens.** The `kk-pusher` token in the hub credential expires (one hour
  here). For anything lasting, use a longer-lived token Secret or a hub-side
  rotation, and never paste tokens into tickets or this document.

## 10. Clean up

```bash
kill %1 2>/dev/null          # the hub started in section 6
kind delete cluster --name "$CLUSTER"
rm -rf /tmp/eso-hub /tmp/tlsecho /tmp/tlsecho.tar /tmp/app.* /tmp/ph.* /tmp/cluster-ca.pem
helm repo remove external-secrets
```

The cluster created for this run (`kk-eso`) was deleted; `kind get clusters`
afterwards reported none.
