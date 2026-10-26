# Try Kryptkeeper in five minutes

One command starts a Kryptkeeper hub filled with clearly labelled sample data, so
the first screen is a working estate instead of an empty console.

```bash
docker compose -f deploy/try/compose.yaml up
```

Podman works the same way (`podman compose -f deploy/try/compose.yaml up`).

This starts PostgreSQL, the hub, the web console, two small TLS servers for the hub
to discover, and a one-shot `seeder` that runs `kryptkeeper demo seed` against the
hub's public API and exits.

## Sign in

Open <http://localhost:3000> and sign in:

| | |
|---|---|
| Email | `admin@demo.test` |
| Password | `kryptkeeper-demo` |

You land on a dashboard with:

- two CAs, **Demo Root CA** and **Demo Issuing CA**, and two certificate templates;
- about 40 certificates in mixed states: active (some on RSA keys), six that expire
  within 14 days, four revoked, one expired, and one with a 1024-bit RSA key and a
  SHA-1 signature (graded F, and flagged by the compliance reports);
- two more certificates found by one discovery scan of the demo TLS servers
  (`demo-web1:8443`, `demo-web2:8443`);
- a **Demo data** banner on every page.

Every certificate carries the label `demo=true`; the CAs and templates carry the
`Demo ` / `demo-` name prefix because they have no label field.

## Reset

As an admin, choose **Reset demo data** in the banner (it asks for confirmation). It
revokes the certificates labelled `demo=true` and clears the banner. Anything that is
not labelled demo is left alone. The demo CAs stay in place: revoking a CA always
needs a second human to approve, which a one-token tool must not bypass.

The command line does the same:

```bash
docker compose -f deploy/try/compose.yaml run --rm seeder demo reset \
  --hub=https://kryptkeeper:8080 --ca-file=/tls/ca.pem
```

To fill the hub again after a reset (revoked demo certificates from the earlier round
remain in the inventory as revoked):

```bash
docker compose -f deploy/try/compose.yaml run --rm seeder
```

`demo seed` refuses a hub that is already seeded, one that reports
`KRYPTKEEPER_ENV=production`, and one that holds certificates or CAs that are not demo
data (a single bootstrap-default CA is tolerated).

## Remove

```bash
docker compose -f deploy/try/compose.yaml down -v
```

This deletes the containers and all three volumes, including the demo CA keys.

## This is a demo, not a deployment

The login, the API token and the login signing secret are published in `compose.yaml`.
Every port is bound to `127.0.0.1` and the hub reports `KRYPTKEEPER_ENV=trial`. Do not
put it on a network, and do not reuse these values anywhere. For a real install see
[docs/deployment.md](../../docs/deployment.md).

## Images

By default the compose file pulls `ghcr.io/bpmforge/kryptkeeper` and
`ghcr.io/bpmforge/kryptkeeper-dashboard` at `${KK_VERSION:-latest}`. The seeder needs a
release that contains the `demo` command (1.1 or newer); pin one with
`KK_VERSION=1.1.0`. To build both images from this checkout instead:

```bash
docker compose -f deploy/try/compose.yaml -f deploy/try/compose.build.yaml up --build
```

Other knobs: `KK_UI_PORT` (default 3000), `KK_PROJECT` (compose project name, default
`kryptkeeper-try`).

## Kubernetes

```bash
kind create cluster --name kk-try
helm install kk charts/kryptkeeper -f charts/kryptkeeper/values-demo.yaml
kubectl port-forward svc/kk-kryptkeeper-dashboard 3000:80
```

`values-demo.yaml` runs one hub replica on SQLite with TLS off, enables the console and
sets `demo.enabled`, which adds a post-install Job that runs `kryptkeeper demo seed`.
Sign in with the same login as above. The chart renders and lints (see
`charts/kryptkeeper/ci/render-test.sh`); it has not been run on a live kind cluster
yet, and there are no demo TLS servers in that variant, so no discovery scan runs
unless you set `demo.targets`.

## Measured

On an Apple M2 Max laptop (Podman 6.1.3 with the Docker Compose provider, 2026-10-24),
with the hub and console images built from this branch and the other images already
present locally: `compose up -d` returned in 3 s, and the API served 40 seeded
certificates with the demo marker set at **10 s** after the start (seeder log: 2 CAs,
38 issued, 2 imported, 2 scans, 2 discovered certificates labelled; 42 certificates in
total). The login and the banner were checked in the browser, and a reset from the
banner revoked all 42 demo certificates and removed the banner. A cold first run adds
the image pulls, which depend on the network and were not timed here.

The count was taken like this (the console proxies the API on port 3000):

```bash
curl -s -H "Authorization: Bearer trial-only-bootstrap-token-0123456789abcdef" \
  "http://127.0.0.1:3000/api/v1/certificates?limit=1"   # .meta.total
```
