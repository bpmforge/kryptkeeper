# W19-01 — ACME live UAT fixture (certbot + lego)

Proves the hub's `/acme/` endpoint against two real ACME clients — certbot
(the Let's Encrypt reference client) and lego (a from-scratch Go
implementation, so a second independent RFC 8555 interpretation) — issuing,
renewing and revoking a certificate, then checking the effects land where
the product claims: the certificate chains to "UAT Root CA", the hub's own
inventory records it with `source: "acme"` (W18-16, previously unexercised
by any real client), and revocation shows up in both the OCSP responder and
the CRL.

## Run

```
bash tests/live/acme/run.sh
```

Requires `podman` (no docker on this host) and network access to pull
`certbot/certbot`, `goacme/lego`, `nginx:alpine`, and `curlimages/curl`.
Builds the hub binary for the podman machine's arch, stands up a private
podman network with the hub, a TLS front, and each client in turn, and
prints PASS/FAIL per step. Idempotent: tears down and recreates the
network/containers/data dir on every invocation, and always cleans up on
exit.

Client versions verified against the actual pulled images at the time of
writing: **certbot 5.8.0**, **lego 5.4.1**. Every CLI flag in `run.sh` was
checked against `--help` output from these images, not written from memory
(the project's verify-before-writing rule) — several flags the ticket suggested
(certbot's `--no-eab-if-not-required`, `--register-unsafely-without-email`,
`--no-random-sleep-on-renew`; lego's top-level `renew`/`revoke` commands and
`--http.port`) do not exist in these versions and had to be replaced; see
"CLI syntax notes" below.

## Topology, and why

**Hub runs inside a container, alongside both clients, on one podman
network — not on the host.** Two hub-external constraints forced this,
distinct from `tests/live/agent/`'s host-hub layout:

1. **HTTP-01 needs the hub's validator to reach the client on port 80.**
   RFC 8555 HTTP-01 always dials the identifier on port 80, no configurable
   port (`internal/acme/server.go:1104`, same constraint `tests/live/agent/`
   documents). macOS podman has no `--network host`, so a host-run hub
   cannot reach a client container's :80 by a published port the way a
   real internet host would reach it by IP — the natural fix is to put the
   hub on the same podman network as the clients and use container-DNS
   names (`kk-certbot`, `kk-lego`) as the ACME identifiers, verified live
   (`podman run ... alpine sh -c "wget http://bindtest:8080"` against a
   trivial listener before committing to this shape).

2. **The hub must bind to its own container hostname, not `0.0.0.0`.**
   `net.Listen`/`http.ListenAndServe` on a container's own hostname
   resolves to that container's own address and binds successfully
   (verified empirically the same way as #1) — so `APP_BIND_ADDR=kk-acme-hub`
   both listens correctly and, pre-W19-13, would have been the literal
   string baked into every ACME URL the directory advertised.

3. **lego refuses a plain-HTTP ACME directory outright, no override.**
   Verified against the actual lego image (`lego run --help`): no
   `--insecure`/`--no-check`/equivalent flag exists. lego's error is
   client-side and unconditional: `"HTTPS is required"`. certbot only
   *warns* about the same thing and proceeds. Since the hub
   (`cmd/kryptkeeper/main.go`) has no built-in TLS listener for protocol
   endpoints at all, `run.sh` fronts it with a throwaway self-signed
   `nginx:alpine` TLS terminator (`kk-acme-tls`, port 8443) proxying to the
   hub's plain-HTTP backend, and sets `KRYPTKEEPER_BASE_URL` (W19-13,
   `cmd/kryptkeeper/main.go`'s `resolvePublicBaseURL`) to that front's
   `https://kk-acme-tls:8443` — otherwise the *directory* URL alone would be
   HTTPS but every URL *inside* the directory response (new-account,
   new-order, challenge, finalize, cert) would still be the hub's own
   `http://` self-URL, and lego would refuse those mid-flow exactly the same
   way. Both clients are pointed at the TLS front consistently, matching how
   this would actually be deployed (ACME over HTTPS is the norm; the hub's
   lack of a native TLS listener, itself, is worth a separate ticket if a
   deployment can't put a reverse proxy in front of it).

   `--no-verify-ssl` (certbot) / `--tls-skip-verify` (lego) accept the
   throwaway cert; it is never something a client should be asked to trust
   by CA path outside this fixture.

## CLI syntax notes (verified against the pulled images, not assumed)

- **certbot**: no `--no-eab-if-not-required` (EAB is off by default on this
  hub anyway — `internal/acme/eab.go`, `APP_ACME_EAB_REQUIRED` unset — so
  moot) and no `--register-unsafely-without-email`/
  `--no-random-sleep-on-renew` in 5.8.0. Uses `-m uat@example.test
  --no-eff-email` for non-interactive registration instead. `revoke
  --cert-path` wants `fullchain.pem`, not `cert.pem` (certbot's own usage
  string says so).
- **lego 5.x flattened the CLI**: there is no top-level `renew` or `revoke`
  command. `run` both obtains and (with `--renew-force --ari-disable
  --no-random-sleep`) renews; revocation is `certificates revoke
  --cert.name <name>`. All data/domain/challenge flags belong to the
  subcommand (`run ...`), not a global preamble before it. The HTTP-01
  listen flag is `--http.address :80`, not `--http.port`.
  `--ari-disable --no-random-sleep` avoid lego's RFC 9773 renewal-info
  logic scheduling a multi-minute random delay before a forced renewal —
  observed live on an earlier run (`lego run --renew-force` alone hung for
  ~5 minutes on "renewal: random delay. sleep=4m56s").

## What each step proves

1. **Directory + CA chain** — `GET /acme/directory` over the TLS front;
   `GET /api/v1/cas` + `GET /api/v1/cas/{id}/chain?format=pem` for the root
   CA certificate used by every `openssl verify` below.
2. **Obtain** — `certonly --standalone` / `run` against the hub's directory,
   HTTP-01 validated by the hub dialing the client container's own :80.
3. **Chain verification** — `openssl verify -CAfile <root>.pem <issued>.pem`
   against "UAT Root CA".
4. **Inventory** — `GET /api/v1/certificates`, matched on *this client's own
   certificate fingerprint* (SHA-256 of the DER, computed independently via
   `openssl x509 -fingerprint`) with `source: "acme"` — not merely "some
   certificate somewhere has source=acme", which would pass even if one
   client's issuance were never recorded while the other's was.
5. **Renew** — forced renewal through each client's own renewal command;
   every downstream check (revoke, CRL, OCSP, inventory) is re-run against
   the *renewed* certificate, copied fresh after the renew step completes,
   since renewal replaces the on-disk cert with a new fingerprint+serial.
6. **Revoke** — each client's revoke command; `openssl crl` against
   `GET /crl/{ca-id}.crl` for the serial, and `openssl ocsp` against
   `GET /ocsp` for a `revoked` status.

If certbot's CRL/OCSP checks pass but lego's CRL check fails (or vice
versa) while OCSP for both passes: check `internal/crl/generator.go` before
calling it a hub revocation defect. The CRL is generated per-CA (not
per-serial) with a cache duration (`crl.NewGenerator(..., 24*time.Hour)`
in `cmd/kryptkeeper/main.go`), so a CRL fetched for one client's revocation
can still be serving a stale (pre-second-revocation) version to the other
within that window — a caching/timing artifact of running two revocations
close together in one fixture, not necessarily a broken revocation path.
OCSP is keyed per-serial and has no equivalent exposure.

## Fixture layout

- `run.sh` — builds the hub binary, drives the network/hub/TLS-front/client
  container lifecycle, and prints PASS/FAIL per step. No real key material
  is committed; the TLS front's cert is a throwaway self-signed cert
  generated fresh by `openssl req` at the start of every run and discarded
  on teardown.
- `README.md` — this file.

Nothing else lives here: no committed images, Containerfiles, or
certificates — everything (hub binary, TLS cert, client data dirs) is
built or generated by `run.sh` into `$KK_UAT_RUN_DIR`
(default `~/kk-uat-acme-run`, must be under `$HOME` — podman machine on
macOS virtiofs-mounts `/Users`, not `/tmp`) and torn down after.

## Hub defects found and fixed on this branch (see git log for detail)

Every one of these was invisible to `scripts/test/run.sh --suite protocol`
(fakes/injected-only ACME coverage) and surfaced only once a real client
drove the endpoint:

1. **ACME-issued certificates were never persisted to the certificates
   table** (W18-16 finding from W18-14; the already-reviewed fix from
   parked branch `kk/w18-16-acme-persist` was ported onto this branch,
   since without it step 4 above cannot be proven at all).
2. **`GET /cas/{id}/chain?format=pem` served the SHA-256 fingerprint hex
   string wrapped in `BEGIN/END CERTIFICATE` markers**, not real
   certificate bytes — a value that looks like PEM but fails to
   base64-decode into anything. Blocked step 3 entirely.
3. **`handleChallenge` never set a `Link: ...;rel="up"` header** on any of
   its three response paths. RFC 8555 §7.5.1 requires it; python-acme's
   `ClientV2.answer_challenge` (certbot, and anything built on it)
   hard-fails without it.
4. **`handleCertificate` never set `Replay-Nonce`** on the certificate
   download response, required by RFC 8555 §6.5.1 for the client's next
   POST; certbot hit `acme.errors.MissingNonce` downloading the cert it had
   just been issued.
5. **The certificate download never included the issuing CA's certificate**
   — only the bare leaf. RFC 8555 §7.4.2 doesn't strictly require a chain,
   but every real client assumes Let's Encrypt's always-send-the-chain
   behavior; certbot hard-failed with "less than 2 certificates in chain".

## FG2 (EAB, ARI, provisioners, dns-01) - W26-05

`fg2-run.sh` is a separate harness (run.sh above is untouched and keeps its own
pass count). It proves the W26-01/02/03 features against real certbot and lego.

```
bash tests/live/acme/fg2-run.sh
```

Env: `KK_UAT_RUN_DIR` (default `$HOME/kk-uat-acme-fg2-run`, must be under `$HOME`),
`CHALLTEST_IMAGE` (default `ghcr.io/letsencrypt/pebble-challtestsrv:latest`; pin a
tag or digest after the first dry run and record it here), `CERTBOT_IMAGE`,
`LEGO_IMAGE`, `FG2_SUBNET_PREFIX` (default `10.91.26`, a /24 on its own network
`kk-uat-acme-fg2`; change it if it collides). Podman only; nothing is written
into the repo; the script tears everything down on exit.

Topology differences from run.sh: fixed IPs on that subnet, hub started with
`APP_ACME_EAB_REQUIRED=true` and `--dns` pointing at pebble-challtestsrv as its
only resolver (it answers the hub's dns-01 TXT lookups, and A queries for the
client names from mocks registered through its API). The clients keep podman
DNS. The hub binds `0.0.0.0` (as `tests/live/ca-revoke/fixture.sh` does).

| Step | Proves |
|---|---|
| 1 | `POST /api/v1/acme/eab-keys` returns `hmac_key` once; `GET` never does; provisioners `internal-tls` (http-01+dns-01) and `internal-dns` (dns-01 only), both allow `*.internal`. Four keys: each client/directory pair needs its own kid (one account key per kid). |
| 2 | `certbot register` without EAB is `externalAccountRequired` on the default and the provisioner directory; audit holds `acme.eab.reject`. |
| 3, 4 | certbot (`--eab-kid/--eab-hmac-key`) and lego (`--eab --kid --hmac`) issue, renew, revoke on `/acme/internal-tls/directory`; chain, inventory `source=acme`, OCSP `revoked` on the first request after revoke (no retry), CRL lists the serial. |
| 5 | `example.com` on the provisioner is `rejectedIdentifier` / not permitted. |
| 6 | dns-01 through `internal-dns` (which offers only dns-01): certbot `--manual` with `fg2-hooks/certbot-dns-auth.sh`, lego `--dns exec` with `fg2-hooks/lego-dns.sh`; hooks call challtestsrv `/set-txt`. |
| 7 | ARI: `renewalInfo/<certID>` 200 with the window end in the future; a mangled certID and an unknown serial give byte-identical 404; after an admin-API revoke the window closes at once and an ARI-aware lego renews without `--renew-force` or `--days`. |

Honest limits: the hub issues long-lived ACME certificates, so "inside the
window" is proven through the revocation-driven renew-now window. lego renewal
uses the `renew` subcommand when the image has one, else `run`; with `run` the
not-yet control is skipped (it cannot be gated on ARI). lego's DNS-propagation
skip flag is picked from `lego run --help`. Results:
`docs/release/LIVE_RESULTS_FG2_ACME_v0.14.md`.
