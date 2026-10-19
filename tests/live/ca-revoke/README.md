# W23-37: revoke an issuing CA, live

Proves CA revocation end to end against a real hub: a root R, an RSA-2048
intermediate I and a leaf L. A proposes `POST /api/v1/cas/I/revoke`, B approves,
then `openssl ocsp` for L reports `revoked`, R's CRL lists I with reason
CA Compromise, and enrolment through I is refused on ACME (lego), EST
(globalsign/est), SCEP (micromdm/scep) and CMP (`openssl cmp`).

```
bash tests/live/ca-revoke/run.sh                  # Postgres (the product's mode)
FX_DB_MODE=sqlite bash tests/live/ca-revoke/run.sh  # see "Why a sqlite mode"
KK_KEEP_GOING=1 bash tests/live/ca-revoke/run.sh  # do not stop at the first FAIL
```

Prerequisites: podman (no docker), Go, OpenSSL 3 on the host (`openssl ocsp`
over https), python3, network access to pull alpine, postgres:16-alpine,
golang:1.23-alpine and goacme/lego, and to fetch Go modules inside the EST and
SCEP client containers. The hub is the linux/arm64 binary built from this
checkout (change `GOARCH` in `fixture.sh` on an amd64 host).

Environment: `HUB_PORT` (default 18437), `FX_DB_MODE` (`postgres` default,
or `sqlite`), `KK_KEEP_GOING`, `RECORD` (output path). The two admins and their
tokens are generated per run into `APP_API_KEYS_JSON` and never printed.

Output: `RESULTS.md` (Postgres) and `RESULTS-sqlite.md`, each stamped with date,
git SHA of the checkout under test (the parent of the commit that stores the
file), machine, and tool versions. Containers, the network and the temp dir are
removed on exit, including on failure.

`fixture.sh` is shared with `tests/live/key-compromise`.

## Why a sqlite mode

Revoking a CA on Postgres currently fails: `insertRevokedCertificate`
(`internal/ca/revocation.go`) writes JSON text (`null`, `["a"]`) into
`TEXT[]` columns, so Postgres rejects it with `malformed array literal`. The
unit tests run on sqlite and do not see it. The sqlite run exercises the rest
of the scenario and is labelled as such in its record; it does not replace the
Postgres result.

Not part of `go test ./...` and not wired into CI.
