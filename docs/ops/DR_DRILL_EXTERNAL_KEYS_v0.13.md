# DR drill: external key backend (HSM / KMS reference keys)

Ticket **W25-09** (FR-P54, UC-J05). Extends `docs/ops/RESTORE_DRILL.md` (software keys, Postgres) and the
"What's NOT covered" section of `docs/ops/DR_RUNBOOK.md` to CAs whose private keys are not extractable.

> **STATUS: PENDING. NOT RUN.** This ticket is human-paired. The runbook below is written but no step has been
> executed; every result cell is `TBD` and the verdict stays `PENDING` until the owner (or someone at the keyboard with him)
> runs it and pastes the real output. Commands in the setup section are unexecuted and may need small fixes on the
> first run; record any fix in section 10.

## 1. Scope and result summary

Claim under test: with CA keys held in an external backend, a lost hub **and** lost database can be rebuilt from
`backup.sh` output plus the surviving key backend, and the restored CA signs a new certificate that `openssl verify`
accepts.

| Check | Result |
|---|---|
| Postgres 16: row counts equal on every table (step 7) | TBD |
| Tables compared / tables PASS | TBD / TBD |
| `backup.sh`: `exported=N skipped_non_extractable=M error=0` (step 5) | TBD (acceptance: M > 0, error = 0) |
| Skipped key ids listed (not lost) | TBD |
| New certificate issued from the restored issuing CA (step 8) | TBD |
| `openssl verify -CAfile root.pem -untrusted issuing.pem leaf.pem` | TBD (acceptance: `leaf.pem: OK`) |
| Old certificate still validates; `GET /api/v1/cas` shows `key_storage_type: pkcs11` | TBD |
| Negative case: empty token, issuance fails closed (step 9) | TBD |
| RTO (disaster step 6 start to first successful issuance) | TBD |
| **Verdict** | **PENDING** |

## 2. Reference key backend

**SoftHSM2** inside a Linux container (nothing is installed on the operator's Mac). The token directory lives on a
podman **volume that is not removed in the disaster step**: it models an HSM that survives the loss of the hub.
SoftHSM2 proves the *mechanism* (references in the DB, keys behind PKCS#11, non-extractable skip, rebuild); it does not
prove a vendor HSM's behavior (clustering, wrapped-key replication, PIN policy). A real KMS run
(`tests/live/kms-aws`, `kms-azure`) is optional, costs money, needs credentials, and would add a second column to the
table above; it is not part of this acceptance and must not be run unattended.

## 3. Setup (all in containers)

Variables used below (set once in the shell you run the drill from; secrets come from `openssl rand`, are never
pasted into the recorded output, and `BACKUP_PASSPHRASE` is different from the keystore passphrase):

```bash
export REPO=$PWD                                    # the kryptkeeper worktree, under $HOME so podman can mount it
export NET=kk-dr-net TOK_VOL=kk-dr-tokens
export KEYSTORE_PASS="$(openssl rand -hex 24)"      # KRYPTKEEPER_KEYSTORE_PASSPHRASE
export CRED_PASS="$(openssl rand -hex 24)"          # APP_CREDENTIAL_STORE_PASSPHRASE
export BACKUP_PASSPHRASE="$(openssl rand -hex 24)"  # separate secret, backup bundle encryption
export HSM_PIN="$(openssl rand -hex 4)" HSM_SO_PIN="$(openssl rand -hex 4)"
export API_TOKEN="$(openssl rand -hex 16)"          # APP_BOOTSTRAP_TOKEN
export PGPASSWORD="$(openssl rand -hex 12)"
```

1. **Hub image with PKCS#11** (`-tags pkcs11` needs cgo and the SoftHSM2 module). Save as `$WORK/Containerfile.hub-hsm`:

   ```dockerfile
   FROM docker.io/library/golang:1.26-bookworm AS build
   RUN apt-get update && apt-get install -y --no-install-recommends gcc libltdl-dev && rm -rf /var/lib/apt/lists/*
   WORKDIR /src
   COPY . .
   RUN CGO_ENABLED=1 go build -tags pkcs11 -o /out/kryptkeeper ./cmd/kryptkeeper

   FROM docker.io/library/debian:bookworm-slim
   RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 opensc ca-certificates libltdl7 openssl \
       && rm -rf /var/lib/apt/lists/*
   COPY --from=build /out/kryptkeeper /usr/local/bin/kryptkeeper
   RUN printf 'directories.tokendir = /var/lib/softhsm/tokens\nobjectstore.backend = file\nlog.level = INFO\n' > /etc/softhsm/softhsm2.conf
   ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf KRYPTKEEPER_PKCS11_LIB=/usr/lib/softhsm/libsofthsm2.so
   ENTRYPOINT ["/usr/local/bin/kryptkeeper"]
   ```

   `podman build -t localhost/kk-dr-hub-hsm -f $WORK/Containerfile.hub-hsm $REPO`. (If the module path differs on the
   base image, `dpkg -L softhsm2 | grep libsofthsm2.so` and fix `KRYPTKEEPER_PKCS11_LIB`.)
2. **Network, token volume, token init.**

   ```bash
   podman network create $NET
   podman volume create $TOK_VOL
   podman run --rm -v $TOK_VOL:/var/lib/softhsm/tokens --entrypoint softhsm2-util localhost/kk-dr-hub-hsm \
     --init-token --free --label kk-dr --pin "$HSM_PIN" --so-pin "$HSM_SO_PIN"
   ```

   Do not use `podman volume rm $TOK_VOL` anywhere in step 6.
3. **Postgres 16** (source database): `podman run -d --name kk-dr-pg-src --network $NET -e POSTGRES_USER=kryptkeeper
   -e POSTGRES_PASSWORD="$PGPASSWORD" -e POSTGRES_DB=kryptkeeper docker.io/library/postgres:16-alpine`.
4. **Tools container** with a **matching-major** `pg_dump`/`psql` (`DR_RUNBOOK.md` version-skew note), `jq`, `curl`,
   `bash`, running `scripts/deploy/backup.sh` / `restore.sh` unmodified:

   ```bash
   podman run -d --name kk-dr-tools --network $NET -v $REPO:/repo:ro -v $HOME/kk-dr-out:/out \
     docker.io/library/postgres:16-alpine sleep infinity
   podman exec kk-dr-tools apk add --no-cache bash jq curl coreutils
   ```

   Record `podman exec kk-dr-tools pg_dump --version` (must be 16.x).
5. **Hub env file** `$WORK/hub.env` (shared by the source and the restored hub; the PIN is read from the environment,
   never echoed into the recorded output):

   ```
   APP_BOOTSTRAP_TOKEN=<API_TOKEN>              AUTH_MODE=bootstrap
   APP_CERTIFICATE_PROVIDER=ca                  APP_DISCOVERY_PROVIDER=db
   APP_NOTIFICATION_PROVIDER=file               KRYPTKEEPER_TLS_DISABLE=true
   APP_CREDENTIAL_STORE_PASSPHRASE=<CRED_PASS>  KRYPTKEEPER_KEYSTORE_PASSPHRASE=<KEYSTORE_PASS>
   KRYPTKEEPER_DB_MODE=postgres                 DATABASE_URL=postgres://kryptkeeper:<PGPASSWORD>@<pg host>:5432/kryptkeeper?sslmode=disable
   KRYPTKEEPER_KEY_BACKEND=pkcs11               KRYPTKEEPER_PKCS11_TOKEN_LABEL=kk-dr
   KRYPTKEEPER_PKCS11_PIN=<HSM_PIN>             KRYPTKEEPER_DATA_DIR=/data
   APP_BIND_ADDR=0.0.0.0                        PORT=8080
   ```

   (`KRYPTKEEPER_PKCS11_LIB` and `SOFTHSM2_CONF` come from the image.) Mount the token volume at
   `/var/lib/softhsm/tokens` and give each hub its own **fresh** `/data` volume (the point is that the hub filesystem is
   lost; only the database backup and the token survive). Publish the hub on a host port in 20080+ (avoid 3000, 8080,
   15432, 18080-19099).

## 4. Seed (source hub)

Boot the source hub with `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="DR Drill Root"` as in
`tests/live/pkcs11/run.sh`, then through the API (shapes: `tests/live/autopilot/run.sh` ~200-215, `RESTORE_DRILL.md`):

- an issuing (intermediate) CA under the root (`POST /api/v1/cas`, `type: intermediate`, `parent_ca_id` = root id).
  Note: `CACreateRequest` has no `key_storage_type` field; the CA's key lands in the token because
  `KRYPTKEEPER_KEY_BACKEND=pkcs11`, and `GET /api/v1/cas` then reports `key_storage_type: pkcs11`. Confirm both CAs show it.
- one template (`POST /api/v1/templates`), 10 certificates (`POST /api/v1/certificates` with a CSR each), 1 revocation
  (`POST /api/v1/certificates/{fp}/revoke`).
- Keep one issued leaf and its fingerprint for the "old certificate still validates" check in step 8.

**Row counts (source).** Take them **after step 5, with the source hub stopped**, so audit writes from the backup call are included:

```bash
podman exec kk-dr-pg-src psql -U kryptkeeper -d kryptkeeper -Atc \
  "select table_name from information_schema.tables where table_schema='public' order by 1" > src-tables.txt
while read -r t; do printf '%s %s\n' "$t" "$(podman exec kk-dr-pg-src psql -U kryptkeeper -d kryptkeeper -Atc "select count(*) from \"$t\"")"; done < src-tables.txt > src-counts.txt
```

Paste `src-counts.txt`: TBD.

## 5. Backup (before the disaster)

`backup.sh` exports keys through the **running** hub, so run it first, then stop the hub (and take the row counts above).

```bash
podman exec -e DATABASE_URL=... -e KRYPTKEEPER_API=http://<hub>:8080 -e API_TOKEN -e BACKUP_PASSPHRASE kk-dr-tools \
  bash /repo/scripts/deploy/backup.sh /out/bundle
jq -r '.keys[] | select(.status=="skipped_non_extractable") | .id' $HOME/kk-dr-out/bundle/keys-*.json
```

Paste the printed line `exported=N skipped_non_extractable=M error=0` (**M must be > 0**, every CA key is in the
token, and `error=0`) and the jq listing: TBD. Verify `SHA256SUMS`. Copy the bundle off the volume used by the hub.

## 6. Disaster

Stop and delete the source hub container and its `/data` volume; drop the source Postgres container (or drop and
recreate the database) and start a **new empty** Postgres 16 container `kk-dr-pg-dst`. **Keep `$TOK_VOL`.** Record the
time as the RTO start: TBD.

## 7. Restore

Ordering is load-bearing (`DR_RUNBOOK.md`): restore into a database no hub ever booted against.

1. `restore.sh /out/bundle` with `DATABASE_URL` pointing at `kk-dr-pg-dst`. It restores the dump, prints
   `database restored`, then polls `/readyz`.
2. **While it waits** (before booting the hub), take the target counts with the same two commands as step 4 against
   `kk-dr-pg-dst` and diff against `src-counts.txt`, printing one line per table:
   `PASS table=<t> src=<n> dst=<n>` or `FAIL table=<t> src=<n> dst=<n>`. Any FAIL is explained here, not hidden: TBD.
3. Boot the new hub (same env file, same token volume, fresh `/data`). The script then imports the bundle; skipped keys
   are reported, not errors. Paste the restore output (PIN and tokens redacted): TBD.

## 8. Prove the CA works

```bash
curl -s -X POST $HUB/api/v1/certificates -H "Authorization: Bearer $API_TOKEN" -d '{"ca_id":..,"template_id":..,"csr_pem":..}'
curl -s "$HUB/api/v1/cas/$ISSUING_ID/chain?format=pem" -H "Authorization: Bearer $API_TOKEN" -o chain.pem
# split chain.pem into issuing.pem / root.pem, download the leaf as leaf.pem
openssl verify -CAfile root.pem -untrusted issuing.pem leaf.pem
```

Expected final line `leaf.pem: OK`: TBD. Also verify the saved OLD leaf the same way: TBD. `GET /api/v1/cas` shows
`key_storage_type: pkcs11` for both CAs: TBD.

## 9. Negative case

Boot a hub against the restored DB with a **different, empty** token (a new volume initialized with `softhsm2-util
--init-token`, same label and PIN). Issuance must fail closed with the key-missing error, and the hub refuses to start
unless `KRYPTKEEPER_ALLOW_MISSING_CA_KEYS=true`: **do not set it**. Record the refusal/error text: TBD. This is why the
HSM's own DR is mandatory.

## 10. What is still open

- Vendor HSM behavior (wrapped-key replication, clustering, firmware/PIN policy): follow the HSM vendor's DR docs.
- PIN custody: where the token PIN is stored and who can retrieve it during a real disaster.
- Cloud KMS: the same drill against KMS keys (key must still exist, new hub identity needs the same IAM), see
  `docs/ops/CLOUD_KMS.md`.
- Fixes needed to the commands above on first execution: TBD.
