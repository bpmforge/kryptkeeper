# Onboarding journey (W33-02)

Drives the first-run wizard (zero CAs) through Root CA, Template, First certificate,
the optional integrations step, and Discovery & install -> `/targets/setup`, then
proves the downloaded leaf with `openssl verify` against the new root.

## Prerequisite

A hub started WITHOUT `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT` on FRESH volumes (first-run
mode, W33-32). The smoke/roles stack sets that variable, so it is not usable here:
use the separate compose override in this folder and a dedicated project name.

```sh
export APP_BOOTSTRAP_TOKEN=$(openssl rand -hex 32) \
       KRYPTKEEPER_KEYSTORE_PASSPHRASE=$(openssl rand -hex 32) \
       APP_API_KEY_PEPPER=$(openssl rand -hex 32)
F=(-p kkw33-onboarding -f docker-compose.yml -f ui/e2e/onboarding/docker-compose.firstrun.yml)
docker compose "${F[@]}" up -d --build --wait
PORT=$(docker compose "${F[@]}" port dashboard 8080 | awk -F: '{print $NF}')
npm --prefix ui run e2e -- e2e/onboarding        # with the env below
docker compose "${F[@]}" down -v
```

Env for the run: `KK_E2E_BASE_URL=http://127.0.0.1:$PORT` and `KK_E2E_BOOTSTRAP_TOKEN=$APP_BOOTSTRAP_TOKEN`.
Host ports are engine-assigned. The first test creates the only CA; if a CA already
exists it skips loudly ("stack not clean") rather than passing silently.

`openssl` must be on PATH. A page refresh mid-wizard loses wizard state (UC-L01 edge):
not asserted.
