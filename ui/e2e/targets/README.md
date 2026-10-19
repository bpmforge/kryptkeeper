# Targets E2E (W33-26)

Adds an agent target (enrollment-token mint, live pairing) and an agentless Linux
target (SSH credential, host-key pin) through `/targets/setup`, against the compose
hub plus a real agent container and a throwaway sshd container.

Skipped unless `E2E_TARGETS=1` (they need a podman machine and take a few minutes
on a cold image cache). Containers are named `kkw33-e2e-*`, join the compose
network, and are removed after each spec; SSH keys are generated per run and never
committed.

```sh
export APP_BOOTSTRAP_TOKEN=$(openssl rand -hex 32) \
       KRYPTKEEPER_KEYSTORE_PASSPHRASE=$(openssl rand -hex 32) \
       APP_API_KEY_PEPPER=$(openssl rand -hex 32)
F=(-p kkw33-b -f docker-compose.yml -f ui/e2e/targets/docker-compose.targets.yml)
podman compose "${F[@]}" up -d --build --wait
PORT=$(podman compose "${F[@]}" port dashboard 8080 | awk -F: '{print $NF}')
E2E_TARGETS=1 E2E_COMPOSE_PROJECT=kkw33-b \
  KK_E2E_BASE_URL=http://127.0.0.1:$PORT KK_E2E_BOOTSTRAP_TOKEN=$APP_BOOTSTRAP_TOKEN \
  npm --prefix ui run e2e -- e2e/targets
podman compose "${F[@]}" down -v
```

Needs `go`, `ssh-keygen` and `podman` on PATH. The agent image is built from
`tests/live/agent` (unmodified Containerfile) with a linux agent binary built from this
checkout; the sshd image from `tests/live/ssh-install`.

The two SSH credential preflight assertions are `test.fixme` until gap ticket
W33-30 (SSH credential preflight) lands.
