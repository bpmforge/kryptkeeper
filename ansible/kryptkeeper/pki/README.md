# kryptkeeper.pki

Ansible collection for a [Kryptkeeper](https://github.com/bpmforge/kryptkeeper) hub: issue, renew and revoke
certificates, read the inventory, and enrol the Linux agent. Version 1.1.0, Apache-2.0, `ansible-core` 2.15 or newer.

| Module | What it does |
|---|---|
| `kryptkeeper.pki.certificate` | `state: present` issues from a CSR (or renews through the hub's renew endpoint) and writes the PEM and chain to `path`; idempotent. `state: absent` revokes by `fingerprint` or by the certificate at `path`. Check mode supported. |
| `kryptkeeper.pki.certificate_info` | Reads certificates by fingerprint, serial or filter and returns the API items. |
| `kryptkeeper.pki.agent` | Mints a single-use enrolment token; with `install: true` downloads the release archive, **verifies its SHA-256 first**, installs it as a systemd service and enrols it. |

Argument names follow the Terraform provider (`ca_id`, `template_id`, `csr_pem` becomes `csr_path`/`csr_content`).
The managed host needs Python `cryptography` for the `certificate` module.

## Connecting

Every module takes `hub_url` (or `KRYPTKEEPER_URL`) and a bearer `token` (or `KRYPTKEEPER_TOKEN`; the option is `no_log`).
`ca_path` (or `KRYPTKEEPER_CA_BUNDLE`) is a CA bundle for a hub with a private CA; `validate_certs: false` exists for
throwaway labs only. The hub's own error message is shown on failure.

```yaml
- hosts: web
  tasks:
    - kryptkeeper.pki.certificate:
        hub_url: https://kryptkeeper.example.com
        ca_id: "{{ issuing_ca_id }}"
        template_id: "{{ web_template_id }}"
        csr_path: /etc/ssl/private/web.csr
        path: /etc/ssl/certs/web.pem
        renew_before_days: 21
      environment:
        KRYPTKEEPER_TOKEN: "{{ vault_kryptkeeper_token }}"
```

Re-running changes nothing while the certificate on disk is valid, matches the CSR's public key, is not revoked at the
hub and is more than `renew_before_days` from expiry. An expiring certificate that the hub holds as active is renewed
(`action: renewed`); anything else is issued (`action: issued`).

## Develop and test

```bash
python3 -m venv venv && . venv/bin/activate && pip install ansible-core pytest cryptography
tests/run-checks.sh 3.12          # pytest unit tests + ansible-test sanity (pass the Python you have)
tests/integration/run.sh          # live hub: needs podman/docker compose, openssl, curl
ansible-galaxy collection build   # writes kryptkeeper-pki-1.1.0.tar.gz (not committed)
```

`tests/integration/run.sh` brings up `deploy/try` with locally built images under a unique `RUN_ID`, runs
`tests/integration/targets/certificate/playbook.yml` (issue, re-run unchanged, check mode, renew, revoke, revoke again,
bad token) and removes only what it created. `KK_HUB_URL` and `KK_TOKEN` point it at a hub that is already running.

## Publishing

Publishing to Galaxy needs the maintainers' `kryptkeeper` namespace and an API key; building and testing do not.
`ansible-galaxy collection publish kryptkeeper-pki-1.1.0.tar.gz --token <key>` once those exist.
