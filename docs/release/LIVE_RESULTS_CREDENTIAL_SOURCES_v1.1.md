# Live results v1.1: credentials from Vault and OpenBao, W38-07

Date: 2026-10-25. Branch `worktree-agent-afadcb9a66838f2ff` (on `feat/v1.1-integrations`).

## Verdict: PASS against real HashiCorp Vault 1.20 and real OpenBao 2 with a real sshd. CyberArk and Delinea were not available: those two plugins are proven against mocks only

## What ran

`bash tests/live/credential-sources/run.sh` (58 PASS lines, `ALL PASS`, both flavors).
Per flavor it starts the secret manager in server mode (TLS with a per-run
certificate pinned as the source's CA, file storage for Vault and raft for
OpenBao, which dropped the file backend), a plain sshd host and a hub container,
all on one podman network created for the run. The hub reaches the manager by
container name over https, so the egress guard sees what production sees.
Unique names (`kk-w38-cs-<runid>-*`), nothing pruned, only this run's
containers, network and two images removed (verified: none left).

## Results

- **API shapes read from the live servers, not assumed.** `GET /v1/secret/data/ssh/web1`
  answers 200, `?version=1` 200, a path that does not exist 404, a path outside the
  token's policy 403. That 404 is what the hub reports as "not found".
- **A least-privilege token** (read on `secret/data/ssh/*` only) drives a real
  `POST /api/v1/discovery/scans` ssh scan. The scan completes and the host's
  `/etc/nginx/ssl/web.crt` is found with the fingerprint `openssl` reports on the
  host, though the hub never stored the private key. The credential row holds
  `source=external` and `reference={"path":"ssh/web1"}` only.
- **Test endpoint.** `POST /credential-sources/{id}/test` returns the field names
  (`host_public_key, port, private_key_pem, user`) and no key bytes.
- **Version pinning.** After version 2 was written with an unusable key, the
  "latest" credential's scan failed and the hub logged why
  (`credential payload is invalid: private key: ssh: no key found`, no key bytes),
  while the credential pinned to `version=1` still completed.
- **Refusals are clear.** Outside the policy: `vault kv2 denied reading
  secret/other/web1: the login has no read policy on that path`. Missing path:
  `nothing at secret/ssh/nope (missing path, deleted or destroyed version)`.
- **AppRole.** A real role and secret_id drive the same scan (one login per use,
  never reused). A wrong secret_id is `approle login failed ... invalid role or
  secret ID` and does not echo the submitted secret_id.
- **Audit.** 8 `credential.resolve` rows on the Vault run (5 success, 3 failure),
  each `source=vault_kv2:<id> credential_type=ssh_key outcome=ok|error class=...`.
- **No leak.** A line from the private key's body and the PEM header appear in no
  hub log line, no audit row and nothing under the hub's `/data` (database, audit
  file, certificates), checked after both runs.

## What this does not prove

- CyberArk CCP and Delinea Secret Server: the real wasm of each plugin passes the
  credentials conformance suite and an in-hub test (plugin manager, source,
  `Resolve`, payload validation, audit) against mocks that enforce the documented
  request shapes. No real CyberArk or Delinea service was used. The CyberArk
  response keys come from the RETURN block of CyberArk's Ansible module because
  the vendor's REST page was not reachable from the build tooling; its error
  ErrorCode was not verified. ROADMAP: "Needs partner hardware".
- Windows (WinRM) credentials fetched this way: the payload shape is unit-tested and
  an in-hub test resolves a Delinea `windows_password`; no WinRM host was used.
- Postgres: migration 000386 and the store SQL are written for both engines (and
  self-heal like the other stores); everything here ran on SQLite.

## Repeat

```bash
bash tests/live/credential-sources/run.sh            # KK_CS_FLAVORS=vault to run one; KK_CS_KEEP=1 keeps the stack
go test ./internal/bootstrap/ -run 'External|CredentialSource|PluginSource|CyberArkPlugin|DelineaPlugin' -count=1
go test ./tests/plugins/conformance/ -run 'CyberArk|Delinea' -count=1
```
