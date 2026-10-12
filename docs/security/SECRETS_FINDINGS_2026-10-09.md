# Secrets Findings — 2026-10-09 (--deep, pre-public-release)

Category: `secrets` | Scanner: secrets-scanner | Repo: `kryptkeeper` (HEAD + all refs)

## Scope and method

- **Refs scanned:** `git rev-list --all` = 1,633 commits, all local + remote branches, all tags
  (`internal/v1.0.0` … `internal/v2.2.0`). 11,679 unique blobs read via `git cat-file --batch`.
- **Tooling:** TruffleHog and gitleaks are **not installed** on this host, so neither ran.
  Substitute: a custom regex scan over every blob in history (AWS `AKIA…`, GitHub `ghp_`/`github_pat_`,
  `sk-…`, Slack `xox?-`, PEM/PKCS#8/OpenSSH/EC/encrypted/cosign private-key headers, kubeconfig
  `client-key-data`/`token:`, DB URLs with inline passwords, JWTs, `password|secret|token|api_key = "literal"`,
  `env || "literal"` fallbacks, RFC1918/CGNAT IPs, internal hostnames, personal e-mail), plus a second pass
  over every **added line** in `git log --all -p` (28.6 MB diff) for lab credentials (sshpass, hypervisor
  `root@pam`/`PVEAPIToken`, WinRM/LDAP/admin passwords, `-p "…"`, `hvs.`, `glpat-`, `tskey-`, base64 DER `MII…`),
  plus a filename sweep for `.env*`, `*.pem|key|p12|pfx|jks|kdbx`, `kubeconfig*`, `cosign.*`, `id_rsa*`,
  `*.tfstate` ever committed.
- **Gap:** no live-verification of any candidate (TruffleHog's verifier). Mitigated by the fact that no
  candidate was a credential-shaped real value — see triage. Recommend one `gitleaks detect --log-opts=--all`
  run before the visibility flip as an independent second tool.

## Summary

| Bucket | Current tree | History only | Rotation | History rewrite |
|---|---|---|---|---|
| Live credentials (keys, tokens, real passwords, private keys) | **0** | **0** | — | — |
| Sensitive non-credential info (lab topology / dev defaults / infra identifiers) | 3 | 1 | 1 conditional | Not required |
| Hardening gaps | 1 | — | — | — |

**Verdict:** No secret in the working tree or in any reachable commit requires rotation or a
history rewrite before the repo goes public. Findings below are LOW/INFO disclosure items.

## REAL findings

### SEC-01 — Home-lab network topology disclosed (LOW)
- **Where:** tree + history. 192.0.2.0/24 addresses in 20 files across history, 8 still in HEAD, e.g.
  `docs/STATUS.md:242` and `:405` (`192.…` lab host, hypervisor VM 123 on `prox…`, runner `kk-t…`),
  `docs/board/plan.json:6694`, `:6936` (`iis-…kk.local`), `docs/board/specs/W18-06.md:7`,
  `internal/bootstrap/winrm_discovery_test.go:109` (`192.…`, user `kkte…`), `internal/ca/san_test.go`,
  `internal/bootstrap/renewal_executor_test.go`, `internal/bootstrap/certificate_ca_provider_test.go`.
  History-only: `docs/SESSION_STATUS.md` (commit containing `ssh bmat…@192.…`), `docs/ops/DR_RUNBOOK.md:120`,
  `internal/agentinstall/live_k8s_test.go:13`.
- **Impact:** RFC1918, not routable; reveals lab host roles (Windows 11 IIS target, hypervisor nodes,
  k8s endpoint), a local Windows username and an SSH username. Useful only for an attacker already on the LAN.
- **Live?** Addresses appear current. **Rotation:** none. **History rewrite:** not required.
- **Fix (optional):** in tree, replace lab IPs in tests/docs with RFC 5737 (`192.0.2.x`) / `example.test`
  names. Live tests already read endpoints and passwords from env (`KK_WINRM_URL`, `KK_WINRM_PASS` —
  `internal/agentdiscovery/live_winrm_test.go:100-101`), which is correct.

### SEC-02 — hypervisor API token ID and privilege set documented (LOW)
- **Where:** tree + history — `docs/STATUS.md:389`, introduced in commit `f2224d1` (2026-10-07).
- **What:** the token **ID** `root…!claude` and its granted roles. The token **secret is not present**
  anywhere in history (searched `PVEAPIToken=`, `root@pam`, hypervisor + token/password).
- **Live?** Token is live, but no secret disclosed. **Rotation:** not required. **Rewrite:** not required.
- **Fix (optional):** reword to "a scoped hypervisor API token" before release.

### SEC-03 — Hardcoded dev-login default password (LOW, conditional rotation)
- **Where:** tree `scripts/dev/local-review-env.sh:21` (`${KK_DEV_PASSWORD:-Guid…}`); history-only copy in
  `docs/SESSION_STATUS.md`, commit `802314a` (2026-08-02), paired with `demo@example.com`.
- **What:** default password for the local review/demo environment, overridable by env.
- **Live?** Local dev env only as far as the repo shows. **Rotation:** REQUIRED only if this value is used
  on any network-reachable instance (demo/UAT host) — verify with the operator. **Rewrite:** not required.
- **Fix:** keep as a documented dev default, or generate a random password at script start and print it.

### SEC-04 — `.gitignore` lacks infra-secret patterns (INFO, hardening)
- **Where:** `.gitignore` (tree). Covers `*.pem *.key *.p12 *.pfx *.jks .env .env.local`, but not
  `*.tfstate*`, `kubeconfig*`, `cosign.key`, `.env.*` (only `.env.*.local`), or `docs/security/*-output*.json`.
- **Evidence nothing leaked:** filename sweep across all history found only `packaging/windows/agent.env.example`
  (template, no values). Repo has `deploy/terraform/` — a state file would contain DB passwords.
- **Fix:** add those patterns (outside this agent's write-scope; not modified).

### INFO — Identity metadata becomes public
- Remotes: `git.example.test` (the self-hosted forge) and GitHub `bpmforge`. Commit author e-mails and the the self-hosted forge hostname
  will be public with history. Not a secret; confirm intended.

## False positives (triaged, with reasoning)

| Hit | Location | Why FP |
|---|---|---|
| `postgres://post…@postgres:5432` | `.github/workflows/ci-main.yml:139`, `ci-pr.yml:166/168`, `nightly-scale-and-protocol.yml:93` (hist), `docs/ops/CI_RUNNER_SETUP.md:72` | Ephemeral CI service-container creds, never exposed |
| `postgres://post…:chan…@localhost` | `README.md:279` | Documented placeholder |
| `postgres://post…:kkte…@127.0.0.1:55432` | `docs/SESSION_STATUS.md:152` | Throwaway local test container |
| `postgres://…${POSTGRES_PASSWORD}` / `$DB_PASSWORD` / `...@` | `docker-compose*.yml`, `docs/deployment.md`, `user_data.sh.tpl:108`, `docs/ops/DR_RUNBOOK.md:53`, `RESTORE_DRILL.md:46` | Variable interpolation / elided |
| `uat-…-passphrase-32-bytes!!`, `tls-…`, `uat-plugins-bootstrap-token` | `tests/live/*/run.sh`, `tests/smoke/run.sh` | Documented placeholder passphrases for disposable harness containers |
| Test passwords/tokens (`defi…`, `s3cr…`, `hunt…`, `winp…`, `Pass…`, `f5-s…`, `adc-…`, `est-…`, `corr…`, `pw-s…`) | `internal/**/*_test.go`, `tests/plugins/conformance/*_test.go`, `ui/src/test/*`, `ui/src/mocks/handlers.ts` | In-test fixtures against fakes/httptest servers |
| `-----BEGIN … PRIVATE KEY-----` (10 in HEAD) | `agentless_ssh_test.go:75`, `haproxy_test.go:21`, `delivery_plugin_signing_test.go:151`, `handlers_credentials_test.go:41`, `outbound_credential_store_test.go:35`, `plugins/delivery/host_test.go:17`, `conformance/kit_test.go:146`, `conformance/testdata/hostile/main.go:47`, `ui/src/test/spiffe.test.tsx:81`, `ui/src/pages/TargetSetup.tsx:124` | Header-only or body `AAAA`/`key`/`MIIEv`/`fake-key-material`/`super-secret-material`; UI placeholder marked `secret-scan:allow` |
| EC / PKCS#8 private key headers | `cmd/kryptkeeper-discover-helper/main_test.go:83,88` (history only, `a670600`) | Body is the sentinel `SECRETKEYMATERIAL`, not a key |
| `MIID…` | `internal/agentdiscovery/keystores_test.go` (`8300f21`) | Certificate DER generated in-test (`testDER`) — public material |
| `client-key-data` / kubeconfig | `internal/agentdiscovery/keystores.go:182`, `keystores_test.go:128` | Parser field name; fixture built in-test |
| `AKIA` | `.github/workflows/ci-pr.yml` (`04d25b4`), `inventory_source_commercial_test.go` (`552a620`, `AKIATEST`) | Detection regex; fake 8-char fixture |
| `APP_BOOTSTRAP_TOKEN=REPL…` / `your-bootstrap-token` | `deploy/terraform/terraform.tfvars.example:12`, `docs/guides/pqc-certificate.md:27` | Placeholders |
| `publicKeyToken="31bf…"` | `deploy/uat-lab/autounattend.xml.tmpl:8` | Microsoft public assembly token |
| `MiiH…` | `ui/package-lock.json` (`91d1a54`) | npm integrity hash |
| Plugin signing keys | `internal/bootstrap/plugin_signing_keys.txt`, `internal/bootstrap/testdata/plugin-signing/*` | Public keys (expected-benign per HANDOFF) |
| `process.env.KK_REVIEW_API ?? "http://127.0.0.1:8080"` | `scripts/dev/serve-real.mjs:18` | URL default, not a secret |
| `*.corp`, `*.internal`, `*.local`, `10.0.0.x`, `192.168.1.x` | many tests/docs | Synthetic fixture names/ranges |

## Recommendations before the visibility flip

1. Run `gitleaks detect --log-opts="--all"` (or TruffleHog with verification) as an independent second tool.
2. SEC-03: confirm `Guid…` is not used on any reachable host; rotate there if it is.
3. SEC-04: extend `.gitignore` (`*.tfstate*`, `kubeconfig*`, `cosign.key`, `.env.*`, scan outputs).
4. SEC-01/02: optional doc/test scrub of lab IPs, usernames and the hypervisor token ID. No history rewrite needed.

## Addendum (coordinator, 2026-10-09): gitleaks run

gitleaks 8.30.1 was installed and run over all history (`gitleaks git --redact --log-opts=--all`, 1,454 commits, 20.2 MB): **26 hits, 0 real.** Every hit was triaged with its value truncated to 4 characters:

| Hits | Where | Verdict |
|---|---|---|
| 7 | tests/live/agent/run.sh `Authorization: Bearer uat-…` | FP: the live harness's own throwaway bootstrap token |
| 6 | tests/smoke/run.sh `APP_AUTH_LOGIN_PASSWORD_HASH` | FP: hash of the smoke suite's fixture password |
| 4 | docs/ops/workflow-hardening-report-2026-04-06.md `APP_JWT_HS256_SECRET=ci-smo…` | FP: the CI smoke suite's fixed test secret |
| 4 | docs/API_DESIGN.md, docs/sdlc/phase-3-design/API_DESIGN.md example `access_token`/`token`/`secret` | FP: illustrative examples (`eyJh…`, `kk_a…`) |
| 2 | private-key in cmd/kryptkeeper-discover-helper/main_test.go, internal/agentdiscovery/agentless_ssh_test.go | FP: fake/sentinel test keys (see the table above) |
| 1 | tests/plugins/conformance/appliances_test.go `password` | FP: mock-device test password |
| 2 | docs/STATUS.md:216, internal/bootstrap/spiffe_workload_grpc.go:31 | FP: prose ("join-token", "bearer token") |

The recommended verification is done; the verdict above (no rotation, no history rewrite) stands.
