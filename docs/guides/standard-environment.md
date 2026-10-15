# Certificates for ordinary servers and apps

Most servers and applications do not speak ACME, EST or SCEP. They read a
certificate and key from a file and need a reload. Kryptkeeper gets
certificates onto them, and renews them, without anyone running a renewal by
hand. Pick the mode by what you can put on the host.

| Host / app | Mode | Needs on the host | Auto-renewal | Status |
|---|---|---|---|---|
| Linux nginx, Apache, HAProxy | Agentless SSH install | sshd, key login, a way to run the reload | hub scheduler | validated live |
| Linux nginx (agent can run) | Agent | the `kryptkeeper-agent` binary | hub tasks the agent | validated live |
| Windows IIS | WinRM push | WinRM reachable from the hub | hub scheduler | install validated live (Windows lab); scheduled renewal unit-tested |
| Kubernetes TLS Secret | Kubernetes push | a service-account token | hub scheduler | install validated live (`tests/live/k8s`, kind); scheduled renewal unit-tested |
| Windows agent | Agent | the Windows agent, inbound TCP 80 for HTTP-01 (`docs/ops/WINDOWS_AGENT.md`); renew-only, no install step in v0.9 | hub tasks the agent | validated (install/enroll/renew guard; no install target in v0.9); renewal needs the port 80 rule; see `docs/release/LIVE_RESULTS_WINDOWS_AGENT_v0.9.4.md` |
| macOS agent | Agent (launchd) | the macOS agent; see `docs/ops/MACOS_AGENT.md` | hub tasks the agent | validated (v0.9.4-rc.2); see `docs/release/LIVE_RESULTS_MACOS_v0.9.4.md` |
| macOS keychain | Keychain install | SSH to the Mac | n/a | not yet validated |

The reference for everything marked "validated live" is
`tests/live/autopilot/run.sh`. It stands up a hub, two nginx hosts and an
agent on a podman network and then only waits.

## Agentless: SSH to nginx, Apache or HAProxy

1. Give the hub an SSH key the host accepts. The hub pins the host key; it
   refuses unpinned hosts.
2. Store it as an `ssh_key` credential (`POST /api/v1/credentials`). The
   payload carries `user`, `private_key_pem`, `host_public_key` (authorized_keys
   format, from `ssh-keyscan`) and optional `port`.
3. Register the host as a target (Target Setup page, or `POST /api/v1/targets`):
   `host`, `install_mode: "ssh"`, `credential_ref`, `install_server_type`
   (`nginx`, `apache` or `haproxy`), `install_cert_path`, `install_key_path`,
   `install_reload_method` (`binary` = `nginx -s reload` / `apachectl -k
   graceful`; default = `systemctl reload <service>`), and **`auto_renew: true`**.
   `host` must equal the certificate's CN or one of its SANs: that is how the
   scheduler pairs a certificate with a target.
4. Issue the certificate for that name. From here the hub renews it.

On every tick the scheduler finds certificates inside the renewal window,
generates a new key and CSR on the hub, issues the successor, writes cert and
key (key mode 0600), runs the server's config test, reloads, dials the host on
`<host>:443` and checks the served leaf is the new one. If any step fails it
restores the previous files and reloads again; the old certificate keeps
serving. There is no free-form "run this command" recipe: reload is limited to
the three server types above.

### Policy knobs (Renewal Policy page / `PUT /api/v1/config/<key>`)

| Setting | Env | Default |
|---|---|---|
| `renewal_policy.threshold_days` | `RENEWAL_THRESHOLD_DAYS` | 30 |
| `renewal_policy.poll_hours` | `RENEWAL_POLL_HOURS` | 24 |
| `renewal_policy.alert_cooldown_hours` | `RENEWAL_ALERT_COOLDOWN_HOURS` | 24 |
| per-target `renewal_threshold_days` | target field | unset |
| per-target `verify_host_port` | target field | `<host>:443` |
| (env only) scan cadence under an hour | `RENEWAL_POLL_MINUTES` | unset |
| (env only) agent task sweep | `AGENT_RENEWAL_SWEEP_MINUTES` | 15 |

Hub renewals are issued for 90 days, so with the default 30-day window a
renewed certificate is not renewed again.

## Agent mode

Use it when the host cannot be reached by SSH from the hub, or you want
discovery too. Register an agent (`POST /api/v1/agent/register` with the
enrolment secret from `KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS`), then run
`kryptkeeper-agent` with `KRYPTKEEPER_HUB_URL`, `KRYPTKEEPER_AGENT_ID`,
`KRYPTKEEPER_AGENT_TOKEN`, `KRYPTKEEPER_SCAN_PATHS` and
`KRYPTKEEPER_CONFIG_PATHS` (and `KRYPTKEEPER_HUB_CA_CERT_FILE` if the hub CA is
private). The agent reports the certificates and nginx endpoints it finds. The
hub assigns a renewal task for each one inside the window; the agent renews
over the hub's ACME server (HTTP-01, so port 80 must reach the agent's web
root, `KRYPTKEEPER_WEB_ROOT`), writes the files, reloads and reports the
outcome. Nothing to configure per certificate. Requirements the harness
exposed:

- The certificate name must be a real DNS name. The hub's ACME server refuses
  `localhost` and will not fetch HTTP-01 over loopback.
- The agent's reload uses `systemctl reload nginx`; hosts without systemd need
  an equivalent.

## Windows IIS and Kubernetes

Both are push installs from the hub (`install_mode: "iis"` over WinRM,
`"k8s"` into a TLS Secret; F5 and Citrix work the same way). Device or cluster
details live in an `api_token` credential, not on the target, so the target
needs only `credential_ref` and **`auto_renew: true`**. The install itself is
validated live (k8s: `tests/live/k8s`; IIS: the Windows lab). The scheduler
renews and pushes these targets exactly as it does for SSH, but that scheduled
path is unit-tested only, not yet proven unattended on a live cluster or
Windows host. A target that is opted in but cannot be executed (for example no
`credential_ref`) is logged by the hub with the reason.

## Checking it is working

- `GET /api/v1/scheduler/renewal/status`: last scan, candidates, auto-renew
  triggers.
- Audit log: `certificate.renew_execute` (actor `renewal-scheduler`, outcome
  and `install=...` in the summary) on success;
  `certificate.renew_execute_partial` / `_failed` with outcome `failure` and
  the install outcome (`config_test_failed`, `reload_failed`, `verify_failed`)
  when the install was rolled back; `renewal_notification_sent` when the owner
  was told. Set the owner with `PATCH /api/v1/certificates/<fp>/ownership`.
- The old certificate shows a `successor_fingerprint`.

## When an install fails

The previous certificate keeps serving: the installer restores the previous
files and reloads. The scheduler then retries with exponential backoff (one
poll interval, capped at an hour, doubling) up to 5 attempts, auditing each as
`attempt=n/5`, and notifies the owner on the first failure and again on the
last (`certificate.renew_execute_gave_up`). `GET /api/v1/scheduler/renewal/status`
shows `pending_installs` and `gave_up_installs`: a non-zero value means a host
is still serving an older certificate. Each retry issues a fresh certificate,
because the private key of a failed attempt is destroyed with it; the unused
ones simply expire. Fix the cause (here, the nginx config) and the next retry
installs it, with no action on the hub.
