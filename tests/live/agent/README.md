# W19-04 — kryptkeeper-agent live UAT fixture

Proves the agent-mode path against a real hub: a Linux container running
`cmd/kryptkeeper-agent` (1) registers with a token the hub issued, (2) pushes
a real inventory of certificates found on its filesystem, and (3) attempts
the renewal task the hub queues for it.

## Run

```
bash tests/live/agent/run.sh
```

Requires `podman` (no docker) and a free host port 80 (real RFC 8555 HTTP-01
challenges always target port 80 — see "Why CN=localhost" below) and 8091/8445.
Builds the agent binary for the podman machine's arch, builds the fixture
image, runs the hub on the host and the agent+nginx in a container, and prints
PASS/FAIL per step. Idempotent: tears down any prior `kk-uat-agent*`
container/image state before running, and always cleans up on exit (trap).

> **Update:** the hub's ACME server now refuses `localhost` names (RFC 6761)
> and http-01 fetches over loopback, so the harness no longer uses the host hub,
> host port 80 or `CN=localhost` described in the sections below. The hub runs
> in a container and the agent host is a container named `agenthost` on one
> podman network (certificate and ACME identifier `agenthost`). Sections below
> describe the original W19-04 findings and are kept as history.

## What it proves, and what it found

1. **Enrol** — `KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS` gates
   `POST /api/v1/agent/register` (`internal/bootstrap/agent_attestation.go`).
   run.sh pre-registers via curl with that secret (mirroring what a human
   would do from `TargetSetup.tsx`'s pairing flow, since the agent's own
   `Register()` only logs credentials to stdout — `cmd/kryptkeeper-agent/
   main.go:93-101` — rather than persisting them) and injects the returned
   `KRYPTKEEPER_AGENT_ID`/`KRYPTKEEPER_AGENT_TOKEN` into the container.
   `GET /api/v1/agents` (bearer auth) is asserted to show the agent
   `active` after its first heartbeat.

2. **Inventory** — the fixture nginx vhost's short-lived (2-day) self-signed
   cert plus 3 extra placeholder PEMs under `/etc/ssl/certs-extra` are
   picked up by `agentdiscovery.WalkCerts`/`WalkConfigCerts`
   (`internal/agentdiscovery/linux.go`, `configparser.go`) and pushed via
   `POST /api/v1/agent/inventory`. Asserted via the agent's own container
   log ("hub accepted N certificates") and `GET /api/v1/agents`'
   `inventory_count`.

3. **Renewal task queue** — `internal/bootstrap/managed_target_store.go`'s
   own doc comment says `ManagedTarget.InstallMode` is **not consumed
   anywhere**; `errRenewalTargetNotSSH` (`renewal_executor.go:41`) confirms
   the per-target renewal executor refuses `install_mode=agent` outright.
   The actual "agent task queue" is `matchRenewalTasks`
   (`handlers_agents.go:289-348`), driven purely by the agent's own reported
   inventory: `AutoRenewable && NotAfter <= now+RENEWAL_THRESHOLD_DAYS &&`
   endpoint-matched-by-cert-path. Creating a `ManagedTarget` with
   `install_mode=agent` is exercised by run.sh to document that inertness
   directly (acceptance-checked, not asserted as the trigger).

   The fixture's 2-day cert is inside the default 30-day threshold, so a
   `renew` task is assigned automatically on the first inventory push — no
   CSR issuance through the hub's certificate API is needed to reach this
   step; that API is not in the loop for agent-mode task assignment at all.

   **Renewal now completes end-to-end (fixed on `kk/w19-04-agent-rerun`,
   2026-09-10). Three compounding defects had to clear, in order:**

   1. **The ACME server's self-advertised base URL was unreachable
      whenever the hub bound a wildcard address** — fixed by W19-13's
      `resolvePublicBaseURL` (`cmd/kryptkeeper/main.go:686`).
      `KRYPTKEEPER_BASE_URL` now wins when set; run.sh sets it to
      `http://host.containers.internal:$HUB_PORT` and a container-side
      `curl` of `/acme/directory` confirms every URL (`newAccount`,
      `newOrder`, `finalize`, ...) is rooted there instead of `0.0.0.0`.

   2. **`AgentRenewalTask.Subject` carried the full RDN string, not a
      bare hostname** — fixed by W19-13's `Identifiers []string` field
      (`handlers_agents.go`'s `renewalIdentifiers`/`parseCNHostname`).
      The queued task now also carries `"identifiers":["localhost"]`,
      and `AcmeRenewer.Renew` (`internal/agentclient/acme_renewer.go:64`)
      uses that instead of the Subject RDN.

   3. **A third, previously undiscovered defect**: `agentinstall.
      Installer.Install`'s post-reload verify step raced nginx's reload.
      `nginx -s reload` (`internal/agentinstall/installer.go`'s
      `reloadCommand`) sends a signal and returns before the master has
      actually swapped workers; the very next TLS dial
      (`defaultVerifier`, `verify.go:27`), issued microseconds later,
      observed the pre-reload leaf on every one of five separately-issued
      renewals in a row. Fixed by `verifyWithRetry` (10 attempts, 300ms
      apart) — no fingerprint comparison was loosened, it just tolerates
      the reload's inherent async handover.

   `ca_url` in the task JSON (`AgentRenewalTask.CAURL`,
   `handlers_agents.go:83`) is still always `""` — traced and confirmed
   **dead, not a bug**: it is declared but never assigned in
   `matchRenewalTasks`, and the agent never reads it, deriving its ACME
   directory URL from its own `KRYPTKEEPER_HUB_URL` instead
   (`AcmeRenewer.Renew`, `acme_renewer.go:64`).

   See `docs/STATUS.md`'s 2026-09-10 "W19-04 done (rerun)" entry for the
   full per-step evidence and log excerpts.

## Why `CN=localhost`, and port 80

RFC 8555 HTTP-01 always dials the identifier on port 80 — there is no
configurable port (`internal/acme/server.go:1104`). `localhost` needs no
`/etc/hosts` edits on the host, since it already resolves to 127.0.0.1.
run.sh publishes the container's `:80` to the host's `:80`
(`podman run -p 80:80`) so the hub's HTTP-01 fetch (from the host) reaches
the agent's challenge file. On this podman machine that required a
one-time, best-effort `podman machine ssh -- sudo sysctl -w
net.ipv4.ip_unprivileged_port_start=0` (run.sh runs it automatically,
ignoring failure) — the rootless port forwarder otherwise refuses
privileged ports; this tunes the podman VM, not the product, and reverts
on VM restart. Port 8445→443 is the TLS vhost `openssl s_client` checks
against and is unaffected by any of this.

## Fixture layout

- `Containerfile` — Ubuntu 24.04 + nginx + openssl-minted fixture certs,
  COPYs in a prebuilt `kryptkeeper-agent` binary (never built inside the
  image).
- `nginx-agent-uat.conf` — the vhost pair (:80 ACME webroot, :443 TLS)
  `agentdiscovery`'s config parser must byte-for-byte match against.
- `entrypoint.sh` — starts nginx, then execs the agent in the foreground.
- `run.sh` — builds both binaries, drives the hub + container lifecycle,
  and prints PASS/FAIL per step. No real key material is committed; every
  cert/key here is generated fresh at build time.
