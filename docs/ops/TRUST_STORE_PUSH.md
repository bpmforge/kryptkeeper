# Trust store push

Push root and intermediate CA certificates from the hub into the operating-system
trust stores of managed hosts, so a private-CA rollover can land the new root
everywhere before the old one is retired. Decisions: D-318 (the bundle and its
approval) and D-319 (the agent's consent, privilege and results).

This changes what a host trusts. Three independent gates stand between a hub
user and a host's trust store, and all three must agree:

1. **A second human approves.** Creating a bundle only queues a proposal. A
   different approver accepts it in Approvals (the proposer can never approve, and
   neither can the MCP agent).
2. **The host opted in.** The agent acts only if its own configuration says so.
   Off by default. A compromised hub cannot add a root to a host that did not ask.
3. **The privilege is one exact command.** On Linux and macOS the agent runs as an
   unprivileged account and may run exactly one root command, with one argument,
   from a separate drop-in you install deliberately.

## Create a bundle

Agents, then **Trust stores**, then **Propose a bundle**.

- **Certificates**: PEM, certificates only. Every certificate must be a CA
  (basicConstraints CA:TRUE). Any other block, a private key included, rejects the
  whole bundle and nothing is stored. At most 20 certificates. For **Add**, an
  expired or not-yet-valid certificate is refused; **Remove** may name an expired
  one.
- **Targets**: any mix of "all agents", "every Linux/macOS/Windows agent" and
  individual agents. The list is fixed at proposal time, so the approver sees the
  exact hosts and an agent that registers later is not included. Agents carry no
  tenant or label today, so with multi-tenancy on this is a platform super-admin
  setting.
- **Remove** deletes only certificates Kryptkeeper itself added (tracked by
  fingerprint in a local state file). A root an administrator installed by hand is
  never touched. If the root you remove issued live certificates the hub manages,
  the proposal carries a warning ("distrusts N live managed certificate(s)") that
  the approver also sees.

API: `POST /api/v1/trust-bundles` answers 202 with the pending action id; the MCP
agent may call it (it proposes, a human approves). `GET /api/v1/trust-bundles` and
`GET /api/v1/trust-bundles/{id}` show status.

## Opt a host in

In the agent's environment file (or the Windows service settings file) set:

```
KRYPTKEEPER_TRUST_STORE_PUSH=true
```

Anything other than `true` is off. An opted-out agent runs no command and reports
`refused_not_opted_in`; the hub keeps offering the bundle, so opting in later and
restarting the agent applies it.

### Linux and macOS: the sudoers rule

```
kryptkeeper-agent --generate-trust-store-sudoers | sudo tee /etc/sudoers.d/kryptkeeper-agent-truststore
sudo chmod 0440 /etc/sudoers.d/kryptkeeper-agent-truststore
sudo visudo -cf /etc/sudoers.d/kryptkeeper-agent-truststore
```

The file contains exactly this (no wildcard, and it is not part of the Renewal
Autopilot drop-in, which is never widened by it, D-114):

```
Cmnd_Alias KK_TRUSTSTORE = /usr/local/bin/kryptkeeper-agent --trust-store-apply
kryptkeeper-agent ALL=(root) NOPASSWD: KK_TRUSTSTORE
```

Requirements:

- `/usr/local/bin/kryptkeeper-agent` must be owned by root and **not writable by
  the agent account**; otherwise the rule is a root shell.
- The systemd unit needs `NoNewPrivileges=false` (the default blocks sudo) and,
  because `ProtectSystem=strict` also confines the sudo child, `ReadWritePaths=`
  for the files the helper writes: `/usr/local/share/ca-certificates` and
  `/etc/ssl/certs` (Debian family), `/etc/pki/ca-trust` (RHEL family), and
  `/var/lib/kryptkeeper-agent` for the state file.
- The root half validates every certificate itself, so it does not rely on the
  agent account or the hub having done so.

### Windows

The agent service already runs privileged; nothing to install. State is kept in
`%ProgramData%\Kryptkeeper\trust-state.json`.

## What the agent runs

| Platform | Add | Remove |
|---|---|---|
| Debian, Ubuntu | writes `/usr/local/share/ca-certificates/kryptkeeper-<sha256>.crt`, runs `/usr/sbin/update-ca-certificates` | deletes that file, runs `/usr/sbin/update-ca-certificates --fresh` |
| RHEL, Rocky, Alma, Fedora, CentOS | writes `/etc/pki/ca-trust/source/anchors/kryptkeeper-<sha256>.crt`, runs `/usr/bin/update-ca-trust extract` | deletes that file, runs `/usr/bin/update-ca-trust extract` |
| Windows | `certutil -store <store> <sha1>` (skip if present), then `certutil -addstore -f <store> <file>`; store is `Root` for a self-issued certificate, `CA` for an intermediate | `certutil -delstore <store> <sha1>` |
| macOS | roots: `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <file>`; intermediates: `security add-certificates -k /Library/Keychains/System.keychain <file>`; skipped if already in the keychain | roots: `security remove-trusted-cert -d <file>`; then `security delete-certificate -Z <sha1> /Library/Keychains/System.keychain` |

Other Linux distributions (SUSE and others) are refused with a clear message.

A certificate that was already trusted before the push (Windows, macOS) is not
taken over: it is skipped and never removed by a later bundle.

## Results

Each targeted host reports one of:

- `applied`: done (or already in place).
- `refused_not_opted_in`: the host has not opted in; nothing ran.
- `failed`: with the reason (unsupported distribution, a command failed, the
  privileged helper was not reachable). The agent retries a failed bundle every
  15 minutes while the hub keeps offering it.

Until a host reports, it shows as "waiting for the agent". Every proposal, the
approved creation (with proposer and approver) and each host's result are audited.

## Rolling over a private CA

1. Propose **Add** for the new root (and any new intermediate) to all agents.
2. Approve it; wait until every host shows `applied` (hosts showing
   `refused_not_opted_in` need the opt-in above).
3. Issue from the new CA and move services over.
4. Propose **Remove** for the old root. Read the warning before approving: it
   lists how many live managed certificates still chain to it.

## Proven

`tests/live/trust-store/run.sh` runs the real agent in Debian 12 and Rocky Linux 9
containers behind the real sudoers rule: refusal when opted out, add (a leaf the
root issued then verifies with the OS), remove (it stops verifying). See
`docs/release/LIVE_RESULTS_TRUST_STORE_v1.1.md`. The Windows and macOS commands are
covered by exact-command tests only; they are on the roadmap as needing real hosts.
