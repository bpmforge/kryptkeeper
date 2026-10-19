# Agentless scanning and renewal on a hardened Linux host

Root SSH login is blocked, `PermitRootLogin no` is policy, and you still want
Kryptkeeper to find and renew the certificates on the box. This guide covers
what you create on the host, the four ways to give the scan account privilege,
and what each one honestly exposes. The hub never asks for root login and never
accepts an SSH password; it uses a key-only account (this guide calls it
`kkscan`, any name works) plus, for root-owned files, `sudo`.

Everything below is generated for you by the target's **privilege bundle**
(`GET /api/v1/targets/{id}/privilege-bundle?mode=helper|nopasswd|password`, also
the Download buttons in Target Setup). The agent renders the same drop-in with
`kryptkeeper-agent --generate-sudoers --sudoers-mode=helper|nopasswd|password`.

## Pick a mode

| Mode | You do once | Scans | Renewals | What the `kkscan` key can do |
|---|---|---|---|---|
| **helper** (recommended) | create the account, install the helper, add one sudoers line | scheduled | yes | only the helper's verbs |
| **raw sudo allowlist** (`nopasswd`) | create the account, add a sudoers drop-in listing commands | scheduled | yes | effectively root read/write |
| **sudo password** | create the account, store its sudo password in the credential | scheduled | yes | root while the password is valid |
| **none** | create the account, authorize the key | read-only, world-readable files | no on privileged paths | nothing beyond its own uid |
| *one-off password* | nothing stored; type it when you run a scan or renewal | only when you run it | only when you run it | nothing at rest |

The mode a new credential starts with is an operator setting
(`agentless.default_privilege_mode`, env
`KRYPTKEEPER_AGENTLESS_DEFAULT_PRIVILEGE_MODE`, default `helper`) on the
Integrations page. Any mode stays selectable per credential.

## Steps common to every mode

1. Create the account: `sudo useradd -m kkscan`.
2. Authorize the Kryptkeeper SSH public key in `/home/kkscan/.ssh/authorized_keys`
   (key login only).
3. Pin the host key in the target (Target Setup shows the fingerprint to check).
4. Press **Test credential** on the target after setup. It dials with the pinned
   host key, then reports one row per capability (SSH login, sudo installed, sudo
   without a tty, sudo rule accepted, helper present and hash, and each command
   or helper verb the role needs), each with the exact fix.

### The `requiretty` fix

sudo is run without a terminal. Some distributions (older RHEL and derivatives)
ship `Defaults requiretty`, and sudo then answers "sorry, you must have a tty to
run sudo". The preflight detects that text and shows the line to add, which is
already included in every drop-in below:

```
Defaults:kkscan !requiretty
```

## Mode: helper (recommended)

Install the helper as root, then add one sudoers line.

```
sudo install -m 0755 -o root -g root kryptkeeper-helper /usr/local/sbin/kryptkeeper-helper
sha256sum /usr/local/sbin/kryptkeeper-helper      # must match the hash shown in Target Setup
```

`/etc/sudoers.d/kryptkeeper-kkscan` (mode 0440, check with `visudo -cf`):

```
Defaults:kkscan !requiretty
kkscan ALL=(root) NOPASSWD: /usr/local/sbin/kryptkeeper-helper
```

The helper is a short POSIX shell script (under 300 lines) you can read before
you install it. Its verbs are the whole allowlist:

| Verb | Does |
|---|---|
| `version` | prints its version |
| `list <root>` | lists certificate-like files under a directory (up to 8 levels) |
| `stat <path>` | prints type, mode, owner, group and size; never contents |
| `read-cert <path>` | prints only `CERTIFICATE` PEM blocks, or the certificate entries of a keystore; **refuses any file containing a private key** |
| `listeners` | listening sockets with the owning process uid and executable |
| `install <tmp> <dst> <mode> [owner:group]` | places a staged file, keeping owner and mode |
| `backup`, `restore`, `discard <path>` | keeps and restores a rollback copy on the host, so the hub never reads a key to be able to put it back |
| `config-test <server>`, `reload <service>` | run from a fixed table (nginx, apache, haproxy, tomcat) |

Every path must be absolute, contain no `..`, resolve to a regular file of at
most 1 MiB with an allowed extension, and not be `/etc/shadow`, `/etc/sudoers*`
or `/root/.ssh/*`.

**Why the hash is pinned.** The helper runs as root, so whoever can replace it
owns the host. The credential stores the expected sha256; the hub checks the
installed file before first use in each session and refuses a mismatch
(`HELPER_TAMPERED`, a finding and an audit row) rather than run it.

**Residual risk.** A stolen `kkscan` key can read every certificate on the host
and replace certificates and keys in the allowed locations; it cannot read
private keys through the helper or run other commands. Anyone who can write
`/usr/local/sbin` already has root.

## Mode: raw sudo allowlist (`nopasswd`)

For sites that will not install a helper. The drop-in lists the commands by
path. Example for an nginx host whose certificates live in `/etc/nginx/ssl`:

```
Defaults:kkscan !requiretty
Cmnd_Alias KK_LIST    = /usr/bin/find /etc/nginx/ssl *
Cmnd_Alias KK_STAT    = /usr/bin/stat -c * /etc/nginx/ssl/*
Cmnd_Alias KK_READ    = /usr/bin/cat /etc/nginx/ssl/*
Cmnd_Alias KK_INSTALL = /usr/bin/install -m * /etc/nginx/ssl/*
Cmnd_Alias KK_LISTEN  = /usr/bin/ss -ltnp, /usr/sbin/ss -ltnp
Cmnd_Alias KK_SERVER  = /usr/sbin/nginx -t, /usr/bin/systemctl reload nginx
kkscan ALL=(root) NOPASSWD: KK_LIST, KK_STAT, KK_READ, KK_INSTALL, KK_LISTEN, KK_SERVER
```

**Residual risk, plainly.** sudoers matches command *arguments* with `fnmatch`
and without path separation: `*` also matches `/`, and `..` is not special. So
`cat /etc/nginx/ssl/*` also permits `cat /etc/nginx/ssl/../../shadow`, and
`find ... *` permits `find ... -exec`. A raw allowlist that includes `cat` or
`install` on globbed paths is **root read and write of the filesystem** for
whoever holds the `kkscan` key. Use it only if that is acceptable, and tighten
the directories to exactly the ones on the host. The hub flags such a credential
as privileged.

**What a clean scan looks like in this mode.** The generated drop-in covers the
target's install directory plus any directory you name with the bundle's
`scan_paths` parameter (for example `scan_paths=/opt/ssl`). It deliberately does
**not** cover the system key directory `/etc/ssl/private`. Because `*` also matches
`/` and `find ... -exec`, allowing `cat` or `find` there would hand the scan account
every private key on the host. So a nopasswd scan keeps reporting one
`INSUFFICIENT_PRIVILEGE` for `paths=/etc/ssl/private`, and nothing else once the
keystore directories are listed. That is the intended outcome, not a gap to close.
Helper and password modes read the directory and report none.

## Mode: sudo password

The drop-in is only the `!requiretty` line; the account must already be allowed
to use sudo (the `sudo` or `wheel` group). Store the password in the credential
(`sudo_password`): it is encrypted at rest, never returned by any API route,
never in a command line (it is sent on stdin to `sudo -S`), a log line or an
audit row, and the hub uses `sudo -k` so no ticket outlives the command.

**Residual risk.** The account is root for as long as the password is valid, and
rotating the password breaks scans and renewals until the credential is updated.
The password is not supported over WinRM.

## Mode: none, and the one-off password

With no sudo the scan reads what `kkscan` itself can read. Root-owned paths are
reported, not hidden: the scan records which paths it could not read and the
fix for the credential's mode. A scheduled run that hits unreadable paths says
*needs a password; run it now or switch mode*.

To run it once with privilege without storing anything, type the sudo password in
the Discovery scan dialog ("Run with sudo password") or send `jit_sudo_password`
to `POST /api/v1/discovery/scans` or `POST /api/v1/renewal/execute`. It is held
in process memory for that one job and wiped when it ends. It is never written
to the scan job, the audit log, a log line or the credential store; the audit row
records only `privilege_source=jit`.

## What a privileged renewal does

The installer runs unchanged on the privileged connection: snapshot, write,
config test, reload, verify, and rollback. Two things matter on a hardened host:

- **Ownership survives.** It reads the existing owner, group and mode first and
  re-applies them, so a push never turns `tomcat:tomcat` into `root:root`.
- **Rollback is honest.** The rollback copy is made on the host (helper mode), so
  the hub never reads a private key. If the rollback itself fails, the result is
  `rollback_failed`, the scheduler stops retrying, the target is flagged for an
  operator, and the audit log has `target.renewal.rollback_failed`.

Every privileged push is audited as `target.renewal.privileged` with the mode,
never the password.
