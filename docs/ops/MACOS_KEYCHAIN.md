# macOS agentless install: System keychain (W18-05)

Status (2026-10-07): implemented, and proven live against macOS 26.6.2 (a
disposable tart VM) with `tests/live/keychain`.

## What it does

A managed target with `install_mode=keychain` is a Mac the hub reaches over
SSH. On renewal the hub:

1. Builds a PKCS#12 bundle containing the renewed leaf, its key and the
   issuing CA chain, protected by a random per-install password. The chain is
   appended from the hub CA because the renewed download is the leaf alone.
2. Creates a private staging directory on the Mac (`mktemp -d`, mode 0700)
   before any key bytes are written. It removes the directory on every exit
   path.
3. Runs `sudo -n /usr/bin/security import … -k /Library/Keychains/System.keychain
   -x`, so the key is non-extractable.
4. Trusts each self-signed root in the chain:
   `sudo -n security add-trusted-cert -d -r trustRoot -k System.keychain`.
5. Proves the result two ways:
   - the leaf's SHA-256 must be listed by `security find-certificate -Z`;
   - `security verify-cert -c leaf.pem` must pass.

Outcomes:

- `installed`, or `installed_verified` when a TLS endpoint is configured to
  check.
- `cert_import_failed`: nothing usable was placed.
- `trust_failed`: the identity was placed, but its root could not be trusted
  or the leaf does not verify. The detail says which.
- `write_failed`.

The bundle password travels in argv, the same residual as the IIS installer.
It is redacted from every error, because the SSH executor quotes the command
line.

## Target requirements

- **SSH access:** an SSH user, with the host's public key pinned in the
  credential. The credential is type `ssh_key`: `user`, `private_key_pem` and
  `host_public_key` (authorized_keys format, e.g. from
  `ssh-keyscan -t ed25519 <host>`). The wizard asks for all three.
- **sudo:** passwordless sudo for `/usr/bin/security`. A narrower sudoers
  entry than full sudo is fine:
  `admin ALL=(root) NOPASSWD: /usr/bin/security`
- **Auto-renew:** with `auto_renew` on, the daily sweep renews keychain
  targets. No server type or file paths are needed.

## Trust on recent macOS (measured)

On macOS 26.6.2:

- **Adding** admin-domain trust as root over SSH works without any user
  interaction (`add-trusted-cert -d` exit 0;
  `dump-trust-settings -d` lists the root).
- **Removing** it the same way is refused: `remove-trusted-cert -d` gives
  "The authorization was denied since no user interaction was possible."
- **Deleting the certificate** from the System keychain does clear its trust
  setting.

If a Mac refuses the trust step (another macOS version, or an MDM
restriction), the install reports `trust_failed` with the identity in place.
Deploy the root with a configuration profile (MDM), then re-run.

## Live test

```bash
KK_LIVE_KEYCHAIN=1 KK_KEYCHAIN_SSH_HOST=<ip> KK_KEYCHAIN_SSH_USER=admin \
KK_KEYCHAIN_SSH_KEY=<client key> KK_KEYCHAIN_HOST_KEY="<ssh-ed25519 AAAA…>" \
go test -count=1 -v ./tests/live/keychain
```

Use a disposable Mac: the test changes the System keychain and admin trust.
It cleans up by deleting what it added. On Apple silicon,
`tart clone ghcr.io/cirruslabs/macos-tahoe-base:latest` gives a VM with SSH
and passwordless sudo.

Not proven live: the full hub-to-Mac renewal sweep. The hub VM could not reach
the tart VM's NAT network. That path is covered by
`TestRenewalExecutorKeychainTarget`, which uses production issuance and a fake
Mac that decodes the bundle it receives.
