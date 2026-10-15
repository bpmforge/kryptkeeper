# Live results: macOS install paths, v0.9.4-rc.2

Date: 2026-10-15. Repo base: origin/main 5024da3e. Validation only, no product code changed.
Follows `LIVE_RESULTS_MACOS_v0.9.3.md`.

## Environment

- Host: Apple Silicon Mac. Host keychain and launchd were not touched; everything ran in a throwaway
  tart VM `kk-macos-094`, cloned from the cached `ghcr.io/cirruslabs/macos-tahoe-base:latest`.
- tart 2.41.0 (official tarball from the previous run; `brew install cirruslabs/cli/tart` still unusable).
- Guest: macOS 26.6.2 arm64, user `admin`, passwordless sudo, Homebrew 7.0.7 (not on the non-interactive
  SSH PATH; used `/opt/homebrew/bin`), `gh` preinstalled, cosign v3.1.3 installed with `brew install cosign`.
- SSH with a throwaway ed25519 key. Hub secrets (bootstrap token, enrollment secret, passphrases) came from
  `openssl rand`, lived only in 0600 files in the VM, and were never printed.
- Release assets are from tag `v0.9.4-rc.2`, downloaded inside the VM with curl (all HTTP 200).

## Verdicts

| Step | Verdict |
|---|---|
| 1a. Formula asset present + cosign verify | PASS |
| 1b. Homebrew 7 local-tap steps from `packaging/README.md` | PASS (one placeholder to fix in the doc) |
| 2. launchd agent per `docs/ops/MACOS_AGENT.md` | PASS, with 2 doc fixes needed |
| 3. Teardown | DONE |

## 1. Homebrew formula

1a. Assets `kryptkeeper.rb`, `.sig`, `.pem`, `checksums.txt`, `.sig`, `.pem` all present on the release (this
fixes the v0.9.3 FAIL where no formula asset existed).

- `cosign verify-blob` (identity
  `https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/v0.9.4-rc.2`, issuer
  `https://token.actions.githubusercontent.com`): `kryptkeeper.rb` Verified OK, `checksums.txt` Verified OK.
  cosign 3.1.3 still prints deprecation warnings for `--certificate` / `--signature`.
- Formula `sha256 965a982b...` equals the `checksums.txt` line for `kryptkeeper_0.9.4-rc.2_darwin_arm64.tar.gz`,
  and `shasum -a 256` of the downloaded tarball matches. The agent tarball also matches its checksum line
  (`29ee0cd2...`). The formula URL points at the goreleaser tarball (the v0.9.3 template defect is gone).

1b. Steps run exactly as in the README "Homebrew" section (tag changed to `v0.9.4-rc.2`):

| Command | Result |
|---|---|
| `gh release download v0.9.4-rc.2 --repo bpmforge/kryptkeeper --pattern kryptkeeper.rb` | PASS, rc 0 |
| `brew tap-new local/kryptkeeper` | PASS |
| `cp kryptkeeper.rb "$(brew --repository local/kryptkeeper)/Formula/"` | PASS |
| `brew install local/kryptkeeper/kryptkeeper` | PASS, `/opt/homebrew/Cellar/kryptkeeper/0.9.4-rc.2`, 7 files |
| `kryptkeeper --version` | `kryptkeeper 0.9.4-rc.2 (commit cbbf589b..., built 2026-10-15T16:11:27Z)` |
| `brew test local/kryptkeeper/kryptkeeper` | PASS, ran `kryptkeeper --version`, no error (the rc I captured belonged to `tail`, the test output itself showed no failure) |
| `brew uninstall kryptkeeper && brew untap local/kryptkeeper` | PASS; binary gone, tap dir gone, `brew list` has no kryptkeeper |

The formula's `depends_on :macos` was accepted by Homebrew 7.0.7 here (the v0.9.3 failure was in tart's own tap).
Doc nit: the README command says `v0.9.4`; that tag does not exist yet for this RC. Substitute the real tag at
release time. `gh` is assumed installed and was usable without login for this public repo.

## 2. launchd agent (`docs/ops/MACOS_AGENT.md`)

Setup: hub binary `kryptkeeper_0.9.4-rc.2_darwin_arm64` run as `admin` in the VM, `AUTH_MODE=bootstrap`,
bound to `127.0.0.1:8443` with its own self-issued TLS CA (`KRYPTKEEPER_TLS_SANS=localhost,127.0.0.1`),
`KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS` set. `/healthz` returned `{"status":"ok"}`. The hub CA was exported
through unauthenticated EST `/.well-known/est/cacerts` (PKCS#7, converted with openssl), and a `curl --cacert`
against it succeeded. Agent binary from the release archive, plist from `packaging/macos/` on origin/main.

| Doc step / claim | Result |
|---|---|
| Install binary to `/usr/local/bin`, 0755 | PASS (`root:wheel`) |
| Create support and log dirs, support dir 0700 | PASS |
| Edit plist: set hub URL and secret, copy CA to `hub-ca.pem`, uncomment `KRYPTKEEPER_HUB_CA_CERT_FILE` | PASS, but the doc gives no edit method (see fix 2) |
| `sudo install -m 0600 -o root -g wheel ...` | PASS, `-rw------- root:wheel` |
| `plutil -lint /Library/LaunchDaemons/...plist` as written | **FAIL**: `couldn't be opened because you don't have permission to view it` (file is 0600 root, command has no sudo). `sudo plutil -lint` prints `OK`. |
| `sudo launchctl bootstrap system ...` | PASS, rc 0; `print` shows `state = running`, `pid`, `last exit code = (never exited)`, `keepalive \| runatload`, stdout/stderr path = `agent.log` |
| Agent registers | PASS. Log: `registered: agent_id=558c38c67c47b416`, `credentials saved ... (mode 0600)`, `discovered 127 certificates, 2 endpoints`, `hub accepted 127 certificates` |
| Credentials file written 0600 | PASS: `-rw------- root:admin` `/Library/Application Support/Kryptkeeper/agent.env`, contains `KRYPTKEEPER_AGENT_ID` and `KRYPTKEEPER_AGENT_TOKEN` (token not printed). Group is `admin`, not `wheel` (inherited from the support dir); harmless at 0600, doc only promises the mode. |
| Hub API lists the agent | PASS: `GET /api/v1/agents` -> `type: mac`, `status: active`, `inventory_count: 127`, `registered_at 16:24:23Z` |
| Heartbeat advances `last_seen` | PASS: untouched 5 minute poll (log `poll=5m0s`) moved `last_seen` from `16:25:03Z` to `16:30:03Z`, with a matching `hub accepted` log line |
| Logs at `/Library/Logs/Kryptkeeper/agent.log` | PASS |
| `launchctl kickstart -k` restart | PASS: pid 2503 -> 2553, log shows `agent 558c38c67c47b416 starting` with no re-registration, same agent id, still the only agent in the hub, `last_seen` advanced to 16:24:53Z |
| "Remove the enrollment secret from the plist and reload it" | PASS: removed the key, `install -m 0600 -o root -g wheel`, `bootout` then `bootstrap`; agent came back (new pid), reused the saved credentials, same agent id, heartbeated (`last_seen 16:25:03Z`). Secret not needed after first registration. |
| Uninstall: `bootout`, `rm` plist and binary, `rm -r` support and log dirs | PASS: all rc 0; `launchctl print` -> `Could not find service`; no agent process; `/Library/LaunchDaemons`, `/Library/Application Support/Kryptkeeper`, `/Library/Logs/Kryptkeeper`, `/usr/local/bin/kryptkeeper-agent` all gone; `find` of `/Library /usr/local /private/var/db /private/etc` for `*kryptkeeper*` found nothing. |
| "Delete the agent in the hub UI too, or it stays listed" | Confirmed: right after uninstall the hub still showed the agent `active` (status only goes stale later). Deletion not exercised. |

Not exercised: reboot persistence (RunAtLoad/KeepAlive are present in `launchctl print` but the VM was not
rebooted), ACME HTTP-01 renewal on port 80, the install-to-System-keychain path (covered by the v0.9.3
keychain run), a quarantined-binary Gatekeeper prompt.

### Doc fixes needed

1. `docs/ops/MACOS_AGENT.md` Install step 4: change `plutil -lint /Library/...` to `sudo plutil -lint ...`.
2. Install step 3 says "Edit" the plist with no method. Add one that works. Caveat found: `PlistBuddy` rewrites
   the file and drops the XML comments, including the commented-out `KRYPTKEEPER_HUB_CA_CERT_FILE` block, so
   uncomment that block (or add the key) before any `PlistBuddy Set`, or edit with a text editor throughout.
   The same applies when removing the enrollment secret.
3. Remove the "Status: documented, validation pending" banner (or point it at this report) once accepted.
4. `packaging/README.md`: replace the literal `v0.9.4` in the `gh release download` example with a
   `<tag>` placeholder, and note the `gh` prerequisite.
5. Optional: `docs/deployment.md` cosign examples still use the deprecated `--certificate`/`--signature` flags.

## 3. Teardown

- Hub process killed with the VM; `tart stop kk-macos-094` and `tart delete kk-macos-094` done, `tart list`
  shows only the cached OCI image (`macos-tahoe-base`, 33 GB, kept for reuse). No `tart run` process remains.
- Scratch ssh key, public key and known_hosts file deleted. The remaining scratch scripts and tart 2.41.0
  stay in the session scratchpad and hold no secrets. All VM secrets died with the VM.
- Host keychain and host launchd untouched.
