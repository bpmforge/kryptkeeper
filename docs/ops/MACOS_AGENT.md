# macOS agent: install and run as a LaunchDaemon

**Status: validated** on v0.9.4-rc.2 (install, enroll, renew); see
`docs/release/LIVE_RESULTS_MACOS_v0.9.4.md`.

The agent runs as root under launchd, starts at boot, and is restarted if it
exits. It discovers certificates and renews them over ACME HTTP-01 against the
hub. (For installing a renewed certificate into the macOS System keychain the
hub reaches the Mac over SSH instead: see `docs/ops/MACOS_KEYCHAIN.md`.)

## Install
Downloading release assets with `gh release download` needs the GitHub CLI
(`gh`); `curl -LO` on the release asset URLs works too.

1. Put the binary at `/usr/local/bin/kryptkeeper-agent` (`darwin_arm64` or
   `darwin_amd64` from the release archive) and `chmod 0755` it.
2. Create the support and log directories:
   ```
   sudo mkdir -p "/Library/Application Support/Kryptkeeper" /Library/Logs/Kryptkeeper
   sudo chmod 0700 "/Library/Application Support/Kryptkeeper"
   ```
3. Edit `packaging/macos/com.kryptkeeper.agent.plist`: set
   `KRYPTKEEPER_HUB_URL`, and `KRYPTKEEPER_AGENT_ENROLLMENT_SECRET` (one of the
   hub's `KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS`; the hub refuses
   self-registration without it). If the hub's certificate is self-issued,
   copy its CA to `/Library/Application Support/Kryptkeeper/hub-ca.pem` and
   uncomment `KRYPTKEEPER_HUB_CA_CERT_FILE`. Edit with a text editor
   (`nano`/`vim`), and uncomment that block first if you need it: PlistBuddy
   rewrites the whole file and strips XML comments, including the commented
   `KRYPTKEEPER_HUB_CA_CERT_FILE` block.
4. Install it root-owned and private, since it holds the enrollment secret:
   ```
   sudo install -m 0600 -o root -g wheel packaging/macos/com.kryptkeeper.agent.plist \
     /Library/LaunchDaemons/com.kryptkeeper.agent.plist
   sudo plutil -lint /Library/LaunchDaemons/com.kryptkeeper.agent.plist
   ```

## How settings are loaded
Unlike the Windows service, the macOS/Linux agent has no general settings file.
It reads its environment, which launchd fills from the plist's
`EnvironmentVariables`. The one file it reads back is its own registration:
on first start it registers and writes `KRYPTKEEPER_AGENT_ID` and
`KRYPTKEEPER_AGENT_TOKEN` to `KRYPTKEEPER_AGENT_CREDENTIALS_FILE`
(`/Library/Application Support/Kryptkeeper/agent.env`, mode 0600), and later
starts reuse them. Do not point that variable at a file holding other settings:
the agent replaces it on registration.
After the first successful registration, remove the enrollment secret from the
plist and reload it. Use `sudo nano`/`sudo vim` for this too (the file is
root-owned, mode 0600); PlistBuddy would strip the comments.

## Start, stop, status
```
sudo launchctl bootstrap system /Library/LaunchDaemons/com.kryptkeeper.agent.plist
sudo launchctl print system/com.kryptkeeper.agent        # state, last exit code
sudo launchctl kickstart -k system/com.kryptkeeper.agent # restart
sudo launchctl bootout system/com.kryptkeeper.agent      # stop and unload
tail -f /Library/Logs/Kryptkeeper/agent.log
```
`bootstrap` is also what makes it start at the next boot. After editing the
plist, `bootout` then `bootstrap` again.

## Uninstall
```
sudo launchctl bootout system/com.kryptkeeper.agent
sudo rm /Library/LaunchDaemons/com.kryptkeeper.agent.plist /usr/local/bin/kryptkeeper-agent
# optional: registration and logs
sudo rm -r "/Library/Application Support/Kryptkeeper" /Library/Logs/Kryptkeeper
```
Delete the agent in the hub UI too, or it stays listed as offline.

## Limits
- HTTP-01 renewal needs the agent to bind port 80 (root can). If another web
  server holds it, set `KRYPTKEEPER_WEB_ROOT` to that server's web root so the
  challenge file is written there instead.
- The install step (copy the cert, reload nginx/apache/haproxy) uses `sudo`
  and Linux-style paths and has not been validated on macOS. To put a
  certificate into the System keychain, use the agentless keychain mode.
- The log file is not rotated; add a `newsyslog` entry under
  `/etc/newsyslog.d/` if it grows.
- The binary is not notarised; if Gatekeeper quarantines a downloaded copy,
  `sudo xattr -d com.apple.quarantine /usr/local/bin/kryptkeeper-agent`.
