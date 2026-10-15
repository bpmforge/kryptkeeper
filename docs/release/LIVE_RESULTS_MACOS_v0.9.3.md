# Live results: macOS install paths, v0.9.3

Date: 2026-10-15. Repo base: origin/main 6561651f. Validation only, no product code changed.

## Environment

- Host: Apple Silicon, macOS 27.0.1. The host keychain and launchd were not touched.
- Tooling: `brew install cirruslabs/cli/tart` FAILED on Homebrew 7.0.9 (the tap formula is pinned
  to tart 2.32.1 and uses a removed `depends_on :macos` form: `tart.rb:22`
  "Calling `depends_on :macos` with `depends_on macos:` is disabled"). Worked around by
  downloading the official tart 2.41.0 `tart.tar.gz` release asset, verifying its sha256 against the
  published checksum, and running it from a scratch directory. Tart is therefore NOT brew-installed.
- VM: `ghcr.io/cirruslabs/macos-tahoe-base:latest` cloned as `kk-macos-validate`, run with
  `tart run --no-graphics`. Guest: macOS 26.6.2, arm64, user `admin`, passwordless sudo
  (`sudo -n true` OK), Homebrew 7.0.9 preinstalled, no cosign/go. SSH key auth with a throwaway ed25519
  key (installed via `tart exec`).

## Verdicts

| Step | Verdict |
|---|---|
| 1. tart + VM | PASS (with the brew-tap workaround above) |
| 2. Release binaries | PASS (checksums, cosign, `--version`); Gatekeeper GUI path UNVERIFIED |
| 3. Homebrew formula | FAIL as shipped (no asset; template cannot work); PASS with a tarball-based formula |
| 4. Keychain installer W18-05 | PASS |
| 5. launchd agent service | GAP: no documented macOS service method; not run |
| 6. Teardown | DONE |

## 2. Release binaries (v0.9.3, darwin_arm64)

- Downloaded in the VM with curl: `kryptkeeper_0.9.3_darwin_arm64.tar.gz`,
  `kryptkeeper-agent_0.9.3_darwin_arm64.tar.gz`, `checksums.txt`, `.sig`, `.pem`.
- `shasum -a 256 -c` against `checksums.txt` (darwin lines): both `OK`.
- `cosign verify-blob` (cosign v3.1.3 installed in the VM via brew), identity pinned to
  `release.yml@refs/tags/v0.9.3`, issuer `token.actions.githubusercontent.com`: `Verified OK`.
  (Also verified OK on the host.) cosign prints deprecation warnings for `--certificate`/`--signature`;
  `docs/deployment.md` still documents those flags.
- `kryptkeeper --version` -> `kryptkeeper 0.9.3 (commit b21b96e0..., built 2026-10-15T02:34:31Z)`, rc 0.
  `kryptkeeper-agent --version` -> same string, rc 0.
- Signing state: `codesign -dv` shows `Identifier=a.out`, `flags=0x20002(adhoc,linker-signed)`,
  `Signature=adhoc`, `TeamIdentifier=not set`. `spctl --assess --type execute -vv` -> `rejected`
  (expected: not Developer-ID signed, not notarized).
- Quarantine behaviour:
  - curl download: no `com.apple.quarantine` xattr; the binary runs.
  - Simulated browser download (copy + `xattr -w com.apple.quarantine "0083;...;Safari;<uuid>"`):
    both binaries still ran from the SSH shell, rc 0, no prompt or kill. `spctl` still says `rejected`.
  - NOT observed: the interactive path (a real browser-downloaded file launched from Terminal.app or
    Finder, which can show the "cannot verify developer" dialog). SSH sessions cannot reach that UI.
    UNVERIFIED. The simulated xattr is also not byte-identical to what a browser writes.
- Doc check: `docs/deployment.md` step 2 uses `sha256sum --ignore-missing -c`; macOS 26.6.2 ships
  `/sbin/sha256sum`, so it works. `/usr/local/bin` exists (root-owned) so the `install` line needs sudo.

## 3. Homebrew formula

Root cause of the missing `kryptkeeper.rb` asset (two independent defects):

1. The `homebrew-formula` job no longer exists in `.github/workflows/release.yml`. It was deleted by
   commit 6f54fffb ("build(W20-02): goreleaser release"), which replaced the old hand-written workflow
   (job at old `release.yml:100`, `render-formula.sh` call at old line 116, upload at old line 119) with a
   `test` + `goreleaser` two-job file (`release.yml:28` and `:39`). Nothing in the current workflow or
   `.goreleaser.yaml` calls `packaging/homebrew/render-formula.sh` or uploads `kryptkeeper.rb`.
   `packaging/README.md:58-59` still claims the job exists.
2. The template and script target assets that goreleaser does not publish. `kryptkeeper.rb.tmpl:9,12`
   uses URLs `.../kryptkeeper-darwin-arm64` and `.../kryptkeeper-darwin-amd64` (raw binaries);
   `render-formula.sh:26-27` requires both raw files. `.goreleaser.yaml:76-93` publishes only `.tar.gz`
   archives named `kryptkeeper_<ver>_<os>_<arch>`, and `.goreleaser.yaml:26-29` ignores darwin/amd64
   entirely. So even a restored job would emit a formula whose URLs 404.

Evidence:

- `curl -L` from the VM on both raw URLs: `404` (arm64 and amd64).
- Rendered the formula with `render-formula.sh` against v0.9.3, feeding it the extracted arm64 binary under
  both raw names (the amd64 file is a stand-in copy, so the amd64 sha is meaningless).
- `brew install --build-from-source ./kryptkeeper.rb` (the command documented in `packaging/README.md`):
  FAIL, `Error: Homebrew requires formulae to be in a tap`. Homebrew 7 rejects path installs, so the
  documented local test no longer works.
- Rendered formula placed in a local tap (`brew tap-new kk/local`) and installed:
  FAIL, `Download failed: .../kryptkeeper-darwin-arm64 curl: (56) The requested URL returned error: 404`.
- Fixed formula (tarball URL `kryptkeeper_0.9.3_darwin_arm64.tar.gz`, sha256 `658586ef...`,
  `bin.install "kryptkeeper"`, test asserts `--version` contains 0.9.3), in the local tap:
  `brew install --build-from-source kk/local/kryptkeeper` PASS; `brew test` PASS (rc 0);
  `kryptkeeper --version` -> 0.9.3; `brew uninstall` PASS; binary gone from PATH; `brew untap` clean.
- Nothing is published to a tap, so `brew install kryptkeeper` has never been possible
  (`packaging/README.md:62-69` acknowledges this).

Suggested fix (not applied): have the template use the goreleaser tarball URL and checksums from
`checksums.txt`, add a darwin-arm64-only branch (or build darwin/amd64), call the script from a
post-goreleaser step (or use goreleaser's `brews:` block), and update the README's local test to use a tap.

## 4. Keychain installer (W18-05)

Command (inputs from the throwaway key and the VM's ed25519 host key):

```
KK_LIVE_KEYCHAIN=1 KK_KEYCHAIN_SSH_HOST=<vm ip> KK_KEYCHAIN_SSH_USER=admin \
KK_KEYCHAIN_SSH_KEY=<scratch key> KK_KEYCHAIN_HOST_KEY=<ssh-keyscan ed25519> \
GOTOOLCHAIN=go1.26.9 go test -count=1 -run . ./tests/live/keychain/ -v
```

Output:

```
=== RUN   TestLive_KeychainInstallPlacesAndTrusts
    keychain_live_test.go:103: result: {Installed:true Reloaded:false Verified:false RolledBack:false ServedFingerprint: Outcome:installed Detail:}
--- PASS: TestLive_KeychainInstallPlacesAndTrusts (0.40s)
PASS
ok  	kryptkeeper/tests/live/keychain	0.523s
```

PASS on macOS 26.6.2. After the run, `sudo security dump-trust-settings -d` reported "No Trust Settings were
found" (cleanup worked). `Verified:false` is expected: no TLS endpoint was configured.
Not covered (same as `docs/ops/MACOS_KEYCHAIN.md`): the full hub-to-Mac renewal sweep.

## 5. Agent as a launchd service

GAP. The repo documents no macOS service method for `kryptkeeper-agent`: no plist, no docs. The only
launchd material is the unrelated CI runner (`docs/ops/CI_RUNNER_SETUP.md`, `deploy/ci-runner/`).
`cmd/kryptkeeper-agent/main.go:387` defaults the agent type to `mac` on darwin, and
`docs/guides/standard-environment.md:15` lists macOS agent as "not yet validated". Agent runs from the
tarball: `--help` without env exits with `required environment variable KRYPTKEEPER_HUB_URL is not set`.
No hub was started in the VM and no enrollment or heartbeat was attempted. UNVERIFIED.

## 6. Teardown

`tart stop` and `tart delete kk-macos-validate` done; `tart list` shows no local VM. The scratch ssh key
and host key files were removed. The VM-only secrets (admin/admin image credentials) died with the VM.
Left behind: tart 2.41.0 in the scratchpad, and the cached OCI image
`ghcr.io/cirruslabs/macos-tahoe-base` (about 33 GB) in the tart cache; remove with `tart delete` on the OCI name.
