# UAT: deb/rpm install, upgrade, remove (W25-12)

Date: 2026-10-15. Host: macOS arm64, podman 6.x machine (applehv); containers
run natively as arm64, no emulation. Harness: `tests/live/packages/run.sh`
(`PKG_SOURCE=local`). Images: `debian:12`, `rockylinux:9`.

Packages were built from this tree's `packaging/nfpm/nfpm.yaml` with
`goreleaser/nfpm:v2.41.0` (run under podman because nfpm is not installed on
the host) at versions 0.0.1 and 0.0.2, with a stub shell script as the hub
binary: the run tests packaging, not the hub. `NFPM_ARCH=arm64`.

## Result: 8 of 8 steps PASS, 0 FAIL

```
target             step                                     result
debian:12          precondition_no_user                     PASS
debian:12          deb_install_creates_user_no_start        PASS
debian:12          deb_upgrade_env_sha256_identical         PASS
debian:12          deb_remove_keeps_data                    PASS
rockylinux:9       precondition_no_user                     PASS
rockylinux:9       rpm_install_creates_user_no_start        PASS
rockylinux:9       rpm_upgrade_env_sha256_identical         PASS
rockylinux:9       rpm_remove_keeps_data                    PASS
ALL PASS (0 FAIL)
```

Sub-checks behind each step (all `ok`): install exit 0; user `kryptkeeper`
exists with shell `/sbin/nologin`; `/usr/bin/kryptkeeper` and
`/usr/lib/systemd/system/kryptkeeper.service` present; `/etc/kryptkeeper/env`
is `640 root:kryptkeeper`; `/var/lib/kryptkeeper/keys` is `700`; no
`kryptkeeper` process; `postinstall.sh` has no `systemctl ... start|enable`
line outside its heredoc; `systemctl` absent in the container so a start was
impossible. Upgrade exit 0, installed version 0.0.2, user still present.
Remove exit 0, binary and unit gone, env and `/var/lib/kryptkeeper/keys` kept.

### Env file sha256 (after `UAT_MARKER=1` appended, before upgrade vs after)

| Target | before | after |
|---|---|---|
| debian:12 | `6b71537aa07240e22f889f878b69942f29c5f34e8725064bc358ad0ca0630633` | `6b71537aa07240e22f889f878b69942f29c5f34e8725064bc358ad0ca0630633` |
| rockylinux:9 | `6b71537aa07240e22f889f878b69942f29c5f34e8725064bc358ad0ca0630633` | `6b71537aa07240e22f889f878b69942f29c5f34e8725064bc358ad0ca0630633` |

Identical on both targets (the same hash on both is expected: same seed file
plus the same marker line). The hash was also unchanged after remove.

Limit of this evidence: `/etc/kryptkeeper/env` is not a packaged file. It is
created by `postinstall.sh` from `env.example` only when absent, so
"byte-identical across upgrade" proves that guard works; neither dpkg
conffile handling nor rpm `%config(noreplace)` is involved.

## Same packages through build-repo.sh (W25-11 end to end, local)

The four packages were run through `packaging/repo/build-repo.sh` with a
throwaway passphrase-less key (generated in the container, never kept) and
served by `python3 -m http.server`; clients installed over HTTP from it:

- `debian:12` without the key: `apt-get update` exits non-zero with `NO_PUBKEY
  19E840D068A1A09D` and `E: The repository ... InRelease' is not signed`
  (negative check PASS). With `signed-by` the `.gpg` key: `apt-get update`
  succeeds, `apt-get install kryptkeeper` installs 0.0.2, `kryptkeeper
  --version` prints the stub line.
- `rockylinux:9`: `dnf install -y kryptkeeper` with the generated
  `kryptkeeper.repo` (`gpgcheck=0`, `repo_gpgcheck=1`) imports the key from
  `kryptkeeper.asc`, installs `kryptkeeper-0.0.2-1.aarch64`, `--version` prints.
- `packaging/repo/build_repo_test.go` run in a Debian 12 container (with
  apt-utils, gnupg, createrepo-c, rpm): `TestBuildRepoApt`,
  `TestBuildRepoRejectsEmptyAndMissingKey`, `TestBuildRepoRpm` all PASS.

This is a local proof only. The hosted `https://pkg.kryptkeeper.io` repository
does not exist yet (needs the owner's secrets and Pages setup, see
`packaging/repo/README.md`), so `PKG_SOURCE=repo` is implemented but not run.

## Notes and findings

- Rocky 9 container already ships `shadow-utils`; the harness installs it only
  if missing. The package does not declare it as a dependency. Worth adding
  `Requires: shadow-utils` (rpm) / `passwd` (deb, always present) if minimal
  images without it matter.
- Debian 12 and Rocky 9 containers have no systemd, so `postinstall.sh`'s
  `systemctl daemon-reload` branch and `preremove.sh`'s stop/disable branch
  were not exercised. A real-systemd run is out of scope here.
- MSI (Windows agent) upgrade-keeps-env was validated live in
  `LIVE_RESULTS_WINDOWS_AGENT_v0.9.4.md`; env handling is unchanged, so it was
  not re-run and no Windows steps were added.
- Re-run: `bash tests/live/packages/run.sh` (about 70 s with images cached).
