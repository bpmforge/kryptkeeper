# Live results: v1 Linux coverage gaps (Tomcat JKS, W34 privilege modes)

Run 2026-10-18 on the lab runner (Ubuntu amd64, rootless podman 4.9, podman 5
for `podman build` via ~/shim, podman-compose 1.0.6).

## 1. ssh-install: Tomcat JKS keystore leg (qa/v1-final 36b8fadc)

`bash tests/live/ssh-install/run.sh` -> **ALL PASS, 54 checks**.

New fifth container (`ROLE=tomcat-jks`): same Tomcat 10.1, `server.xml` swapped
for `tomcat-server-jks.xml` (`certificateKeystoreType="JKS"`, `conf/kk.jks`).
The format is selected by `keystore_format: "jks"` in the `ssh_key` credential
payload (not the target; `renewal_executor.go` `sshCredentialPayload`).

| Check | Result |
|---|---|
| install_outcome installed_verified | PASS |
| served leaf == new_fingerprint (independent openssl via published port) | PASS |
| verify_host_port mismatch -> verify_failed, prior leaf still served | PASS |
| broken server.xml -> config_test_failed, old leaf served, kk.jks restored byte-for-byte (sha256) | PASS |
| installed file starts with JKS magic `feedfeed`, server.xml declares JKS | PASS |
| keystore password appears 0 times in hub log + audit (covers all Tomcat legs) | PASS |

First run's restore check hashed the PKCS12 path by mistake; fixed (36b8fadc)
and re-run green. No product bug found: the JKS path in
`internal/agentinstall/tomcat.go` works end to end.

## 2. W34 agentless-sudo (feat/v1-discovery-posture f6d3d0a6, separate clone ~/kk-w34, unmodified branch)

`bash tests/live/agentless-sudo/run.sh` -> **ALL PASS** for all three modes.

| Mode | Unprivileged scan INSUFFICIENT_PRIVILEGE | Privileged scan reads JKS+P12 | Listener correlation (nginx:443, tomcat:8443 high) | PRIVILEGED_INSTALL_PATH | Renewal via privexec | nginx -t failure rollback | No secret leakage |
|---|---|---|---|---|---|---|---|
| helper | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| nopasswd | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| password | PASS | PASS | PASS | PASS | PASS | PASS | PASS (incl. sudo password) |

Harness note (not a product bug): the W34 harness names compose containers
`<project>-<svc>-1`; podman-compose 1.0.6 names them `<project>_<svc>_1`, so
the first run failed at "services never listened". Run with a local,
uncommitted one-line change to `ctr()` in the VM clone. W34 should make `ctr()`
resolve the name (e.g. `podman ps --filter label=com.docker.compose.service`).

Observation for the W34 thread: in `nopasswd` mode the privileged scan still
reports `INSUFFICIENT_PRIVILEGE ... unreadable=1 paths=/etc/ssl/private;
fix=sudo -n works but its rule does not` (the raw allowlist does not cover that
directory). The harness treats this as acceptable (JKS/P12 read, no blocking
issue); confirm that is intended.

## 3. W34 fingerprint-corpus (same clone)

`bash tests/live/fingerprint-corpus/run.sh` -> **RESULT: PASS** (release gate).

| Mode | Expected | Correct | Wrong | Missed | Recall | Precision | High-conf wrong |
|---|---|---|---|---|---|---|---|
| full | 16 | 16 | 0 | 0 | 1.000 | 1.000 | 0 |
| deep | 16 | 16 | 0 | 0 | 1.000 | 1.000 | 0 |

Deep TLS stack: 10/10 correct. mssql (1 of 17 endpoints) SKIPPED in both
modes: podman-compose 1.0.6 rejects the global `--profile` flag, so the
VM clone ran with `--profile mssql` removed locally (mssql image was present
but the service is not started). Recall is therefore over 16 endpoints; mssql
needs a run on a compose provider that supports profiles (the Mac).
Confidence distribution: high=1 medium=12 low=3.

## 4. Re-verify 3a5c3f95 on podman-compose 1.0.6

Linux amd64 VM (Ubuntu, rootless podman 4.9, podman-compose 1.0.6), W34 clone
at `3a5c3f95` (`test(live): compose-implementation-neutral harnesses; nopasswd
outcome asserted (W34-20)`). The two earlier local workaround edits were
discarded; both harnesses ran **unmodified**.

### agentless-sudo: `bash tests/live/agentless-sudo/run.sh` -> exit 0, 50 PASS, 0 FAIL

| Mode | PASS | FAIL |
|---|---|---|
| helper | 15 | 0 |
| nopasswd | 14 | 0 |
| password | 15 | 0 |
| (setup, cleanup, shared) | 6 | 0 |

The nopasswd privileged scan asserts `INSUFFICIENT_PRIVILEGE` (unreadable=1,
`paths=/etc/ssl/private`, `fix=sudo -n works but its rule does not`) and that
the JKS/PKCS12 certificates are still read with `PRIVILEGED_INSTALL_PATH`
raised: PASS. The previously noted observation is now an asserted outcome.

### fingerprint-corpus: `bash tests/live/fingerprint-corpus/run.sh` -> RESULT: PASS

The runner starts the SQL Server 2022 compose file itself (no `--profile`);
all 17 services listened, mssql included.

| Mode | Expected | Correct | Wrong | Missed | Recall | Precision | High-conf wrong |
|---|---|---|---|---|---|---|---|
| full | 17 | 17 | 0 | 0 | 1.000 | 1.000 | 0 |
| deep | 17 | 17 | 0 | 0 | 1.000 | 1.000 | 0 |

Deep TLS stack: 10/10 correct. mssql identified at high confidence. Confidence
distribution: high=2 medium=12 low=3. This closes the section 3 gap (mssql
skipped) on podman-compose 1.0.6.
