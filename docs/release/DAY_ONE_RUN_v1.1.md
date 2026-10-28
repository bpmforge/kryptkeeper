# Day-one estate run — v1.1

The timed run that [`DAY_ONE_RUN_v0.12.md`](DAY_ONE_RUN_v0.12.md) left as
PENDING-RUN: a clean VM to a risk-scored estate report in which the estate
report, the dashboard and the seeded counts agree.

## Verdict: PASS, after fixing five defects the run found

On the first run, following the docs as written failed four times before the
estate verified. Each defect is fixed in the same change as this record, and a
second run from an empty hub passed with no workarounds:

1. `docs/guides/getting-started.md` step 1 exported a token that Compose does
   not read, so `docker compose up` stopped on the missing
   `KRYPTKEEPER_KEYSTORE_PASSPHRASE`. Its API examples used old field names and
   plain HTTP as well.
2. `Dockerfile` and `Dockerfile.fips` set `ARG TARGETARCH=arm64`. A source build
   on x86_64 produced an ARM binary, and the hub crash-looped with
   `exec /kryptkeeper: exec format error`. That covers the README Quick Start on
   any x86_64 Linux host. The agent, cert-manager and MCP Dockerfiles defaulted
   to amd64, the same bug for arm64 hosts. Released images were not affected,
   because goreleaser passes `TARGETARCH` explicitly.
3. `scripts/day-one-estate.sh` started its scan with `scan_type: network`,
   which the API no longer accepts (HTTP 400).
4. The script piped the PQC report into `head -c 400` under `pipefail`. Any
   report longer than the preview failed the report stage.
5. The script's verify stage ran as soon as the scan was submitted. A scan
   job also reports `completed` a few seconds before its certificates appear
   in the estate. The fixed script waits for both (`SCAN_WAIT_SECONDS`).

The guide also documented `GET /api/v1/discovery/scans`, which returns 405; the
status endpoint is `GET /api/v1/discovery/scan-jobs`.

## 1. Header

| Field | Value |
|---|---|
| Date | 2026-10-28 (17:36Z to 18:02Z) |
| Run 1 source | public `main` at 9aad236 (product code identical to v1.1.1; later commits are docs, CI and site tooling), as documented |
| Run 2 source | the same tree plus the fixed `Dockerfile` and `scripts/day-one-estate.sh` from this change |
| Hub version string | `dev` (Compose builds from source and does not stamp a version) |
| Operator | automated agent run (Claude), authorized by the owner on 2026-10-28 |

## 2. Environment

| Field | Value |
|---|---|
| VM | new KVM guest from the Ubuntu 24.04.5 LTS cloud image, 4 vCPU, 4 GiB RAM, 30 GB disk, created for this run |
| Container runtime | Ubuntu's `docker.io` 29.1.3 and `docker-compose-v2` 2.40.3, plus `docker-buildx` 0.30.1 |
| Hub install path | Docker Compose, SQLite, TLS on (Compose defaults) |
| Seed: certs in PEM bundle (N) | 12, from three private CAs plus two self-signed (one expired, two RSA-1024, one expiring in 10 days) |
| Seed: endpoints in scan range (M) | 5 nginx TLS endpoints on an isolated Docker network (172.31.250.0/28) on the same VM |
| Seed: AD CS export certs (K) | 11, exported with `certutil -view` from the lab's AD CS enterprise CA on Windows Server 2025 (1 domain controller certificate, 10 user certificates), synced as an `adcs_export` source |
| CT monitoring | SKIPPED: CT results depend on what public logs hold on the day, so the counts could not be seeded. CT is proven separately in [`LIVE_RESULTS_CT_v1.1.md`](LIVE_RESULTS_CT_v1.1.md) |
| EXPECT_TOTAL / MANAGED / EXTERNAL / UNMANAGED | 29 / 1 / 11 / 17 (12 + 5 + 11 seeded, plus the hub's own TLS certificate, which is internal and managed) |

## 3. Timeline

### Run 1: the docs as written

| Stage | Start | End | Duration | Result |
|---|---|---|---|---|
| VM created and booted, cloud-init done | 17:36:09 | 17:38:32 | 2m 23s | PASS |
| Docker prerequisites installed | 17:38:32 | 17:39:08 | 36s | PASS |
| getting-started.md step 1 (`docker compose up`) | 17:39:14 | 17:39:22 | 8s | FAIL: defect 1 |
| README Quick Start (`.env`, `docker compose up`), first build | 17:39:42 | 17:42:04 | 2m 22s | FAIL: hub crash-loops, defect 2 |
| Diagnosis; installing `docker-buildx` and rebuilding did not help | 17:42 | 17:48:43 | about 6m | FAIL: still an ARM binary |
| Build with `--build-arg TARGETARCH=amd64`, start, first login | 17:49:11 | 17:51:30 | 2m 19s | PASS: `/healthz` ok, bootstrap token is `pki-admin`, dashboard 200 |
| Seed data prepared (bundle, endpoints, AD CS export) | 17:51:30 | 17:53:50 | about 2m 20s | PASS |
| Script, attempt 1 | 17:54:00 | 17:54:16 | 16s | FAIL at scan: defect 3 |
| Script, attempt 2 (scan type fixed locally) | 17:54:37 | 17:54:37 | under 1s | FAIL at report: defect 4 |
| Script, attempt 3 (report pipe fixed locally) | 17:55:32 | 17:55:33 | 1s | PASS: counts verified 29 / 1 / 11 / 17 |

Attempt 3 passed only because attempt 2's scan had finished in the meantime;
run 2 found that race (defect 5).

### Run 2: the fixed tree, from an empty hub

Hub volumes and images were deleted first (`docker compose down -v`).

| Stage | Start | End | Duration | Result |
|---|---|---|---|---|
| Build without a build argument (binary checked: ELF x86-64), start, first login | 17:59:07 | 17:59:40 | 33s (layers cached from run 1) | PASS |
| Script, first try | 17:59:40 | 18:00:01 | 21s | FAIL at verify, 24 of 29: defect 5. The five scanned certificates appeared 11 s later |
| Script wait added; volumes deleted again; build, start, login | 18:01:03 | 18:01:24 | 21s | PASS |
| Script: hub, import, scan (waited for the job and its 5 certificates), sync, report, verify | 18:01:24 | 18:01:49 | 25s | PASS: counts verified |

## 4. Wall-clock total

- Run 1, VM creation to verified estate following the docs as written:
  19m 24s (17:36:09 to 17:55:33), about 9 minutes of it spent hitting and
  working around the defects above.
- Run 2, empty hub to verified estate with the fixes: 46s (cached build).
  A cold first build took 2m 22s in run 1.

TOTAL < 8h: PASS.

## 5. Counts (run 2)

| Field | Seeded | /reports/estate | Dashboard |
|---|---|---|---|
| total | 29 | 29 | 29 |
| managed | 1 | 1 | 1 |
| external | 11 | 11 | 11 |
| unmanaged | 17 | 17 | 17 |

By origin: internal 1, imported 12, discovered 5, synced 11.
PQC split: 20 vulnerable, 4 migration-ready, 5 not applicable, 0 quantum-safe
(PQC score 13%). Risk: 3 critical, 20 high, 3 medium, 3 low.

## 6. What this run did not cover

- The scanned endpoints were containers on the hub VM, not separate servers.
  Discovery against real hosts is covered in
  [`LIVE_RESULTS_v1.0.0.md`](LIVE_RESULTS_v1.0.0.md).
- The AD CS certificates came in through an export file. The live LDAP
  connector against the same CA is covered in
  [`ADCS_CUTOVER_REHEARSAL_v0.21.md`](ADCS_CUTOVER_REHEARSAL_v0.21.md).
- The numbers were checked through the API (`/reports/estate` and
  `/dashboard/summary`); the dashboard pages were not walked through by hand.
- Day two (taking over an unmanaged certificate) was not part of this run.

## 7. Artifacts (run 2)

| File | sha256 |
|---|---|
| kryptkeeper-estate-2026-10-28.json | f21b56d8bcae22b169b2fbd034c6c47b664bacf8d66ecb62698069b27525ade7 |
| kryptkeeper-estate-2026-10-28.pdf | 94c0bfd031842c44f907bacfa53c4fea0aebba2c283a8e0d5579c4271e0fefba |
| kryptkeeper-estate-2026-10-28.csv | 9ebd6d5d72a99af18cc271503260f0bb58f1c1da0ef0435df74194f3a9c0beda |
