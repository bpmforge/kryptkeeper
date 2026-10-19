# Day-one estate run — v0.12

Status: **PENDING-RUN**. The timed clean-VM run is a human/ops activity. Every measured field below is the literal `PENDING-RUN` until an operator replaces it. Section 6 was produced locally (no VM, no hub). Nothing here is an invented timing or count.

## 1. Header

| Field | Value |
|---|---|
| Version / commit | PENDING-RUN |
| Date | PENDING-RUN |
| Operator | PENDING-RUN |

## 2. Environment

| Field | Value |
|---|---|
| VM image | PENDING-RUN |
| CPU / RAM | PENDING-RUN |
| Hub install path | `docs/guides/getting-started.md` (single binary or compose: PENDING-RUN) |
| Network range scanned | PENDING-RUN |
| Seed: certs in PEM bundle (N) | PENDING-RUN |
| Seed: endpoints in scan range (M) | PENDING-RUN |
| Seed: ADCS export certs (K) | PENDING-RUN |
| EXPECT_TOTAL / MANAGED / EXTERNAL / UNMANAGED | PENDING-RUN |

Run command: `BASE_URL=... TOKEN=... PEM_BUNDLE=... SCAN_TARGET=... ADCS_EXPORT_PATH=... EXPECT_TOTAL=... EXPECT_MANAGED=... EXPECT_EXTERNAL=... EXPECT_UNMANAGED=... bash scripts/day-one-estate.sh`

## 3. Timeline

CT (`KRYPTKEEPER_CT_DOMAINS`) and ADCS (no lab DC) may be skipped per the board decision; write them as `SKIPPED: <named reason>`.

| Stage | Start | End | Duration | Result |
|---|---|---|---|---|
| install + first login (hub) | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| import | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| scan | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| sync (ADCS) | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| CT monitoring | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| report | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| verify | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |

## 4. Wall-clock total

Total: PENDING-RUN

TOTAL < 8h: PENDING-RUN

## 5. Counts

| Field | Seeded | /reports/estate | Dashboard |
|---|---|---|---|
| total | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| managed | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| external | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| unmanaged | PENDING-RUN | PENDING-RUN | PENDING-RUN |

All three columns must match.

## 6. Failure-injection check (LOCAL run, no VM, no hub; commit b3934ff8 base)

Command: `KK_DAYONE_INJECT_FAIL=<stage> BASE_URL=http://localhost:8080 TOKEN=x bash scripts/day-one-estate.sh`

| Stage | Observed exit | Observed line |
|---|---|---|
| hub | 10 | `FAILED stage=hub exit=10` |
| import | 20 | `FAILED stage=import exit=20` |
| scan | 30 | `FAILED stage=scan exit=30` |
| sync | 40 | `FAILED stage=sync exit=40` |
| report | 50 | `FAILED stage=report exit=50` |
| verify | 60 | `FAILED stage=verify exit=60` |

A live-hub dry run (one-cert PEM bundle, local hub, not a clean VM) also passed the `verify` stage with `EXPECT_TOTAL=1 EXPECT_UNMANAGED=1`, and a wrong `EXPECT_TOTAL=99` exited 60. This is script validation only, not the clean-VM result.

## 7. Artifacts

Reference by sha256 only (attachments under `docs/release/day-one-v0.12/` are out of scope).

| File | sha256 |
|---|---|
| kryptkeeper-estate-<date>.pdf | PENDING-RUN |
| kryptkeeper-estate-<date>.json | PENDING-RUN |
| kryptkeeper-estate-<date>.csv | PENDING-RUN |
