# Live validation W24-27: ADCS LDAP inventory sync vs Windows DC - v0.12

Date: 2026-10-18. Hub commit: c9e0e766. Harness: `tests/live/ad-ldap/windows/run.sh`.
DC OS: Windows Server 2025 Standard. Search base: DC=kkuat,DC=lab. Page size: 1000.

## Verdict: PASS

| Field | Value |
|---|---|
| K (expected distinct certs) | 10 |
| DC-side count (PowerShell) | 10 |
| Sync 1 synced / failed / duration | 10 / 0 / 96 ms |
| Sync 2 synced / skipped / duration | 0 / 10 / 87 ms |
| Inventory meta.total after sync 1 / 2 | 10 / 10 |

## Steps

| Step | Result | Evidence |
|---|---|---|
| hub up | PASS | commit c9e0e766 (main, v0.21.0 + #161) |
| source registered | PASS | page_size=1000 |
| sync 1 synced == K | PASS | synced=10 failed=0 96ms |
| inventory total == K after sync 1 | PASS | meta.total=10 |
| sync 2 adds 0 duplicates | PASS | synced=0 skipped=10 87ms |
| inventory total unchanged after sync 2 | PASS | meta.total=10 |
| DC-side count (PowerShell) == K | PASS | dc_count=10 |
| wrong password rejected, secret not leaked | PASS | http=503 |
| first source unaffected | PASS | skipped=10 |

Samba is unsupported for adcs_live (see tests/live/ad-ldap/README.md).

## Lab notes (2026-10-18)

- Lab: corp.example.test. DC LAB-DC01 (Windows Server 2025); Enterprise Root CA "CORP Lab Enterprise CA" on a new member server LAB-CA01 (Windows Server 2025), built for the W33-19 rehearsal. The DC's LDAPS certificate was auto-enrolled from that CA.
- K: 10 RSA-2048 certificates issued by the CA (WebServer template) and published to the `userCertificate` attribute of 10 test users in `OU=KKW33Rehearsal`. Bind account: a Domain Users-only account in the same OU.
- The hub ran in a Linux container (golang:1.26) with the lab root added to the container's trust store; the build host's own trust store was not changed.
