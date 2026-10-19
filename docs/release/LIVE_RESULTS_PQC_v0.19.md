# Live results: PQC agility (v0.19)

Evidence record for UC-G01, UC-G02 and UC-G03. Only executions that actually ran are recorded; everything else is marked PENDING-RUN or BLOCKED with its reason.

## Environment

| Field | Value |
|---|---|
| Record written | 2026-10-17 (UTC), W31-12 |
| Build under test | `v0.15.0-29-g444ce215` (commit `444ce215`, branch `kk/w31-c`). Not a tagged v0.19.x; the binary does not report v0.19. |
| Commit each run reported | W31-04 run: `9eb9725a` (`v0.15.0-21-g9eb9725a`); W31-11 run: `89f7f120` (`v0.15.0-28-g89f7f120`) |
| OpenSSL (host verifier) | 3.6.5 (29 Sep 2026) |
| OpenSSL (wave endpoint image) | 3.5.9, alpine:3.22 with nginx + sshd |
| Podman | 6.1.3 |
| Host | Darwin 27.0.0 arm64, go1.27.1 |
| Run by | automated agent session on the build host (no human operator) |

Raw logs: `tests/live/pqc/RESULTS.md` (W31-04) and `tests/live/pqc-wave/RESULTS.md` (W31-11), both written by the real harness runs on 2026-10-17T00:02:41Z and 2026-10-17T00:14:07Z.

## Summary table

| Check | Result | Date | Version |
|---|---|---|---|
| 1. Mixed-estate posture, live API vs UI counts (UC-G01) | PENDING-RUN | n/a | n/a |
| 1a. Posture corpus tests (in-process, not a live hub) | PASS (6 tests) | 2026-10-17 | `v0.15.0-29-g444ce215` |
| 2. OpenSSL 3.5+ interop (UC-G02) | PASS | 2026-10-17 | `v0.15.0-21-g9eb9725a` |
| 3a. PQC wave: run steps (UC-G03) | PASS | 2026-10-17 | `v0.15.0-28-g89f7f120` |
| 3b. PQC wave: served serial changes to ML-DSA cert (ep-a, ep-b) | BLOCKED | n/a | n/a |
| 3c. PQC wave: injected verify failure rolled back (ep-fail) | BLOCKED | n/a | n/a |

## 1. Mixed-estate posture (UC-G01)

**Result: PENDING-RUN.** The side-by-side API vs rendered-UI comparison (`GET /api/v1/reports/pqc-migration`, `GET /api/v1/reports/crypto-posture`, and the counts shown on `ui/src/pages/PQCMigration.tsx`) was not performed. It needs a live hub with a mixed inventory and a human reading the rendered page; no UI count was read in this session, so no API-vs-UI pair is claimed.

| Readiness class | API count | UI count | Equal |
|---|---|---|---|
| `vulnerable` | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| `hybrid_quantum_safe` | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| `quantum_safe_leaf_only` | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| `quantum_safe` | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| `migration_ready` | PENDING-RUN | PENDING-RUN | PENDING-RUN |

### 1a. Substitute evidence that did run (not a live-UI result)

`go test ./internal/bootstrap -run TestPQCCorpus -count=1 -v` on `444ce215`, 2026-10-17: PASS, 6 of 6.

- `TestPQCCorpus_ExpectedBucketsZeroMismatch` PASS
- `TestPQCCorpus_ThreeReportsAgree` PASS (the three report endpoints agree on the corpus)
- `TestPQCCorpus_MCPToolPathsMatchEndpoints` PASS
- `TestPQCCorpus_CAIssuedMLDSAIsNotPQCVulnerable` PASS
- `TestPQCCorpus_EmptyInventory` PASS
- `TestPQCCorpus_100kReportsUnder3s` PASS (`computeCryptoPostureReport` over 100000 synthetic certs: 6.27ms; synthetic corpus, not a live estate)

This shows server-side report agreement on a synthetic corpus. It does not show that the UI renders matching counts.

## 2. OpenSSL 3.5 interop (UC-G02)

**Result: PASS.** Harness `tests/live/pqc/run.sh` (W31-04), 2026-10-17T00:02:41Z, commit `9eb9725a`, OpenSSL 3.6.5, podman 6.1.3, postgres. Verbatim end of run: `ALL STEPS PASSED`. Step lines (all PASS, none SKIPPED, none FAIL):

- 0: OpenSSL version gate (3.6.5 >= 3.5)
- 1-3: hub built and up; ML-DSA-65 intermediate M and ECDSA-P256 intermediate C created under bootstrap ECDSA root R; M parses as ML-DSA-65; templates created
- 4: ML-DSA-44, ML-DSA-65 and ML-DSA-87 leaves issued under both classical C and ML-DSA M; `openssl verify` OK on all six chains, including the ML-DSA signature hop under M
- 5: Hybrid-ECDSA-P256-ML-DSA-65 and Hybrid-ECDSA-P384-ML-DSA-87 leaves issued under C; `openssl verify` OK on the classical path; each parses and carries subjectAltPublicKeyInfo (2.5.29.72)
- 6: ML-DSA-65 CSR against the ECDSA-only template refused with HTTP 422
- 7: bad proof-of-possession ML-DSA-65 and hybrid CSRs rejected with 400
- 8: `openssl ocsp` against the ML-DSA CA M returns good, then revoked after revocation (response verified); M's CRL lists the revoked serial and `openssl` verifies the ML-DSA CRL signature

Hybrid leaves are the project's own encoding (D-104). Only the classical chain path and parse were verified. No LAMPS composite interop is claimed.

## 3. PQC wave run (UC-G03)

**Result of the steps that could run: PASS.** Harness `tests/live/pqc-wave/run.sh` (W31-11), 2026-10-17T00:14:07Z, commit `89f7f120`, endpoint image OpenSSL 3.5.9. Verbatim end of run: `ALL RUN STEPS PASSED (3 legs PENDING, nothing claimed for them)`.

Served serials (from `openssl s_client` before and after the wave; serials only):

| Endpoint | Serial before | Serial after | Outcome |
|---|---|---|---|
| ep-a | 324C10ADB69C8EE9DC58B31E9B409117 | 324C10ADB69C8EE9DC58B31E9B409117 | unchanged, old cert still served |
| ep-b | B5B62878B323F0CBEC4522DF6BDB07AA | B5B62878B323F0CBEC4522DF6BDB07AA | unchanged, old cert still served |
| ep-fail | E7FC5A62AF957F83B0DD8072A5141857 | E7FC5A62AF957F83B0DD8072A5141857 | unchanged, old cert still served |

Step lines that passed:

- hub-issued ECDSA leaf installed over SSH on all three endpoints and observed as served
- wave created with 3 bound members and 1 unbound member, accepted
- two-principal execute: alice proposes (201), alice cannot approve her own proposal (403), bob approves and the wave runs (200)
- execute result: `migrated 1, failed 0, skipped 0, unsupported 3, regressed False`
- each bound member reports `delivery_unsupported` with a reason citing D-103 (PQC key material cannot be installed yet; manual install); each has an ML-DSA-65 successor in the hub inventory; the unbound member reports `migrated`
- wave status `in_progress`, not reported done; audit has `pqc.wave_execute_propose`, `pqc.wave_execute_approve` and 4 `pqc.wave_member_result` rows

What this shows: the wave issues ML-DSA-65 successors, enforces proposer != approver, audits every member, and leaves endpoints serving their old certificates with no outage. It does not show a successful in-place PQC rotation: delivery of PQC certificates is unsupported by design today (D-103), so the served certificate never changed.

## Not run / skipped / failed

| Item | Status | Reason |
|---|---|---|
| Section 1 live API vs UI posture counts | PENDING-RUN | Needs a live hub with a mixed estate and a human reading the rendered `PQCMigration.tsx` page; not performed. Only the in-process corpus tests (1a) ran. |
| Wave: ep-a and ep-b served serial changes to the ML-DSA cert | BLOCKED | ML-DSA private-key export follow-up not implemented; production deliverer is `unsupportedWaveDeliverer` (D-103). |
| Wave: ep-fail injected verify failure rolled back, old serial still served | BLOCKED | Same blocker: no Deliver is ever attempted, so there is nothing to roll back. |
| Wave progress reporting | KNOWN GAP | Wave status stays `in_progress` while members are `delivery_unsupported`; progress gap tracked as W31-21, fix in flight and not part of this evidence. |
| Harness runs at the exact build under test | NOTE | W31-04 and W31-11 ran at `9eb9725a` and `89f7f120`, not `444ce215`; the recorded versions above are the ones each harness reported. No SKIPPED or FAIL occurred in either run. |

## Claims explicitly NOT made

- LAMPS composite interop: hybrid leaves are verified on the classical ECDSA path and parse only.
- HSM-backed PQC: all runs used software keys.
- Relying-party compatibility (browsers, TLS stacks, clients other than OpenSSL 3.5+).
- 1,000-cert scale: no live run at that size; the only scale figure is the synthetic 100k in-process corpus timing in 1a.
- Successful in-place PQC certificate rotation on a served endpoint.
- UI/API count agreement on a live mixed estate.
