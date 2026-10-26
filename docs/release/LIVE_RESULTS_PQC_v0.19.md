# Live results: PQC agility (v0.19)

Evidence record for UC-G01, UC-G02 and UC-G03. Only executions that actually ran are recorded; everything else is marked PENDING-RUN or BLOCKED with its reason.

## Environment

| Field | Value |
|---|---|
| Record written | 2026-10-17 (UTC), W31-12 |
| Build under test | `v0.15.0-29-g444ce215` (commit `444ce215`, branch `kk/w31-c`). Not a tagged v0.19.x; the binary does not report v0.19. |
| Commit each run reported | W31-04 run: `9eb9725a` (`v0.15.0-21-g9eb9725a`); W31-11 run: `89f7f120` (`v0.15.0-28-g89f7f120`); W31F-06 wave re-run (section 3): `5d041b04` + W31F-06 tree, 2026-10-19 |
| OpenSSL (host verifier) | 3.6.5 (29 Sep 2026) |
| OpenSSL (wave endpoint image) | 3.5.9, alpine:3.22 with nginx + sshd |
| Podman | 6.1.3 |
| Host | Darwin 27.0.0 arm64, go1.27.1 |
| Run by | automated agent session on the build host (no human operator) |

Raw logs: `tests/live/pqc/RESULTS.md` (W31-04) and `tests/live/pqc-wave/RESULTS.md` (W31-11), written by the real harness runs on 2026-10-17T00:02:41Z (W31-04) and 2026-10-19T16:45:13Z (W31-11 harness, W31F-06 re-run).

## Summary table

| Check | Result | Date | Version |
|---|---|---|---|
| 1. Mixed-estate posture, live API vs UI counts (UC-G01) | PASS on counts (every API/UI pair equal); 1 UI render defect found, see section 1 | 2026-10-19 | `v1.0.0-2-g78b475d7` |
| 1a. Posture corpus tests (in-process, not a live hub) | PASS (6 tests) | 2026-10-17 | `v0.15.0-29-g444ce215` |
| 2. OpenSSL 3.5+ interop (UC-G02) | PASS | 2026-10-17 | `v0.15.0-21-g9eb9725a` |
| 3a. PQC wave: run steps (UC-G03) | PASS | 2026-10-19 | `5d041b04` + W31F-06 working tree (committed as `feat(pqc): W31F-06`) |
| 3b. PQC wave: served serial changes to ML-DSA cert (ep-a, ep-b) | PASS | 2026-10-19 | same |
| 3c. PQC wave: injected verify failure rolled back (ep-fail) | PASS | 2026-10-19 | same |

## 1. Mixed-estate posture (UC-G01)

**Result: counts PASS, with one UI render defect (FINDING W31F-07-A).** Run 2026-10-19 (UTC) by W31F-07 on commit `78b475d7` (branch `kk/w31f-b`, built from the worktree; not a tagged v0.19.x). A local hub (sqlite data dir, `APP_CERTIFICATE_PROVIDER=ca`, `APP_NOTIFICATION_PROVIDER=delivery`, `APP_DISCOVERY_PROVIDER=db`, `SPIFFE_TRUST_DOMAIN=example.org`, TLS off, port 18471) was filled through the API, then `GET /api/v1/reports/{crypto-posture,pqc-countdown,pqc-migration}` were fetched with one admin token. The production UI bundle (`npm --prefix ui run build`, served by `scripts/dev/serve-real.mjs`, never the MSW dev server) was driven in headless Chromium (Playwright), signed in through `/login`, and the numbers below were read from the rendered DOM of `/reports/pqc-migration` and `/crypto-posture` (metric cards and `data-testid="pqc-quarter"` rows), not recomputed from the API.

Estate (20 certificates): ECDSA-P256, Ed25519 and RSA-3072 leaves, each issued with a 30-day template and a 365-day template, under a classical ECDSA-P256 intermediate; ML-DSA-44/65/87 leaves under that classical CA, under an ML-DSA-65 intermediate chained to the (classical ECDSA) bootstrap root, and under an ML-DSA-65 root plus ML-DSA-65 intermediate; two hybrid leaves (Hybrid-ECDSA-P256-ML-DSA-65, Hybrid-ECDSA-P384-ML-DSA-87) under the classical CA. Not seeded: RSA-2048 (refused by the built-in Baseline issuance policy, HTTP 422), any certificate expiring after 2030 (issuance policy caps template validity; a 2000d template was refused), and any `not_applicable` certificate.

| Item | API | UI | Match |
|---|---|---|---|
| Total certificates | 20 | 20 (Crypto Posture header cards) | yes |
| `vulnerable` | 3 | 3 (PQC Migration, Countdown, Crypto Posture) | yes |
| `migration_ready` (includes hybrid per `ReadinessTally`) | 3 | 3 (PQC Migration, Crypto Posture) | yes |
| `quantum_safe_leaf_only` | 8 | 8 (PQC Migration, Countdown, Crypto Posture) | yes |
| `quantum_safe` | 6 | 6 (PQC Migration, Countdown, Crypto Posture) | yes |
| `not_applicable` | 0 | 0 (Crypto Posture) | yes |
| PQC readiness % | 85 | 85% (all three panels) | yes |
| Quantum-safe % | 30 | 30% (Crypto Posture bucket row) | yes |
| Expire before 2030 | 6 | 6 | yes |
| Expire after 2030 | 0 | 0 | yes |
| Quarter 2026-Q4 due / migrated | 3 / 6 | 3 / 6 | yes |
| Quarter 2027-Q4 due / migrated | 3 / 0 | 3 / 0 | yes |
| 12 other quarters (2027-Q1..Q3, 2028-Q1..Q4, 2029-Q1..Q4, 2030-Q1) due / migrated | 0 / 0 each | 0 / 0 each (14 rows total) | yes |
| Algorithm breakdown ECDSA / Ed25519 / ML-DSA / RSA | 4 / 2 / 12 / 2 | 4 / 2 / 12 / 2 (both pages) | yes |
| Countdown status and nearest deadline | `on_track`, 2030-01-01 in 1169 days | On track, 1169d, 2030-01-01 | yes |
| Roadmap items | 6 | 6 table rows | yes |

Raw API JSON for this run is not committed (it holds certificate fingerprints of a throwaway hub). Screenshots (full page, 1440px): [PQC Migration](assets/pqc-v0.19/migration-full.png), [Crypto Posture](assets/pqc-v0.19/posture-full.png).

Bucket coverage: `vulnerable`, `migration_ready`, `quantum_safe_leaf_only` and `quantum_safe` are all non-zero. `not_applicable` is 0 (no such certificate could be created through the API). There is no separate `hybrid_quantum_safe` count in any report: `ReadinessTally` folds that value into `migration_ready`, and in this run the two hybrid leaves did not read as `migration_ready` or `hybrid_quantum_safe` at all.

Observations (not count mismatches; not fixed in this ticket):

- **FINDING W31F-07-A (UI render defect, FAIL on text).** `ui/src/pages/PQCMigration.tsx:870` builds the roadmap panel subtitle inside a template literal with the pluralisation written as plain text instead of `${...}`, so the page renders the literal string `6 certificate{roadmap.items.length === 1 ? "" : "s"} need{roadmap.items.length === 1 ? "s" : ""} action, highest priority first`. Introduced in commit `a8960d83`. The number is correct; the surrounding text is not. Fix: wrap the two ternaries in `${...}`.
- **Observation W31F-07-B.** The two hybrid leaves (public key reported as ECDSA, issued under the classical CA) were classified `quantum_safe_leaf_only` by the API, so the 8 leaf-only certificates are 3 ML-DSA under the classical CA, 3 ML-DSA under the ML-DSA intermediate chained to the classical root, and these 2 hybrids. The "Migration ready" explanation on the page says hybrid certificates are migration-ready. The API and UI agree with each other; whether the hybrid classification is intended (D-104/D-105) is for the lead to decide.
- Full-chain `quantum_safe` required an ML-DSA root; an ML-DSA intermediate under the ECDSA bootstrap root reads `quantum_safe_leaf_only`, consistent with D-104.

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

**Result: PASS (W31F-06 re-run, supersedes the 2026-10-17 delivery_unsupported run).** Harness `tests/live/pqc-wave/run.sh`, 2026-10-19T16:45:13Z, built from `5d041b04` plus the uncommitted W31F-06 tree that became the commit `feat(pqc): W31F-06 deliver PQC wave successors to endpoints` (the harness cannot record its own commit's SHA; see `git log` for it). Endpoint image OpenSSL 3.5.9 (alpine:3.22, nginx + sshd), run with `KK_KEEP_GOING=1`. Verbatim end of run: `ALL PASS`. The earlier 2026-10-17 run (`89f7f120`, production deliverer `unsupportedWaveDeliverer`) is retained in git history of `tests/live/pqc-wave/RESULTS.md`.

Served serials (from `openssl s_client` inside the endpoint containers, not from the hub; serials only):

| Endpoint | Serial before | Serial after | Outcome |
|---|---|---|---|
| ep-a | 26F45E1F97CA6E4EA42A1E3574826C16 | B3439CCA9376D974C0185E54EF4E5466 | changed to the ML-DSA-65 successor's serial |
| ep-b | 5BAE6A20CC2589B6EE90AB195111EC04 | EBA952737B17A73F588FB7A14AB29529 | changed to the ML-DSA-65 successor's serial |
| ep-fail | 9061E00764BF85DB2D7AEED6E6C73975 | 9061E00764BF85DB2D7AEED6E6C73975 | verify failed, rolled back; old serial still served, key file byte-identical |

Step lines that passed:

- hub-issued ECDSA leaf installed over SSH on all three endpoints and observed as served
- ep-fail's target `verify_host_port` set to `kkw31-11-ep-a:443` (so the post-install verify sees the wrong fingerprint)
- two-principal execute: alice proposes (201), alice cannot approve her own proposal (403), bob approves and the wave runs (200)
- execute result: `migrated 3, failed 1, skipped 0, unsupported 0, regressed True, wave_status regressed`
- ep-a, ep-b: `status=migrated delivery=verified`; served cert is ML-DSA-65 (`openssl x509 -text`) and its serial equals the successor's serial in the hub inventory
- ep-fail: `status=failed delivery=failed old_serial_served=true`, reason `delivery rolled_back: verify_failed: served fingerprint does not match renewed cert; rolled back`; still serves the ECDSA leaf; `sha256sum` of its server.key unchanged
- unbound member `migrated`, `delivery=none`
- wave status `regressed` (not done); audit has `pqc.wave_execute_propose`, `pqc.wave_execute_approve`, 4 `pqc.wave_member_result` and 3 `key.export_for_delivery` rows, and the audit trail contains no private-key PEM

Verification note: the hub's verify is its ordinary Go `crypto/tls` dial that compares the SHA-256 of the served leaf. It handshook with the OpenSSL 3.5 nginx serving an ML-DSA-65 leaf (probed separately: fingerprint equal to `openssl x509 -outform DER | sha256sum`), so no alternative verifier was needed. This is a fingerprint check with `InsecureSkipVerify`; it does not prove private-key possession by the server beyond what the TLS stack enforced.

What this shows: an ML-DSA-65 successor key is exported as PKCS#8, installed through the renewal install path, served by a real nginx, and a failed verify restores the previous certificate and key. Scope: ssh targets with nginx or apache profiles only; other install modes report `delivery_unsupported`.

## Not run / skipped / failed

| Item | Status | Reason |
|---|---|---|
| Section 1 UI render defect W31F-07-A | FIXED | Subtitle at `ui/src/pages/PQCMigration.tsx:870` rendered unevaluated JS (counts unaffected); fixed on feat/w31-followups (missing `${}`), with the hybrid label copy corrected to match D-104. |
| Section 1 untested cases | NOT RUN | No RSA-2048 (Baseline policy refuses), no cert expiring after 2030 (validity capped), no `not_applicable` cert, no separate hybrid bucket, so those paths are unverified live. |
| Harness runs at the exact build under test | NOTE | W31-04 ran at `9eb9725a` and the wave re-run at `5d041b04` + W31F-06 tree, not `444ce215`; the recorded versions above are the ones each harness reported. No SKIPPED or FAIL occurred in either run. |

## Claims explicitly NOT made

- LAMPS composite interop: hybrid leaves are verified on the classical ECDSA path and parse only.
- HSM-backed PQC: all runs used software keys.
- Relying-party compatibility (browsers, TLS stacks, clients other than OpenSSL 3.5+).
- 1,000-cert scale: no live run at that size; the only scale figure is the synthetic 100k in-process corpus timing in 1a.
- UI/API agreement for post-2030 expiry, `not_applicable` and RSA-2048 certificates (not seeded, see section 1).
