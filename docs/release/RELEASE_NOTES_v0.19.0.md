# Kryptkeeper v0.19.0

This release is post-quantum agility: honest PQC readiness labels, ML-DSA
signed CRL and OCSP, FIPS/allow-list/HSM refusals, PQC migration waves with
verify and rollback, non-PQC algorithm transitions through the same waves, a
blast-radius page, and an explicit software-only PQC key-custody statement. It is
feature group W31 of the v1.0 release train. 19 of 21 tickets are `done`; W31-11
and W31-12 are `in_progress`. Decisions: D-172 to D-181 and D-194.

## Upgrade notes (read first)

- **No migrations.** `migration_wave_members` gains a `delivery_status` column,
  added best effort at runtime like the existing status column (W31-21, D-194).
- **New environment variable:** `KRYPTKEEPER_PQC_WAVE_APPROVAL_TTL_HOURS`
  (default 24, separate from `APPROVAL_TTL_HOURS`). An expired wave approval is
  refused 409 and audited as denied; the proposer cannot approve (403) (D-176).
- **PQC issuance refusals answer 422** and audit `certificate.issue_refused` with
  `reason=allow_list|fips|hsm_pqc`. Hybrid is refused whenever FIPS is enabled;
  ML-DSA only when `fips140` is enforced (D-177).
- **PQC readiness labels can get worse, never better.** An unknown-OID key that is
  not ML-DSA is `not_applicable`; Ed25519 is classical; a certificate whose
  issuing chain cannot be resolved takes the weaker leaf-only label. A chain is
  `quantum_safe` only when no hop is vulnerable and it is not leaf-only (D-173).
  Expect counts on the PQC Migration page to shift after upgrade.
- **Wave progress counts delivery, not issuance.** A member whose delivery is
  `delivery_unsupported` or `failed` is reported `undelivered`, not migrated, and
  keeps the wave out of `done` (D-194).
- **Production PQC delivery is still manual.** Waves issue the ML-DSA successor
  but the production deliverer reports `delivery_unsupported` (D-103, D-175).
- `GET /reports/pqc-migration` now carries a per-quarter 2030 timeline (W31-20).
- Scale tests (1,000-cert wave, 100k blast radius) run nightly only (D-180).

## New

- **Readiness:** a seeded 500-certificate corpus test and a 100k report timing
  benchmark (W31-01); label fixtures for leaf-only, full-chain, multi-tier and
  unknown-hop chains (W31-02); label explanations and a per-quarter 2030
  timeline on the PQC Migration page (W31-03, W31-20).
- **Interop:** OpenSSL 3.5+ live test for ML-DSA and hybrid leaves (W31-04).
  Hybrid certificates use Kryptkeeper's own alt-sig encoding; no LAMPS composite
  interop is claimed (D-172).
- **ML-DSA CAs sign their own CRLs and OCSP responses** using a new
  `internal/revsign` package; `CAListItem.revocation_signing` reports `ml-dsa`
  or `classical` (hybrid CAs sign classically) (W31-05, D-174).
- **Refusals:** FIPS-mode, allow-list and HSM refusals on PQC issuance with tests
  (W31-06); docs for hybrid encoding, CRL/OCSP behaviour and the LAMPS decision
  (W31-07).
- **Waves:** verify-and-rollback parity with delivery targets, members renewed by
  another path skipped with a reason (W31-08, D-175); approval expiry,
  proposer-not-approver and `pqc.wave_member_result` audit and alert events
  (W31-09, D-176); a 1,000-cert RSA to ML-DSA scale test with failure injection
  (W31-10); undelivered members excluded from progress (W31-21).
- **Crypto agility:** a 500-cert roadmap accuracy test and audit event (W31-13);
  non-PQC transitions (RSA-2048 to ECDSA-P384) through waves via
  `target_algorithm` and `BuildTransitionCSR` (W31-14, D-178); a Crypto Agility
  roadmap UI in Algorithm Sunset and PQC Migration (W31-15).
- **Blast radius:** impact shown on approval, pending-action and revoke screens
  (W31-16); a Blast Radius page with a simulate form and dependency graph
  (W31-17); `GET /api/v1/blast-radius` with disclosed `edge_coverage`, an unknown
  target 404 and another tenant's cert or CA 403, accuracy and p95 tests, and a
  read-only MCP `blast_radius` tool (W31-18, D-179).
- **Custody statement:** ML-DSA and hybrid keys are software-keystore only, stated
  on the Keys pages, the Cloud Keys page and `GET /reports/key-custody`
  (`pqc_custody_statement`), pinned by a drift test (W31-19, D-181).

## Decisions

D-172 to D-181 and D-194.

## Pending human runs

Record: `docs/release/LIVE_RESULTS_PQC_v0.19.md`, written 2026-10-17 against
build `v0.15.0-29-g444ce215`, not a tagged v0.19 binary.

- **W31-12 `in_progress`; live mixed-estate posture comparison is PENDING-RUN.**
  The API versus rendered-UI counts were not compared. Only the in-process corpus
  tests ran: 6 of 6 passed, including a synthetic 100k report in 6.27 ms. That is
  not a live-UI result.
- **OpenSSL 3.5 interop: PASS** (OpenSSL 3.6.5; six ML-DSA chains verified,
  hybrid classical path and parse only, ML-DSA OCSP and CRL verified).
- **W31-11 `in_progress`; wave served-serial change and rollback are BLOCKED.**
  The wave run steps passed, but all three endpoints kept their old serial because
  production delivery is unsupported (D-103), so no in-place PQC rotation and no
  rollback was exercised.

Claims not made: LAMPS composite interop, HSM-backed PQC, relying-party
compatibility beyond OpenSSL 3.5+, live 1,000-cert scale.

## Known gaps

- Hardware PQC (PKCS#11 v3.2) is deferred to v1.x. A GCP KMS harness is tracked
  under W19-12 and is not covered here.
