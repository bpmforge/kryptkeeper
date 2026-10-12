# Kryptkeeper V4 — Risk Register
**Date:** 2026-04-24
**Owner:** Engineering Lead

Format: ID · Description · Likelihood (1–5) · Impact (1–5) · Score · Mitigation

---

## Technical Risks

| ID | Risk | L | I | Score | Mitigation |
|---|---|---|---|---|---|
| T-01 | **Cloudflare CIRCL ML-DSA API changes** — CIRCL is pre-1.0; minor version bumps can break calling code | 3 | 3 | 9 | Pin to exact version in go.mod; write thin adapter layer; monitor CIRCL releases weekly |
| T-02 | **Go x509 rejects ML-DSA signer** — stdlib's `x509.CreateCertificate` may not accept non-standard public key types | 3 | 5 | 15 | Prototype in spike branch before committing to approach; may need custom DER encoding for ML-DSA SubjectPublicKeyInfo |
| T-03 | **Composite cert OID compatibility** — draft-lamps-pq-composite-sigs OIDs may change before RFC finalization | 4 | 3 | 12 | Use experimental OID space; document as "pre-RFC, subject to change"; add migration path in planner |
| T-04 | **PKCS#11 library fragmentation** — different HSMs expose PKCS#11 differently; SoftHSM2 is not representative of real HSMs | 3 | 3 | 9 | Test against SoftHSM2 + document manual validation steps for Thales/Utimaco; abstract behind interface |
| T-05 | **Intune BYOCA SCEP format underdocumented** — Microsoft's exact SCEP challenge format for BYOCA is not fully public | 4 | 4 | 16 | Use Microsoft Learn docs as spec; file GitHub issues if behavior deviates; test against Intune tenant if available |
| T-06 | **Certificate size inflation with ML-DSA** — ML-DSA-65 chain is ~10KB vs 1.5KB ECDSA; OCSP responses also larger | 3 | 2 | 6 | Document size implications; consider OCSP response caching increase (already implemented); add size warnings in UI |
| T-07 | **Test coverage regression** — Sprint 3 adds ~6 new packages; coverage could drop below 80% | 2 | 2 | 4 | Write tests alongside each feature; gate on `go test ./...` before merge |

## Product / Market Risks

| ID | Risk | L | I | Score | Mitigation |
|---|---|---|---|---|---|
| P-01 | **Keyfactor ships ML-DSA OSS before us** — EJBCA Community could add PQC | 2 | 4 | 8 | EJBCA's enterprise-gated track record makes this unlikely; even if they do, Kryptkeeper's simpler UX + Go single binary wins |
| P-02 | **TLS 47-day deadline shifts** — CA/B Forum could delay the 2029 mandate | 2 | 3 | 6 | Automation is still valuable regardless; shorter certs are coming even if timeline slips |
| P-03 | **Microsoft changes BYOCA spec** — Intune Cloud PKI BYOCA API could change without notice | 3 | 3 | 9 | Track Microsoft Learn changelog; build abstraction layer; treat BYOCA as a versioned integration |
| P-04 | **PQC algorithm found vulnerable** — ML-DSA weakness discovered (rare but possible) | 1 | 5 | 5 | Hybrid cert strategy mitigates: classical ECDSA path still valid; crypto-agile design means algo swap without CA rewrite |
| P-05 | **OSS adoption slower than expected** — launch gets no traction | 3 | 3 | 9 | Plan launch for HackerNews + security Reddit; write "Replace ADCS" guide targeting high-SEO query |

## Operational Risks

| ID | Risk | L | I | Score | Mitigation |
|---|---|---|---|---|---|
| O-01 | **Single developer bandwidth** — Sprint 3 is ~31 days single-threaded; any blocker extends timeline | 4 | 3 | 12 | Strict priority ordering (S3-1 blocks nothing; S3-6 unblocks ADCS story); cut S3-5 if needed for launch |
| O-02 | **No real Intune tenant for testing** — BYOCA integration may not be testable without Microsoft licensing | 3 | 3 | 9 | Use Microsoft's developer sandbox / 90-day trial; test against published spec; mark as "spec-validated, not tenant-tested" |
| O-03 | **Doc site not ready at launch** — Poor documentation kills OSS adoption | 3 | 4 | 12 | Start docs in parallel with Sprint 3 code; minimum viable docs = Getting Started + 3 how-to guides |
| O-04 | **CI pipeline breaks on new deps** — Cloudflare CIRCL has CGO? | 2 | 3 | 6 | Check CIRCL's build requirements early; if CGO, update Dockerfile; test on clean CI environment |

## Risk Priority Order (by score, descending)

1. T-05 (Intune BYOCA underdocumented) — 16
2. T-02 (Go x509 ML-DSA acceptance) — 15
3. O-01 (single developer bandwidth) — 12
4. T-03 (composite OID changes) — 12
5. O-03 (doc site not ready) — 12
6. T-01 (CIRCL API changes) — 9
7. T-04 (PKCS#11 fragmentation) — 9
8. P-03 (Microsoft BYOCA spec changes) — 9
9. P-05 (OSS adoption) — 9

**Mitigate T-02 first** — if Go's x509 won't accept ML-DSA signers natively, we need to know in week 1, not week 3. Spike this before committing to the full ML-DSA workstream.
