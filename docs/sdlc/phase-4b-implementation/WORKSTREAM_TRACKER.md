# Kryptkeeper — Phase 4b Workstream Tracker

**Date:** 2026-04-08
**Owner:** SDLC orchestration

---

## 1. Workstream Board

| ID | Workstream | Scope | Complexity | Status |
|---|---|---|---|---|
| B-01 | Crypto Engine (CA Core) | Root/intermediate/external CA, cert builder, policy engine, signer manager | L | DONE |
| B-02 | Key Store Layer 1 (Software PKCS#8) | Argon2id KDF, AES-256-GCM envelope, crypto.Signer adapter, key persistence | M | DONE |
| B-03 | Certificate Issuance + Revocation | IssueFromCSR, RevokeCertificate, RenewCertificate, audit trail | L | DONE |
| B-04 | OCSP Responder | RFC 5019 GET/POST, response signing, LRU cache, nonce | M | DONE |
| B-05 | CRL Generator + Distribution | Full/delta CRL, scheduled/on-demand, public endpoint | M | DONE |
| B-06 | ACME Server (RFC 8555) | Directory, accounts, orders, challenges (HTTP-01/DNS-01/TLS-ALPN-01) | L | DONE |
| B-07 | EST Server (RFC 7030) | cacerts, simpleenroll, simplereenroll, csrattrs | M | DONE |
| B-08 | SCEP Server | PKCSReq, CertRep, GetCACert, GetCACaps, RA mode | M | DONE |
| B-09 | Network Discovery Scanner | masscan + Go TLS handshake, scan job lifecycle, risk scoring | L | DONE |
| B-10 | Alert Delivery Engine | SMTP, Slack, PagerDuty channels, retry, threshold evaluation | M | DONE |
| B-11 | Dashboard UI | React + Vite + TailwindCSS: 5 views, TanStack Query, API client | L | DONE |
| B-12 | Docker Compose Full Deploy | Postgres + API + dashboard nginx, health chain, volumes | M | DONE |
| B-13 | OpenAPI Spec | OpenAPI 3.1 covering all V1 endpoints | S | DONE |

---

## 2. Build Order

| Wave | Workstreams | Blocks |
|---|---|---|
| Wave 1 | B-02, B-01 | Everything |
| Wave 2 | B-03 | All protocols, scanner, alerts, dashboard |
| Wave 3 | B-04, B-05, B-06, B-07, B-08 (parallel) | B-12 |
| Wave 4 | B-09, B-10, B-11 (parallel) | B-12 |
| Wave 5 | B-12, B-13 | Gate check |

---

## 3. Progress Summary

- Completed: B-02 Key Store Layer 1 — `internal/keystore/` with `Store` interface, `SoftwareStore` adapter, Argon2id KDF (time=1, mem=64MB, threads=4), AES-256-GCM encrypted PKCS#8 PEM persistence, `crypto.Signer` adapter for RSA-2048/4096, ECDSA P-256/P-384, Ed25519. 14 unit tests.
- Completed: B-01 CA Core — `internal/ca/` with `Service` interface, `Engine` implementation. Root CA creation (self-signed), intermediate CA creation (parent-signed, validity clamped), external CA import (PEM parse, IsCA validation), certificate issuance from CSR (128-bit random serial, OCSP/CRL/SAN extensions, template enforcement), chain retrieval with circular reference detection. 10 unit tests.
- In progress: Security review on B-01/B-02 crypto code (running)
- Wave 1 complete. Wave 2 (B-03 issuance + revocation) is next.
- Completed: B-03 CA-backed CertificateProvider — `certificate_ca_provider.go` bridges Phase 4a `CertificateProvider` interface to Phase 4b `ca.Engine`. Real X.509 issuance from CSR, revocation with reason codes/conflict detection, renewal with predecessor/successor chain tracking, import with duplicate detection, PEM/DER download, risk scoring (expiry, PQC, weak algo), grade computation. 7 integration tests.
- Completed: crypto security audit hardening — computeSKI error propagation, Argon2id t=2, O_EXCL atomic writes, encoding/hex, negative validity rejection, IP SAN propagation.
- Wave 2 complete. Waves 3+4 (protocol servers + platform) now unblocked.
- Completed: B-04 OCSP Responder — `internal/ocsp/` with POST request handling per RFC 5019, response signing by CA cert, in-memory cache with invalidation, good/revoked status. 6 tests.
- Completed: B-05 CRL Generator — `internal/crl/` with full CRL generation per CA, monotonic CRL numbers, DER/PEM output, HTTP handler at `/crl/{ca-id}.crl`. 5 tests.
- Completed: B-06 ACME Server — `internal/acme/` with directory, nonce service, account creation, order state machine, authorization + challenge types (http-01/dns-01), finalize with CSR issuance, certificate download. 6 tests including full order flow integration test.
- Completed: B-07 EST Server — `internal/est/` with /cacerts, /simpleenroll, /simplereenroll, /csrattrs. Multi-format CSR parsing (PEM, base64, raw DER). 5 tests.
- Completed: B-08 SCEP Server — `internal/scep/` with GetCACert, GetCACaps, PKIOperation (GET+POST). Simplified CSR-based enrollment for MVP. 5 tests.
- Wave 3 complete: all 5 protocol servers done (OCSP, CRL, ACME, EST, SCEP).
- Completed: B-09 Network Scanner — Go TLS handshake cert extraction, CIDR expansion, goroutine pool, risk scoring. 6 tests.
- Completed: B-10 Alert Delivery — Channel interface, SMTP/Slack/PagerDuty, exponential retry, threshold evaluator. 6 tests.
- Completed: B-11 Dashboard UI — React 18 + Vite + TailwindCSS + TanStack Query. 5 pages (Dashboard, Certificates, CAs, Discovery, Alerts). API client. 276KB production build.
- Completed: B-12 Docker Compose — Postgres 16, API server, dashboard nginx proxy. Health checks, persistent volumes, security hardening.
- Completed: B-13 OpenAPI Spec — OpenAPI 3.1 at docs/openapi.yaml covering all V1 endpoints.
- **Phase 4b complete: 13/13 workstreams DONE.**
