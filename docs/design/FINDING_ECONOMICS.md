# Finding Economics — the funnel and the accepted-risk exception primitive

**Date:** 2026-07-16. **Status:** design + phase-1 implementation (the exceptions table/store).
Ticket: **W2-06** (D-031/R-D1, FR-R10 phase 1). Read alongside `docs/DECISIONS.md` D-031 and
`docs/work/IMPROVEMENT_RECOMMENDATIONS.md` R-D1/R-D2/R-D3.

## The one-line version

**Today every "finding" in Kryptkeeper is raw, ephemeral, and unsuppressable.** There is no
dedup, no scoping, no applicability check, and no way for an operator to say "yes, I know about
this, I accept the risk, stop counting it against my totals until X happens." This doc names the
funnel a finding should pass through and specifies the accepted-risk exception primitive that
lets a human close that last gap — honestly, with an expiry, never silently.

## What a "finding" is today (the layer this funnel sits on top of)

Two independent code paths compute finding-shaped data, both **recomputed fresh on every read,
with no identity, no persistence, no lifecycle**:

- `computeRiskFlags` (`internal/bootstrap/certificate_ca_provider.go:916`) returns a flat
  `[]string` of flag codes per certificate on every list/get call — `EXPIRED`, `WEAK_SIGNATURE`,
  `WEAK_RSA_KEY`, `WEAK_EC_KEY`, `PQC_VULNERABLE`, `PQC_MIGRATION_NEEDED`, `SAN_SPRAWL`,
  `NO_OCSP_URL`. These are string literals, not a typed enum — there is no fixed registry of
  finding codes anywhere in the code.
- `EndpointTLSConfig.Issues` (`internal/cipheraudit/auditor.go`) is the same shape for discovered
  TLS/cipher findings.

Neither path has any concept of "I've seen this exact finding on this exact target before."
Every page load recomputes the full flag list from scratch. This is the **raw** layer.

**W2-06 does not touch either of these paths.** Wiring the funnel below into `computeRiskFlags`,
`cipheraudit`, or any report/endpoint is explicitly **out of this ticket's scope** — the
roadmap's own exit criteria split this into two phases: W2's exit criterion is "design landed
with the accepted-risk primitive" (**FR-R10 phase 1**, this ticket); W3's is "finding funnel
effective-counts surfaced end-to-end" (**FR-R10 phase 2**, ticket **W3-02**, UI-only, which reads
whatever backend wiring phase 2 turns out to need). This ticket delivers the design and the
exception table/store phase 2 will consume — nothing downstream is wired yet.

## The funnel

A finding's life should pass through five stamped stages. None of them silently drop a finding —
every stage that removes a finding from a count records *why*, and the raw count is never hidden
behind the effective one.

```
raw → dedup → scope → applicability → effective → suppressed(justified)
```

1. **raw** — every finding a detector produces, every time it runs. This is what
   `computeRiskFlags`/`cipheraudit` produce today. No dedup, no identity.
2. **dedup** — the same finding on the same target, seen across repeated scans/reads, collapses
   to one logical finding with a stable identity. Identity is `(target_type, target_id,
   finding_code)` — e.g. `(certificate, <fingerprint>, WEAK_RSA_KEY)`. This mirrors the identity
   scheme W2-05 already established for discovery endpoints (dedup on `(ip, port, sni)`) — same
   principle, applied to findings instead of endpoints.
3. **scope** — a finding is filtered to what the viewing principal is allowed to see (tenant
   scoping, per W2-01/W2-03's existing tenant-visibility machinery — a finding on a cert the
   caller can't see shouldn't appear in their funnel at all, independent of suppression).
4. **applicability** — a finding that no longer applies to the *current* state of its target
   (the cert was re-issued, the endpoint stopped resolving, the offending config was already
   fixed) drops out here, distinct from being suppressed — it isn't accepted risk, it's gone.
5. **effective** — what's left after dedup + scope + applicability: the real, current, in-scope
   finding count.
6. **suppressed(justified)** — a subset of *effective* findings that carry an active accepted-risk
   exception (below). A suppressed finding is **never removed from the raw or effective count** —
   it is annotated and excluded only from whatever "needs attention now" view a UI chooses to
   build. Every finding-count surface (once phase 2 wires it) must show `raw → effective →
   suppressed(justified)` side by side, per FR-R10/NFR-R4 — raw is never hidden.

Phase 1 (this ticket) builds the accepted-risk exception primitive that stage 6 depends on. Phases
2+ (dedup identity tracking, applicability re-checks, the actual funnel computation) are future
tickets — W3-02 surfaces counts end-to-end but does so by reading whatever the eventual backend
wiring produces; that wiring itself is not yet ticketed and is intentionally left open rather than
guessed at here.

## The accepted-risk exception primitive

An exception is a human decision that a specific finding, on a specific target, is accepted risk
for a bounded period — not a blanket suppression, not silent, not permanent.

### Schema (`finding_exceptions` table, migration `000022`)

| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PK | `exc-<16 hex bytes>` |
| `target_type` | TEXT | `certificate` \| `ca` — matches R-D1's "per cert/CA" scope. `CHECK` constrained, following this codebase's existing enum convention (`000002_templates_ca_certs_core.up.sql`'s `type`/`status` columns). |
| `target_id` | TEXT | The certificate's `fingerprint_sha256` or the CA's `id`. Not FK-constrained — certificates are file-based (no genuine DB `certificates` table backing every deployment; see G-55 for the parallel discovery-side version of this same constraint) so a hard FK isn't available uniformly across deployments. |
| `finding_code` | TEXT | The raw finding this exception covers, e.g. `WEAK_RSA_KEY`. Free text, not `CHECK`-enforced — `computeRiskFlags`/`cipheraudit` emit plain string literals today with no fixed registry (noted above), so constraining this column to a fixed list would go stale the moment a new flag is added in Go without a matching migration. This is the one deliberately *not* fixed enum in the schema — only `justification_code` is, per D-031's literal ask. |
| `justification_code` | TEXT | Fixed enum, `CHECK` constrained: `risk_accepted`, `compensating_control`, `false_positive`, `planned_remediation`, `not_applicable` (see below). |
| `justification_note` | TEXT, nullable | Free-text detail alongside the fixed code — *why*, for a human reader. Never a substitute for the fixed code (the code is what a report can group/count on; the note is context). |
| `created_by` | TEXT | Principal ID that filed the exception. |
| `created_at` | TEXT | RFC3339. |
| `expires_at` | TEXT | RFC3339, **required, not nullable** — R-D1/D-031 both specify "expiry-dated"; there is no permanent exception in this design. An operator who needs a long window sets a long `expires_at` and re-files when it lapses; the schema doesn't offer an escape hatch from that discipline. |

### Fixed-enum justification codes

Cribbed from VEX-style (CISA Vulnerability Exploitability eXchange) justification vocabularies,
adapted for accepted-risk rather than pure not-affected/affected status, since Kryptkeeper's
findings (weak keys, expiring certs, SAN sprawl) are real, present conditions being risk-accepted
— not disputes about whether a vulnerability applies at all:

- `risk_accepted` — the resource owner has explicitly accepted this risk (e.g. legacy system,
  scheduled decommission).
- `compensating_control` — a different control mitigates the risk (e.g. network segmentation
  around a weak-key legacy endpoint).
- `false_positive` — the finding is factually wrong for this target.
- `planned_remediation` — a fix is scheduled; the exception is a bridge, not an endpoint.
- `not_applicable` — the finding's underlying condition doesn't actually apply in this
  deployment's context.

### Auto-reopen — expiry is the only field that needs runtime logic

D-031/FR-R10 require an exception to "auto-reopen … when the cert is re-issued or the exception
lapses." These are two different mechanisms, and only one of them needs code:

- **Lapse (expiry)**: an exception is only ever effective when `now < expires_at`. Any consumer
  (phase 2+) checks this at read time — there is no background job that "expires" a row; expiry
  is computed, not stored as a status flip, so there's nothing to keep in sync.
- **Cert re-issuance**: this is **structural, not code** — a certificate's `fingerprint_sha256`
  changes on every re-issuance (the fingerprint is over the full DER-encoded cert, including
  serial number and validity window, both of which differ on a new issuance even with an identical
  key). A `certificate`-scoped exception is keyed by `target_id = <the old fingerprint>`. Once
  that certificate is renewed, the *new* certificate has a *new* fingerprint with no exception row
  of its own — the old exception simply no longer matches anything live. There is nothing to
  "reopen": the new cert was never covered in the first place. This falls out of choosing
  fingerprint (not some longer-lived logical-certificate identity) as the `target_id` for
  cert-scoped exceptions, and is the reason this design doesn't need a reconciliation job, a
  webhook on renewal, or a "was this cert's exception invalidated by a later event" query.
  `ca`-scoped exceptions are deliberately not fingerprint-bound (a CA persists across every cert
  it issues), so they are unaffected by any single certificate's re-issuance, which is the
  correct behavior for a CA-level risk acceptance.

### What phase 1 does and does not include

**Included** (this ticket): the migration, the `FindingExceptionStore` interface + sqlite/postgres
implementations with the `EnsureSchema` self-heal (G-33 pattern — the migration exists but, as
established for every other DB-backed store this arc, cannot be assumed to have actually run
against a live deployment), and CRUD (`Create`/`Get`/`List`/`Delete`) plus an
`ActiveForTarget`/`ListActive`-shaped read that applies the expiry check above.

**Not included** (future tickets, not guessed at here): wiring this store into `computeRiskFlags`,
`cipheraudit`, any report endpoint, or any UI. Persisted dedup identity for raw findings (stage 2
of the funnel) does not exist yet — this ticket's exception rows reference a `finding_code` string
that isn't backed by any persisted "finding" row, because no such row exists yet. Building that
tracking is a separate, larger piece of work than this ticket's 8 points cover (its own notes flag
it as a "split candidate" for exactly this reason).
