# Kryptkeeper v0.17.0

This release covers machine identity: SPIFFE/SPIRE conformance, NHI revocation
at the authorisation layer, a management page for non-human identities,
single-use agent enrollment tokens, the MCP agent surface (blast radius and a
tool catalogue), CI-OIDC-bound code-signing certificates and an RFC 3161
time-stamp service. It is feature group W29 of the v1.0 release train. All 15
W29 tickets are `done` on the board. Decisions: D-150 to D-153.

## Upgrade notes (read first)

- **Migrations 000240 and 000241 run on upgrade:** `agent_enrollment_tokens`
  and `codesign_oidc_trust`.
- **Agent enrollment prefers single-use tokens.** An admin mints a token with
  `POST /api/v1/agent/enrollment-tokens` (24 h default, 7 d maximum, `kkenr_`
  prefix, SHA-256 at rest, revocable) and the agent redeems it once at
  `/api/v1/agent/register`. The shared CSV secret
  `KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS` still works but logs a startup warning
  (never the secret). Unauthenticated open registration stays off (D-151).
- **Time-stamp service is closed by default.** `POST /api/v1/tsa` needs a hub
  principal unless `KRYPTKEEPER_TSA_ALLOW_ANONYMOUS=true` (startup WARN; anonymous
  mode is unthrottled). Enabling it needs `KRYPTKEEPER_TSA_CERT_FILE` and
  `KRYPTKEEPER_TSA_KEY_FILE` (PKCS#8, mode 0600 enforced), optionally
  `KRYPTKEEPER_TSA_CHAIN_FILE` and `KRYPTKEEPER_TSA_POLICY_OID`. The hub CA
  cannot mint a spec-valid TSA certificate, so you provision one (D-153).
- **Code-signing CSR key rules:** ECDSA P-256/P-384/P-521 or RSA 3072 and up.
  Ed25519, RSA-2048 and ML-DSA keys are refused with 400. If the issued
  certificate cannot be recorded in the inventory the call fails 503 and nothing
  is handed out (D-152).
- **A revoked NHI's live SVID still lives to its expiry** (maximum 7 days) until
  CRL/OCSP linkage ships. The authorisation layer rejects it within 60 seconds,
  but see Known gaps (D-150).
- Migrations are on both engines.

## New

- **SPIFFE Workload API conformance harness** (go-spiffe v2.8.1) under
  `tests/live/spiffe`, plus a guide stating the interop boundary and attestation
  limits. Shared-UID or shared-pid workloads receive identical IDs; the test
  asserts that rather than hiding it (W29-01, W29-02). JWT-SVID and K8s PSAT/AWS
  IID attestors are not included (v1.x).
- **NHI revocation:** revoking an NHI burns unredeemed join tokens and the
  authorizer resolves scopes live with no cache (W29-03).
- **NHI management page:** propose, approve, revoke and scopes (W29-04). A live
  flow test drives propose, approve, redeem and revoke through a real client
  (W29-05).
- **Per-agent single-use enrollment tokens** with 24 h expiry and constant-time
  compare (W29-06), with a live test that anonymous registration is refused and
  tokens are single-use (W29-07).
- **MCP:** live client E2E over stdio and HTTP (propose, human approve, executed;
  proposer is never approver) (W29-08); blast-radius impact on MCP proposals and a
  `blast_radius` tool, output wrapped as untrusted (W29-09); a published tool
  catalogue page (W29-10).
- **Code signing from CI:** OIDC trust rules for CI issuers with token
  verification and `jti` replay protection (W29-11); short-lived code-signing
  certificates from a verified CI OIDC token, with a table-driven test covering
  GitHub and GitLab claim sets (W29-12).
- **RFC 3161 time-stamp authority:** token generation and signing (W29-13);
  HTTP endpoint with per-use audit and a post-expiry live verification (W29-14).
- **Container and SBOM signing guide** using a cosign key from Kryptkeeper
  (W29-15).

## Decisions

D-150 (NHI authorizer built, not wired), D-151 (enrollment tokens), D-152
(CI-OIDC code signing), D-153 (TSA key provisioning and closed default). D-154 to
D-159 do not exist in `docs/DECISIONS.md`.

## Pending human runs

None recorded for W29 on the board. The signtool verification path may run only
on a Windows lane; that run is not recorded here (not verified).

## Known gaps

- **The NHI request-time authorizer is not wired to any request path** (D-150):
  nothing presents an SVID as a request credential until SVID-to-principal
  resolution lands. It is a follow-up ticket.
- No per-source rate limit on the TSA; a CriticalEKU issuance option so the hub
  can issue its own TSA certificate is a follow-up (D-153).
