# Kryptkeeper v0.14.0

This release is about enrollment: every protocol credential is now managed
through the API and the UI instead of env files, SCEP gains renewal, CMP gains
revocation and polling, SSH issuance honours approval templates, code-signing
gets an approval-and-hardware-key profile, and the cert-manager issuer works on a
real cluster. It is feature group W26 of the v1.0 release train.

## Upgrade notes (read first)

- **EST answers 401, not 403, when a client is not authenticated.** Anonymous
  `csrattrs`, client-cert-only `simpleenroll` without a certificate and
  `simplereenroll` without a peer certificate now return 401. Plaintext requests
  and a server with no EST enrollment configured still return 403.
- **cert-manager issuer chart.** `pollIntervalSeconds` is renamed
  `resyncIntervalSeconds` (default 300; env `KRYPTKEEPER_RESYNC_INTERVAL`, the old
  `KRYPTKEEPER_POLL_INTERVAL` is gone). The chart now ships the `Issuer` and
  `ClusterIssuer` CRDs, and the issuer approves and denies its own
  CertificateRequests. `certManager.approverRBAC` defaults to `false`; leave it
  off (and do not let approver-policy pre-approve this signer) or policy
  denials show as `Ready=False/Denied` instead of `Denied=True`. The hub remains
  the policy authority: a request is approved only after the hub signs it.
- **Repeat issuance returns the existing certificate.** `POST /api/v1/certificates`
  with the same public key, CA, template, team and names as an unrevoked
  certificate with at least a third of its validity left now answers `200` with
  that certificate instead of signing a new one. A repeat on an approval
  template returns the same pending `approval_id`.
- **Approval templates check policy before queueing.** A request the issuance
  policy would refuse now gets `422 policy_violation` at request time instead
  of `202` followed by a failed approval.
- **Baseline policy allows RSA-3072.** Migration 000196 adds `RSA-3072` to an
  unedited `Baseline` policy, which already set `min_rsa_bits: 3072` but listed
  only `RSA-4096`. The policy API, openapi and UI now accept `RSA-3072` in
  `allowed_algorithms`. RSA-2048 leaves stay refused by default; devices that
  only do RSA-2048 (common for SCEP appliances) need an operator policy.
- **Policy refusals stay 422.** `POST /certificates` documents
  `422 {"error":"policy_violation"}` with the rule name in `message`.
- **CMP starts whenever a hub database is configured**, not only when
  `KRYPTKEEPER_CMP_SECRET` is set, so API-minted credentials work alone. Set
  `KRYPTKEEPER_CMP_TEMPLATE` to route CMP through a template (with
  `require_approval`, clients get `waiting` and poll).
- **Code-signing protected mode** (`KRYPTKEEPER_CODESIGN_PROTECTED=true`) needs
  an HSM keystore backend and refuses requester CSRs without a YubiKey PIV
  attestation. No vendor root ships yet, so until an operator adds the Yubico
  PIV CA to `internal/attestation/roots/`, protected mode accepts only
  hub-generated keys (`POST /api/v1/codesign/requests`).
- **Migrations 000180-000196** (both engines): ACME EAB admin and provisioners,
  CMP credentials, EST users and labels, code-signing attestations, approval
  rows gain `kind`/`request_json`/`tenant`, Baseline RSA-3072.

## Added

- **ACME server:** EAB key API (create, list, revoke, bind to template),
  provisioners at `/acme/<name>/directory` with domain allow-lists and
  challenge-method policy, ARI that honours the issuer hash and answers
  renew-now for revoked or superseded certificates.
- **ACME upstream:** ARI-driven renewal windows with `replaces`, Retry-After
  backoff and a rate-limit gate (no CA traffic while backed off), and a
  mass-revocation reaction that forces affected certificates due, paced by the
  CA's ARI Retry-After.
- **EST:** API-managed Basic users (create, rotate, disable) and label routes
  `/.well-known/est/<label>/` bound to templates.
- **CMP:** `rr` revocation, `certConf` handling and `pollReq` against approval
  templates; per-credential PBM secrets and trust-anchor registration
  (anchors are stored, not yet enforced).
- **SCEP:** renewal signed by the current certificate (PKCSReq and RenewalReq),
  advertised in GetCACaps.
- **SSH:** issuance from a `require_approval` template returns `202` and is
  signed only after a different principal approves.
- **Code signing:** template profile with mandatory approval, protected-key
  generation in the HSM, and YubiKey PIV attestation for requester CSRs.
- **UI:** ACME admin page, enrollment page for SCEP challenges, EST users and
  labels and CMP credentials, SSH certificates page, issuance wizard next-step
  links and approval-pending state.
- **Terraform provider acceptance tests** against a live hub.
- **Template policy parity test** across API, ACME, EST, SCEP, CMP and WSTEP.

## Fixed

- The cert-manager issuer could not issue on a real cluster (double-wrapped
  CSR, no PEM in the hub response, missing CRDs, Denied on approved requests).
- The Terraform provider sent wrong CA field names and never fetched PEMs.
- Accessibility: light-theme muted text, inactive tabs and error messages now
  meet WCAG AA contrast; wizard step headings no longer skip a level.

## Verified live (2026-10-16, on the release branch)

Terraform acceptance (OpenTofu), approval and SSH issuance with a real sshd,
SCEP renewal (micromdm), CMP `rr` and polling (openssl), EST labels
(globalsign/est), ACME with certbot 5.8.0 and lego 5.5.2 (53/53 plus the legacy
28/28), code-signing on SoftHSM2 with osslsigncode, cert-manager v1.17.2 on kind,
SPIFFE SVID mTLS on kind, and axe-core at 375/768/1440 px. Results are in
`docs/release/LIVE_RESULTS_FG2_*_v0.14.md`.

## Not yet verified (needs hardware or people)

- SCEP from an F5 BIG-IP or Palo Alto appliance (W26-12).
- WSTEP/XCEP on Windows 10, Server 2019 and 2022, and the lab runbook second-operator pass (W26-13, W26-14).
- Issuance wizard timing with three first-time users and a keyboard-only run (W26-26).
- The YubiKey attestation success path (needs a device and the Yubico root).
- Istio `cacerts` (Path I); SPIFFE Path S is verified.

## Known limits

- Trust anchors for CMP signature protection are registered but not enforced.
- Waiting CMP transactions are held in memory; a hub restart forgets them.
- Requests that do not ask for a forbidden EKU are not refused for it; the
  template's EKU list is stamped instead (no path issues a codeSigning EKU it
  was not configured for).
