# Live validation W26-11: SCEP renewal, CMP rr and polling, EST labels - v0.14

Date: 2026-10-16. Harness: `tests/live/protocols/run.sh`. globalsign/est: v1.0.7.
Hub commit, host, micromdm/scep and openssl (alpine) versions: not recorded by the log (PENDING-RUN).
Source log: `uat11-pass.log`, real run 2026-10-16 (hub on :8096, TLS), ends `ALL STEPS PASSED`, `EXIT 0`.

## Verdict: PASS - validated (full run: 105 PASS lines, 0 failures, 2026-10-16)

The W22-17 policy-refusal sub-step reports `RESULT: 19 passed, 0 failed`. In it, one line reads
`FAIL enroll: issuance policy "rsa-only"...`: that is the estcheck client printing the
EXPECTED refusal (ECDSA-P256 against an RSA-only policy); the harness counted it as
`PASS: EST refusal: client error cites the rule`. It is not a failure.

Mechanisms: SCEP renewal is W26-30; CMP template selection is `KRYPTKEEPER_CMP_TEMPLATE`
(deferred issuance approved as a `cmp_enroll` pending action, `act-95571affa6bfa632750943c8`);
EST labels are `POST /api/v1/est/labels` and the label template lists `protocol:est`.

## Board acceptance

| # | Acceptance | Named PASS lines | Result |
|---|---|---|---|
| 1 | SCEP renewal signed by the current cert succeeds, unrelated key refused, replay fails | "SCEP renewal signed by the current cert is issued", "...unrelated key is refused", "...replay refused" | PASS |
| 2 | `openssl cmp -cmd rr` revokes and OCSP answers revoked; pollReq shown against an approval-required template | "OCSP answers revoked for the rr'd certificate", "client log shows waiting/pollReq before approval", "openssl cmp ir completes after approval" | PASS |
| 3 | globalsign/est enrolls on a label path, refused outside the suffix; ALL STEPS PASSED | "globalsign/est enrolled on /.well-known/est/uat-label/", "a name outside the allowed suffix is refused" | PASS |

## Steps

| Step | Result | Evidence |
|---|---|---|
| SCEP renew (signed by current cert), same CN, new serial | PASS | uat11-pass.log |
| renewed cert chains to the RSA SCEP CA | PASS | uat11-pass.log |
| SCEP renew-rogue (cert of first, unrelated key) refused | PASS | uat11-pass.log |
| SCEP renew-foreign (self-signed signer) refused | PASS | uat11-pass.log |
| SCEP challenge replay after renewal refused | PASS | uat11-pass.log |
| `scep.renew` audit rows (success and denied) | PASS | [scep.renew:denied scep.renew:denied scep.renew:success] |
| CMP rr wrong secret rejected | PASS | uat11-pass.log |
| CMP rr revokes (RR_RC=0) | PASS | uat11-pass.log |
| OCSP revoked for the rr target | PASS | serial E5492681C2C8E7B72F1B199B829D27F3 |
| CRL lists the rr serial | PASS | uat11-pass.log |
| second rr rejected | PASS | uat11-pass.log |
| `cmp.rr` success audited | PASS | uat11-pass.log |
| CMP poll: cmp_enroll pending in the queue | PASS | act-95571affa6bfa632750943c8 |
| client log shows waiting/pollReq before approval | PASS | uat11-pass.log |
| bootstrap token cannot approve (403) | PASS | uat11-pass.log |
| alice approves (200) | PASS | uat11-pass.log |
| client ends IR_POLL_RC=0 with a certificate, chains to CMP CA | PASS | IR_POLL_RC=0; checkAfter = 30 s |
| `cmp.ir` pending_approval audited | PASS | uat11-pass.log |
| EST label created, listed | PASS | uat11-pass.log |
| EST enroll on label path; inventory template_id = est-label-tpl, source=est | PASS | serial 257181830170574244015799694608348953258, CN uat-est-label.est.uat.example |
| EST outside the user's suffix refused | PASS | uat11-pass.log |
| EST label without protocol:est refused | PASS | 403 |
| unknown EST label 404 | PASS | 404 |

## Notes

- The poll step ran with `checkAfter = 30 seconds` (openssl cmp has no `-polltime`).
- Not recorded by the log: hub commit, host, micromdm/scep and alpine openssl versions (PENDING-RUN).

## Product fixes this run drove

- Migration 000196: the Baseline policy allows RSA-3072; the policy API, openapi and UI accept RSA-3072
  (the W22-17 rsa-only refusal proof needs RSA-3072 on the allow-list; ACME positive control passes).
- X.509 approval templates now dry-run the engine policy before queueing (W26-32 commit).
- osslsigncode 2.5 signs a PE via the engine by name (see W26-24).
