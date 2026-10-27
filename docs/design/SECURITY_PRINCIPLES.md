# Security principles

Kryptkeeper is PKI software. These five rules apply to every change, from
code to tests to docs. A change that breaks one is a security defect, not a
style issue, and it is not merged.

1. **Never loosen verification.** Cryptographic behaviour is never made to
   pass. If a test fails because a signature, chain, expiry or key-usage check
   is correct and the test's expectation is wrong, fix the test. A
   verification path is never weakened to turn a check green.
2. **Private key material never leaves its boundary.** No key bytes in logs,
   errors, API responses or committed test fixtures. Test keys are generated
   in the test or are clearly marked fakes.
3. **Proposer is not approver.** Writes from the MCP server are proposals
   that wait in a human approval queue. The separation is enforced in code,
   and test doubles must keep it.
4. **Tenant leaks are security defects.** Multi-tenancy is behind a flag.
   Any change that lets data cross a tenant boundary is treated as a
   vulnerability, not a bug.
5. **Audit records are append-only.** If something cannot be reconstructed
   from the audit log, that is a bug.

See [SECURITY.md](../../SECURITY.md) for how to report a vulnerability and
[CONTRIBUTING.md](../../CONTRIBUTING.md) for how changes are made.
