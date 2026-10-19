# W26-15 live test: Terraform provider acceptance against a live hub
date:    2026-10-17T01:35:04Z
commit:  8b1fe4058a8d514e5f0eed182f36698fd5ee5144
machine: Darwin 27.0.0 arm64, go1.27.1, OpenSSL 3.6.5
cli:     OpenTofu v1.13.1

=== build and start the hub (plain HTTP, 127.0.0.1:56149, state in a temp dir) ===
PASS: hub built from this checkout
PASS: hub up; admins alice and bob authenticate

=== go test -run TestAcc (real provider binary through tofu) ===
=== RUN   TestAcc_CA_Template_Certificate_RoundTrip
    acceptance_test.go:364: residual=0
--- PASS: TestAcc_CA_Template_Certificate_RoundTrip (7.34s)
=== RUN   TestAcc_PolicyViolationSurfacesRule
--- PASS: TestAcc_PolicyViolationSurfacesRule (1.96s)
=== RUN   TestAcc_StateHasNoPrivateKey
--- PASS: TestAcc_StateHasNoPrivateKey (8.32s)
=== RUN   TestAcc_DestroyPendingApprovalFails
--- PASS: TestAcc_DestroyPendingApprovalFails (11.72s)
=== RUN   TestAcc_ImportThenPlan
--- PASS: TestAcc_ImportThenPlan (11.91s)
PASS
ok  	terraform-provider-kryptkeeper/internal/provider	41.374s
PASS: TestAcc_CA_Template_Certificate_RoundTrip
PASS: TestAcc_StateHasNoPrivateKey
PASS: TestAcc_DestroyPendingApprovalFails
PASS: TestAcc_ImportThenPlan
PASS: TestAcc_PolicyViolationSurfacesRule

=== residuals through the API (tfacc- objects left behind) ===
residual=0 (non_revoked_cas=0 active_templates=0 non_revoked_certs=0)
PASS: 0 residual resources

ALL STEPS PASSED
