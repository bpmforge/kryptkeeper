// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// decodeForbiddenMessage extracts the "message" field from a
// {"error":"forbidden","message":"..."} envelope.
func decodeForbiddenMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode forbidden body: %v (%s)", err, rec.Body.String())
	}
	if body.Error != "forbidden" {
		t.Fatalf("expected error=forbidden, got %q (%s)", body.Error, rec.Body.String())
	}
	return body.Message
}

// TestCertificateIssueDeniedMessagesDistinguishTeamScopeFromTenantVisibility
// is the S-37 regression: a 403 on certificate issuance must name which gate
// failed -- team scope vs tenant visibility -- and the two messages must not
// leak the other tenant's identifiers into the response body.
func TestCertificateIssueDeniedMessagesDistinguishTeamScopeFromTenantVisibility(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)

	// Team-scope refusal: acme's own CA and template, but a team_id that
	// doesn't match the authenticated principal (svc-principal).
	teamReq := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", strings.NewReader(
		`{"ca_id":"ca-acme","template_id":"tpl-acme","csr_pem":"placeholder","team_id":"someone-elses-team"}`))
	teamReq.Header.Set("Authorization", "Bearer "+lastTenantWritePathViewerToken)
	teamReq.Header.Set("X-Tenant", "acme")
	teamRec := httptest.NewRecorder()
	mux.ServeHTTP(teamRec, teamReq)
	if teamRec.Code != http.StatusForbidden {
		t.Fatalf("team-scope mismatch: expected 403, got %d: %s", teamRec.Code, teamRec.Body.String())
	}
	teamMsg := decodeForbiddenMessage(t, teamRec)

	// Tenant-visibility refusal: acme's principal, globex's CA.
	tenantReq := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", strings.NewReader(
		`{"ca_id":"ca-globex","template_id":"tpl-acme","csr_pem":"placeholder"}`))
	tenantReq.Header.Set("Authorization", "Bearer "+acmeToken)
	tenantReq.Header.Set("X-Tenant", "acme")
	tenantRec := httptest.NewRecorder()
	mux.ServeHTTP(tenantRec, tenantReq)
	if tenantRec.Code != http.StatusForbidden {
		t.Fatalf("tenant-visibility mismatch: expected 403, got %d: %s", tenantRec.Code, tenantRec.Body.String())
	}
	tenantMsg := decodeForbiddenMessage(t, tenantRec)

	if teamMsg == tenantMsg {
		t.Fatalf("expected distinct messages for team-scope vs tenant-visibility refusals, both got %q", teamMsg)
	}
	if !strings.Contains(teamMsg, "team") || strings.Contains(teamMsg, "tenant") {
		t.Fatalf("team-scope message should name the team check and not the tenant check, got %q", teamMsg)
	}
	if !strings.Contains(tenantMsg, "tenant") || strings.Contains(tenantMsg, "team") {
		t.Fatalf("tenant-visibility message should name the tenant check and not the team check, got %q", tenantMsg)
	}

	// Neither message may leak which tenant/CA actually owns the resource.
	for _, leak := range []string{"globex", "ca-globex", "Globex"} {
		if strings.Contains(teamMsg, leak) || strings.Contains(tenantMsg, leak) {
			t.Fatalf("forbidden message leaked another tenant's data (%q): team=%q tenant=%q", leak, teamMsg, tenantMsg)
		}
	}
}

// TestCertificateIssueDenialLogsPrincipalFieldAndReason is the S-37 server-log
// regression: the found note was that a denied certificate mutation "writes
// NOTHING to the server log" -- an operator reading logs had no way to act on
// it. Each denial must log the principal, the offending field, and the
// reason, and the log line must distinguish the two refusal types just like
// the response body does.
func TestCertificateIssueDenialLogsPrincipalFieldAndReason(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)

	var logBuf strings.Builder
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	teamReq := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", strings.NewReader(
		`{"ca_id":"ca-acme","template_id":"tpl-acme","csr_pem":"placeholder","team_id":"someone-elses-team"}`))
	teamReq.Header.Set("Authorization", "Bearer "+lastTenantWritePathViewerToken)
	teamReq.Header.Set("X-Tenant", "acme")
	teamRec := httptest.NewRecorder()
	mux.ServeHTTP(teamRec, teamReq)
	if teamRec.Code != http.StatusForbidden {
		t.Fatalf("team-scope mismatch: expected 403, got %d: %s", teamRec.Code, teamRec.Body.String())
	}
	teamLog := logBuf.String()
	if !strings.Contains(teamLog, "svc-principal") {
		t.Fatalf("expected team-scope denial log to name the principal, got %q", teamLog)
	}
	if !strings.Contains(teamLog, `field="team_id"`) {
		t.Fatalf("expected team-scope denial log to name the offending field, got %q", teamLog)
	}
	if !strings.Contains(teamLog, "reason=team_scope_mismatch") {
		t.Fatalf("expected team-scope denial log to name the reason, got %q", teamLog)
	}

	logBuf.Reset()
	tenantReq := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", strings.NewReader(
		`{"ca_id":"ca-globex","template_id":"tpl-acme","csr_pem":"placeholder"}`))
	tenantReq.Header.Set("Authorization", "Bearer "+acmeToken)
	tenantReq.Header.Set("X-Tenant", "acme")
	tenantRec := httptest.NewRecorder()
	mux.ServeHTTP(tenantRec, tenantReq)
	if tenantRec.Code != http.StatusForbidden {
		t.Fatalf("tenant-visibility mismatch: expected 403, got %d: %s", tenantRec.Code, tenantRec.Body.String())
	}
	tenantLog := logBuf.String()
	if !strings.Contains(tenantLog, "svc-principal") {
		t.Fatalf("expected tenant-visibility denial log to name the principal, got %q", tenantLog)
	}
	if !strings.Contains(tenantLog, `field="ca_id"`) {
		t.Fatalf("expected tenant-visibility denial log to name the offending field, got %q", tenantLog)
	}
	if !strings.Contains(tenantLog, "reason=tenant_visibility") {
		t.Fatalf("expected tenant-visibility denial log to name the reason, got %q", tenantLog)
	}
}

// TestCertificateDenialLogEscapesInjectedNewline is the CWE-117 regression
// found in gate review: value is attacker-controlled (it is req.CAID,
// req.TemplateID or req.TeamID straight from the JSON body, and
// parseCertificateIssueRequest only checks non-empty). A prior version of
// denyCertificateAccess logged it with plain %s, so a ca_id containing a raw
// newline followed by text shaped like another denyCertificateAccess call
// forged a second, fully-formed log line attributing a fabricated denial to
// an arbitrary principal. If the fix regresses, this produces two newlines
// (the injected one plus the log package's trailing one) instead of one.
func TestCertificateDenialLogEscapesInjectedNewline(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)

	var logBuf strings.Builder
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	forgedLine := "certificate certificate.revoke denied: principal=bootstrap field=team_id value=evil reason=team_scope_mismatch"
	maliciousCAID := "ca-globex\n" + forgedLine
	body, err := json.Marshal(map[string]string{
		"ca_id":       maliciousCAID,
		"template_id": "tpl-acme",
		"csr_pem":     "placeholder",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+acmeToken)
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	logged := logBuf.String()
	if n := strings.Count(logged, "\n"); n != 1 {
		t.Fatalf("expected exactly 1 newline (the injected one must be escaped, not forge a second log line), got %d in %q", n, logged)
	}
	if !strings.Contains(logged, `ca-globex\ncertificate`) {
		t.Fatalf("expected the injected newline to appear escaped as \\n in the logged value, got %q", logged)
	}
}

// TestCertificateRevokeCrossTenantMessageNamesTenantNotTeam covers the shared
// authorizeCertificateResourceAccess path (revoke/renew/ownership/chain/
// download/get all funnel through it): a cross-tenant revoke must get the
// tenant-visibility message, not the generic/team one, and must not leak the
// owning tenant's identity.
func TestCertificateRevokeCrossTenantMessageNamesTenantNotTeam(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)

	rec := doTenantReq(mux, http.MethodPost, "/api/v1/certificates/fp-globex-cert/revoke", acmeToken, "acme")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant revoke: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	msg := decodeForbiddenMessage(t, rec)
	if !strings.Contains(msg, "tenant") || strings.Contains(msg, "team") {
		t.Fatalf("cross-tenant revoke message should name the tenant check and not the team check, got %q", msg)
	}
	for _, leak := range []string{"globex", "ca-globex", "Globex"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("forbidden message leaked another tenant's data (%q): %q", leak, msg)
		}
	}
}

// TestCertificateRevokeCrossTeamMessageNamesTeamNotTenant is the team-scope
// counterpart: multi-tenancy is off (so the tenant check is bypassed
// entirely), a single certificate belongs to a different team than the
// caller, and the resulting 403 must name the team check, not the tenant
// one -- proving authorizeCertificateResourceAccess's two branches are
// genuinely independent, not one masking the other.
func TestCertificateRevokeCrossTeamMessageNamesTeamNotTenant(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")

	dataDir := t.TempDir()
	certFile := filepath.Join(dataDir, "certificates.json")
	certBody := []byte(`[
{"fingerprint_sha256":"fp-owner-team","serial_number":"01","common_name":"svc.example.com","subject_dn":"CN=svc.example.com","subject_alt_names":[],"issuer_cn":"Root","issuer_dn":"CN=Root","ca_id":"ca-1","template_id":"tpl-1","team_id":"team-owner","valid_from":"2026-01-01T00:00:00Z","valid_until":"2027-01-01T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256,"signature_algorithm":"ecdsa-with-SHA256","extended_key_usage":["serverAuth"],"key_usage":["digitalSignature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":false,"risk_score":5,"risk_flags":[],"grade":"A","renewal_method":"manual","renewal_status":"active","source":"api","etag":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}
]`)
	if err := os.WriteFile(certFile, certBody, 0o600); err != nil {
		t.Fatalf("write cert fixture: %v", err)
	}
	t.Setenv("APP_CERTIFICATE_FILE", certFile)

	auth := NewAuthenticatorFromEnv()
	// S-36: team confinement applies below the admin role, so this
	// cross-team requester must be a non-admin identity.
	_, token, err := auth.CreateAPIKey("other-team-svc", "team-requester", "viewer", []string{}, "", "", time.Now())
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}

	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForCertificate{}, stubAuditProviderForCertificate{}, stubCAProviderForCertificate{}, stubTemplateProviderForCertificate{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/fp-owner-team/revoke", strings.NewReader(`{"reason_code":1}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-team revoke: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	msg := decodeForbiddenMessage(t, rec)
	if !strings.Contains(msg, "team") || strings.Contains(msg, "tenant") {
		t.Fatalf("cross-team revoke message should name the team check and not the tenant check, got %q", msg)
	}
	if strings.Contains(msg, "team-owner") {
		t.Fatalf("forbidden message leaked the owning team's id: %q", msg)
	}
}

// S-36: certificate privilege derives from ROLE, never from the
// principal string. The old check was principal == "bootstrap" — every
// real admin session got 403 for other teams while anything named
// "bootstrap" bypassed team confinement entirely.

func adminPD(name string) AuthPrincipal {
	return AuthPrincipal{ID: name, Role: "pki-admin", Scopes: []string{"*"}}
}

func viewerPD(name string) AuthPrincipal {
	return AuthPrincipal{ID: name, Role: "viewer", Scopes: []string{}}
}

func TestCertificateMutationAuthorizesOnRoleNotPrincipalString(t *testing.T) {
	// A pki-admin named anything mutates for any team.
	team := "platform"
	if err := authorizeCertificateMutationRequest(adminPD("demo-operator"), &team); err != nil {
		t.Fatalf("pki-admin must mutate for any team regardless of principal string: %v", err)
	}

	// The literal is dead: a principal NAMED "bootstrap" with a non-admin
	// role gets no privilege from its name.
	team = "platform"
	if err := authorizeCertificateMutationRequest(viewerPD("bootstrap"), &team); err == nil {
		t.Fatal("a non-admin role named \"bootstrap\" must not bypass team confinement")
	}
}

func TestCertificateMutationConfinesNonPrivilegedBothDirections(t *testing.T) {
	// Own team: allowed.
	team := "team-a"
	if err := authorizeCertificateMutationRequest(viewerPD("team-a"), &team); err != nil {
		t.Fatalf("own-team mutation must be allowed: %v", err)
	}
	// Other team: refused.
	team = "team-b"
	if err := authorizeCertificateMutationRequest(viewerPD("team-a"), &team); err == nil {
		t.Fatal("cross-team mutation by a non-privileged principal must be refused")
	}
	// Empty team defaults to own.
	team = ""
	if err := authorizeCertificateMutationRequest(viewerPD("team-a"), &team); err != nil || team != "team-a" {
		t.Fatalf("empty team_id must default to the principal's own: err=%v team=%q", err, team)
	}
	// Nil team (bulk paths): refused for non-admins, allowed for admins.
	if err := authorizeCertificateMutationRequest(viewerPD("team-a"), nil); err == nil {
		t.Fatal("nil team_id must be refused for non-privileged principals")
	}
	if err := authorizeCertificateMutationRequest(adminPD("ops"), nil); err != nil {
		t.Fatalf("nil team_id must be allowed for admins (bulk ops): %v", err)
	}
}

func TestCertificateListQueryAuthorizesOnRole(t *testing.T) {
	// Admin: query passes through unscoped.
	q := CertificateListQuery{TeamID: "platform"}
	if err := authorizeCertificateListQuery(&q, adminPD("someone")); err != nil {
		t.Fatalf("pki-admin list for any team must pass: %v", err)
	}
	if q.TeamID != "platform" {
		t.Fatalf("admin's requested team filter must be preserved, got %q", q.TeamID)
	}

	// Non-admin: scoped to own team.
	q = CertificateListQuery{}
	if err := authorizeCertificateListQuery(&q, viewerPD("team-a")); err != nil {
		t.Fatalf("own list must pass: %v", err)
	}
	if q.TeamID != "team-a" {
		t.Fatalf("non-admin list must be forced to own team, got %q", q.TeamID)
	}
	q = CertificateListQuery{TeamID: "team-b"}
	if err := authorizeCertificateListQuery(&q, viewerPD("team-a")); err == nil {
		t.Fatal("cross-team list by a non-privileged principal must be refused")
	}
	// The name grants nothing here either.
	q = CertificateListQuery{TeamID: "team-b"}
	if err := authorizeCertificateListQuery(&q, viewerPD("bootstrap")); err == nil {
		t.Fatal("a non-admin named \"bootstrap\" must not list other teams")
	}
}

func TestCertificateAdminIsRoleNotScope(t *testing.T) {
	// S-56's boundary, held from the start: wildcard scopes without the
	// admin role grant nothing.
	scopedOnly := AuthPrincipal{ID: "svc", Role: "service-account", Scopes: []string{"*"}}
	team := "platform"
	if err := authorizeCertificateMutationRequest(scopedOnly, &team); err == nil {
		t.Fatal("wildcard scope without the admin role must not grant certificate admin")
	}
	if isCertificateAdmin(scopedOnly) {
		t.Fatal("isCertificateAdmin must key on role, not scopes")
	}
	if !isCertificateAdmin(adminPD("x")) {
		t.Fatal("pki-admin role must be certificate admin")
	}
}

// S-57(a): truncateForLog's over-length branch — would fail on an
// off-by-one or a dropped bound.
func TestTruncateForLogOverLengthBranch(t *testing.T) {
	// Exactly at the bound: untouched.
	at := strings.Repeat("a", maxLoggedDenialValueRunes)
	if got := truncateForLog(at); got != at {
		t.Fatalf("value at the bound must be untouched, got %d runes", len([]rune(got)))
	}
	// One over: truncated to the bound plus the marker.
	over := at + "b"
	got := truncateForLog(over)
	if !strings.HasSuffix(got, "...(truncated)") {
		t.Fatalf("over-length value must carry the truncation marker, got %q", got[len(got)-20:])
	}
	kept := strings.TrimSuffix(got, "...(truncated)")
	if len([]rune(kept)) != maxLoggedDenialValueRunes {
		t.Fatalf("kept prefix must be exactly %d runes, got %d", maxLoggedDenialValueRunes, len([]rune(kept)))
	}
	if strings.Contains(kept, "b") {
		t.Fatal("the over-length rune must be dropped")
	}
	// Multi-byte runes: the bound counts RUNES, not bytes.
	wide := strings.Repeat("é", maxLoggedDenialValueRunes+5)
	gotWide := truncateForLog(wide)
	keptWide := strings.TrimSuffix(gotWide, "...(truncated)")
	if len([]rune(keptWide)) != maxLoggedDenialValueRunes {
		t.Fatalf("rune bound broken for multi-byte input: %d runes kept", len([]rune(keptWide)))
	}
}

// S-57(b): the list denial names its reason and logs principal/reason
// like every other denial in the file.
func TestCertificateListDenialNamesReasonAndLogs(t *testing.T) {
	mux, _, _ := setupTenantWritePathTest(t)

	var logBuf strings.Builder
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?team_id=someone-elses-team", nil)
	req.Header.Set("Authorization", "Bearer "+lastTenantWritePathViewerToken)
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-team list: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	msg := decodeForbiddenMessage(t, rec)
	if !strings.Contains(msg, "team") {
		t.Fatalf("list denial must name the team check, got %q", msg)
	}
	logged := logBuf.String()
	if !strings.Contains(logged, "svc-principal") || !strings.Contains(logged, "reason=team_scope_mismatch") {
		t.Fatalf("list denial must log principal and reason, got %q", logged)
	}
}

// S-56: possession of a wildcard scope alone must not grant certificate
// admin — cross-team mutation requires the admin ROLE. (No test on this
// branch ever codified scope-as-admin; this pins the boundary at the
// handler level.)
func TestWildcardScopeWithoutAdminRoleCannotRevokeCrossTeam(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")

	certFile := filepath.Join(t.TempDir(), "certificates.json")
	certBody := []byte(`[
{"fingerprint_sha256":"fp-owner-team","serial_number":"01","common_name":"svc.example.com","subject_dn":"CN=svc.example.com","subject_alt_names":[],"issuer_cn":"Root","issuer_dn":"CN=Root","ca_id":"ca-1","template_id":"tpl-1","team_id":"team-owner","valid_from":"2026-01-01T00:00:00Z","valid_until":"2027-01-01T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256,"signature_algorithm":"ecdsa-with-SHA256","extended_key_usage":["serverAuth"],"key_usage":["digitalSignature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":false,"risk_score":5,"risk_flags":[],"grade":"A","renewal_method":"manual","renewal_status":"active","source":"api","etag":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}
]`)
	if err := os.WriteFile(certFile, certBody, 0o600); err != nil {
		t.Fatalf("write cert fixture: %v", err)
	}
	t.Setenv("APP_CERTIFICATE_FILE", certFile)

	auth := NewAuthenticatorFromEnv()
	// Wildcard scope, NON-admin role — the S-56 shape.
	_, token, err := auth.CreateAPIKey("scoped-svc", "other-principal", "service-account", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}

	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForCertificate{}, stubAuditProviderForCertificate{}, stubCAProviderForCertificate{}, stubTemplateProviderForCertificate{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/fp-owner-team/revoke", strings.NewReader(`{"reason_code":1}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wildcard scope without admin role: expected 403 on cross-team revoke, got %d: %s", rec.Code, rec.Body.String())
	}
}

// S-54: meta.total and the paging cursor reflect the TENANT-FILTERED
// set for a tenant-scoped pki-admin — not the global cross-tenant count.
func TestListTotalsAndCursorAreTenantFiltered(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "on")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())

	// 3 acme certs + 2 globex certs.
	rows := ""
	for i, ca := range []string{"ca-acme", "ca-acme", "ca-acme", "ca-globex", "ca-globex"} {
		if i > 0 {
			rows += ","
		}
		rows += `{"fingerprint_sha256":"fp-` + string(rune('a'+i)) + `","serial_number":"0` + string(rune('1'+i)) + `","common_name":"c.example.com","subject_dn":"CN=c.example.com","subject_alt_names":[],"issuer_cn":"Root","issuer_dn":"CN=Root","ca_id":"` + ca + `","template_id":"tpl-1","team_id":"team-x","valid_from":"2026-01-01T00:00:00Z","valid_until":"2027-01-01T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256,"signature_algorithm":"ecdsa-with-SHA256","extended_key_usage":["serverAuth"],"key_usage":["digitalSignature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":false,"risk_score":5,"risk_flags":[],"grade":"A","renewal_method":"manual","renewal_status":"active","source":"api","etag":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}`
	}
	certFile := filepath.Join(t.TempDir(), "certificates.json")
	if err := os.WriteFile(certFile, []byte("["+rows+"]"), 0o600); err != nil {
		t.Fatalf("write certs: %v", err)
	}
	t.Setenv("APP_CERTIFICATE_FILE", certFile)

	ctx := t.Context()
	tenantStore := NewTenantStoreFromEnv()
	if tenantStore == nil {
		t.Fatal("tenant store unavailable")
	}
	if _, err := tenantStore.CreateTenant(ctx, "acme", "Acme"); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	if _, err := tenantStore.CreateTenant(ctx, "globex", "Globex"); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	if err := tenantStore.SetCATenant(ctx, "ca-acme", "acme"); err != nil {
		t.Fatalf("map: %v", err)
	}
	if err := tenantStore.SetCATenant(ctx, "ca-globex", "globex"); err != nil {
		t.Fatalf("map: %v", err)
	}

	auth := NewAuthenticatorFromEnv()
	_, acmeAdmin, err := auth.CreateAPIKey("acme-admin", "admin-a", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	_, globexAdmin, err := auth.CreateAPIKey("globex-admin", "admin-g", "pki-admin", []string{"*"}, "", "globex", time.Now())
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForCertificate{}, stubAuditProviderForCertificate{}, stubCAProviderForCertificate{}, stubTemplateProviderForCertificate{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	list := func(token, path string) (data []map[string]any, total int, next *string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("list %s: %d: %s", path, rec.Code, rec.Body.String())
		}
		var resp struct {
			Data []map[string]any `json:"data"`
			Meta struct {
				Total      int     `json:"total"`
				NextCursor *string `json:"next_cursor"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("parse: %v", err)
		}
		return resp.Data, resp.Meta.Total, resp.Meta.NextCursor
	}

	// Acme admin: total is 3 (never 5), pages of 2 neither overlap nor skip.
	page1, total, next := list(acmeAdmin, "/api/v1/certificates?limit=2")
	if total != 3 {
		t.Fatalf("acme total must be the tenant-filtered 3, got %d", total)
	}
	if len(page1) != 2 || next == nil {
		t.Fatalf("page1: %d items, next=%v", len(page1), next)
	}
	page2, _, next2 := list(acmeAdmin, "/api/v1/certificates?limit=2&cursor="+*next)
	if len(page2) != 1 {
		t.Fatalf("page2 must hold the remaining 1 item, got %d", len(page2))
	}
	if next2 != nil {
		t.Fatalf("no third page expected, got cursor %v", *next2)
	}
	seen := map[string]bool{}
	for _, item := range append(page1, page2...) {
		fp := item["fingerprint_sha256"].(string)
		if seen[fp] {
			t.Fatalf("pages overlap on %s", fp)
		}
		seen[fp] = true
		if item["ca_id"] != "ca-acme" {
			t.Fatalf("cross-tenant row leaked: %v", item["ca_id"])
		}
	}
	if len(seen) != 3 {
		t.Fatalf("pages skipped rows: saw %d of 3", len(seen))
	}

	// The other direction: globex admin sees exactly its 2.
	_, gTotal, _ := list(globexAdmin, "/api/v1/certificates?limit=10")
	if gTotal != 2 {
		t.Fatalf("globex total must be 2, got %d", gTotal)
	}
}
