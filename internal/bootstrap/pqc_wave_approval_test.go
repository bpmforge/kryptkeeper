// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newWaveApprovalFixture is newWaveExecuteTestFixture with a recording audit
// provider. The pending store lives inside registerPQCWaveHandlers, so propose
// and approve must go through fx.mux.
func newWaveApprovalFixture(t *testing.T) (*waveExecuteTestFixture, *recordingAuditProvider) {
	t.Helper()
	fx := newWaveExecuteTestFixture(t)
	ap := &recordingAuditProvider{}
	mux := http.NewServeMux()
	registerPQCWaveHandlers(mux, fx.auth, fx.certs, fx.templates, fx.waveStore, fx.keys, ap)
	fx.mux = mux
	return fx, ap
}

func setWaveNow(t *testing.T, d time.Duration) {
	t.Helper()
	old := waveNow
	waveNow = func() time.Time { return time.Now().Add(d) }
	t.Cleanup(func() { waveNow = old })
}

func approveWave(fx *waveExecuteTestFixture, waveID, actionID, token string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	fx.mux.ServeHTTP(rec, waveExecuteReq(http.MethodPost, "/api/v1/reports/pqc-waves/"+waveID+"/execute/"+actionID+"/approve", token, nil))
	return rec
}

func auditRows(ap *recordingAuditProvider, action string) []AuditEntry {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	var out []AuditEntry
	for _, e := range ap.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// issueWaveMember issues a long-lived classical cert and adds it to the wave.
func issueWaveMember(t *testing.T, fx *waveExecuteTestFixture, waveID, host string) string {
	t.Helper()
	ctx := context.Background()
	issued, err := fx.certs.IssueCertificate(ctx, CertificateIssueRequest{CAID: getFirstCAID(t, fx.engine), TemplateID: "tpl-classical", CSRPEM: generateTestCSRPEM(t, host), TeamID: "team-1"})
	if err != nil {
		t.Fatalf("issue %s: %v", host, err)
	}
	if err := fx.waveStore.AddMember(ctx, waveID, MigrationWaveMember{Fingerprint: issued.FingerprintSHA256}); err != nil {
		t.Fatalf("add member: %v", err)
	}
	return issued.FingerprintSHA256
}

func TestWaveApproval_ProposerCannotApprove(t *testing.T) {
	fx, ap := newWaveApprovalFixture(t)
	wave, _ := fx.waveStore.CreateWave(context.Background(), MigrationWave{Name: "w"})
	issueWaveMember(t, fx, wave.ID, "self.example.com")
	proposer := waveExecuteToken(t, fx.auth, "proposer", "pki-admin")
	action := proposeWaveExecute(t, fx, wave.ID, proposer)

	rec := approveWave(fx, wave.ID, action.ID, proposer)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("self-approval: status = %d, want 403. body: %s", rec.Code, rec.Body.String())
	}
	rows := auditRows(ap, "pqc.wave_execute_approve")
	if len(rows) != 1 || rows[0].Outcome != AuditOutcomeDenied || rows[0].ActorID != "proposer" {
		t.Fatalf("approve audit rows = %+v, want one denied row by proposer", rows)
	}
	if n := len(auditRows(ap, "pqc.wave_member_result")); n != 0 {
		t.Fatalf("member results after denied approval: %d, want 0", n)
	}
	// Still pending and unexecuted: a different approver can redeem it.
	approver := waveExecuteToken(t, fx.auth, "approver", "pki-operator")
	if rec := approveWave(fx, wave.ID, action.ID, approver); rec.Code != http.StatusOK {
		t.Fatalf("approval by second principal: status = %d, want 200 (action must have stayed pending). body: %s", rec.Code, rec.Body.String())
	}
}

func TestWaveApproval_ExpiredCannotBeRedeemed(t *testing.T) {
	fx, ap := newWaveApprovalFixture(t)
	wave, _ := fx.waveStore.CreateWave(context.Background(), MigrationWave{Name: "w"})
	issueWaveMember(t, fx, wave.ID, "exp.example.com")
	proposer := waveExecuteToken(t, fx.auth, "proposer", "pki-admin")
	approver := waveExecuteToken(t, fx.auth, "approver", "pki-operator")
	action := proposeWaveExecute(t, fx, wave.ID, proposer)

	setWaveNow(t, 25*time.Hour)
	rec := approveWave(fx, wave.ID, action.ID, approver)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "expired") {
		t.Fatalf("expired approve: status = %d body = %s, want 409 mentioning expired", rec.Code, rec.Body.String())
	}
	rows := auditRows(ap, "pqc.wave_execute_approve")
	if len(rows) != 1 || rows[0].Outcome != AuditOutcomeDenied {
		t.Fatalf("approve audit rows = %+v, want one denied row", rows)
	}
	if n := len(auditRows(ap, "pqc.wave_member_result")); n != 0 {
		t.Fatalf("expired approval ran members: %d results", n)
	}
	for _, wp := range listWavesForTest(t, fx.mux, approver) {
		if wp.ID == wave.ID && wp.Migrated != 0 {
			t.Fatalf("expired approval migrated %d members", wp.Migrated)
		}
	}
	// The action was marked rejected, so even inside the window it is dead.
	setWaveNow(t, 0)
	if rec := approveWave(fx, wave.ID, action.ID, approver); rec.Code != http.StatusConflict {
		t.Fatalf("second approve of expired action: status = %d, want 409", rec.Code)
	}
}

func TestWaveApproval_WithinWindowRedeems(t *testing.T) {
	fx, _ := newWaveApprovalFixture(t)
	wave, _ := fx.waveStore.CreateWave(context.Background(), MigrationWave{Name: "w"})
	issueWaveMember(t, fx, wave.ID, "ok.example.com")
	proposer := waveExecuteToken(t, fx.auth, "proposer", "pki-admin")
	approver := waveExecuteToken(t, fx.auth, "approver", "pki-operator")
	action := proposeWaveExecute(t, fx, wave.ID, proposer)

	setWaveNow(t, 23*time.Hour)
	if rec := approveWave(fx, wave.ID, action.ID, approver); rec.Code != http.StatusOK {
		t.Fatalf("approve at +23h: status = %d, want 200. body: %s", rec.Code, rec.Body.String())
	}
}

func TestWaveApproval_TTLConfig(t *testing.T) {
	t.Setenv(waveApprovalTTLEnv, "1")
	if got := waveApprovalTTL(); got != time.Hour {
		t.Fatalf("ttl = %s, want 1h", got)
	}
	fx, _ := newWaveApprovalFixture(t)
	wave, _ := fx.waveStore.CreateWave(context.Background(), MigrationWave{Name: "w"})
	proposer := waveExecuteToken(t, fx.auth, "proposer", "pki-admin")
	approver := waveExecuteToken(t, fx.auth, "approver", "pki-operator")
	action := proposeWaveExecute(t, fx, wave.ID, proposer)
	setWaveNow(t, 61*time.Minute)
	if rec := approveWave(fx, wave.ID, action.ID, approver); rec.Code != http.StatusConflict {
		t.Fatalf("approve at +61m with 1h TTL: status = %d, want 409", rec.Code)
	}
	for _, v := range []string{"abc", "-3", "0"} {
		t.Setenv(waveApprovalTTLEnv, v)
		if got := waveApprovalTTL(); got != 24*time.Hour {
			t.Fatalf("ttl for %q = %s, want 24h", v, got)
		}
	}
}

func TestWaveAudit_ProposeApproveAndMemberResults(t *testing.T) {
	fx, ap := newWaveApprovalFixture(t)
	wave, _ := fx.waveStore.CreateWave(context.Background(), MigrationWave{Name: "w"})
	fp1 := issueWaveMember(t, fx, wave.ID, "a.example.com")
	fp2 := issueWaveMember(t, fx, wave.ID, "b.example.com")
	if err := fx.waveStore.AddMember(context.Background(), wave.ID, MigrationWaveMember{Fingerprint: "does-not-exist"}); err != nil {
		t.Fatal(err)
	}
	proposer := waveExecuteToken(t, fx.auth, "proposer", "pki-admin")
	approver := waveExecuteToken(t, fx.auth, "approver", "pki-operator")
	action := proposeWaveExecute(t, fx, wave.ID, proposer)
	if rec := approveWave(fx, wave.ID, action.ID, approver); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}

	if r := auditRows(ap, "pqc.wave_execute_propose"); len(r) != 1 || r[0].Outcome != AuditOutcomeSuccess {
		t.Fatalf("propose rows = %+v", r)
	}
	if r := auditRows(ap, "pqc.wave_execute_approve"); len(r) != 1 || r[0].Outcome != AuditOutcomeSuccess {
		t.Fatalf("approve rows = %+v", r)
	}
	rows := auditRows(ap, "pqc.wave_member_result")
	if len(rows) != 3 {
		t.Fatalf("member_result rows = %d, want 3: %+v", len(rows), rows)
	}
	byFP := map[string]AuditEntry{}
	for _, e := range rows {
		for _, tok := range strings.Fields(e.ChangeSummary) {
			if v, ok := strings.CutPrefix(tok, "fingerprint="); ok {
				byFP[v] = e
			}
		}
	}
	for _, fp := range []string{fp1, fp2} {
		e, ok := byFP[fp]
		if !ok || e.Outcome != AuditOutcomeSuccess || !strings.Contains(e.ChangeSummary, "status=migrated") {
			t.Errorf("member %s row = %+v", fp, e)
		}
	}
	if e, ok := byFP["does-not-exist"]; !ok || e.Outcome != AuditOutcomeFailure || !strings.Contains(e.ChangeSummary, "status=failed") {
		t.Errorf("missing member row = %+v", e)
	}
}

func TestWaveAlert_OnMemberFailureAndRegression(t *testing.T) {
	np := &diffFakeNotifications{rules: []NotificationRule{
		{ID: "r1", Channel: "email", Target: "ops@example.com", Enabled: true},
		{ID: "r2", Channel: "slack", Target: "#off", Enabled: false},
	}}
	old := waveAlertProvider
	waveAlertProvider = func() NotificationProvider { return np }
	t.Cleanup(func() { waveAlertProvider = old })

	// All-success run: no alert.
	fx, _ := newWaveApprovalFixture(t)
	ok, _ := fx.waveStore.CreateWave(context.Background(), MigrationWave{Name: "ok"})
	issueWaveMember(t, fx, ok.ID, "fine.example.com")
	proposer := waveExecuteToken(t, fx.auth, "proposer", "pki-admin")
	approver := waveExecuteToken(t, fx.auth, "approver", "pki-operator")
	a1 := proposeWaveExecute(t, fx, ok.ID, proposer)
	if rec := approveWave(fx, ok.ID, a1.ID, approver); rec.Code != http.StatusOK {
		t.Fatalf("approve ok wave: %d %s", rec.Code, rec.Body.String())
	}
	if len(np.delivered) != 0 {
		t.Fatalf("all-success run alerted: %v", np.delivered)
	}

	// Member failure: one alert to the single enabled rule.
	bad, _ := fx.waveStore.CreateWave(context.Background(), MigrationWave{Name: "bad"})
	if err := fx.waveStore.AddMember(context.Background(), bad.ID, MigrationWaveMember{Fingerprint: "does-not-exist"}); err != nil {
		t.Fatal(err)
	}
	a2 := proposeWaveExecute(t, fx, bad.ID, proposer)
	if rec := approveWave(fx, bad.ID, a2.ID, approver); rec.Code != http.StatusOK {
		t.Fatalf("approve bad wave: %d %s", rec.Code, rec.Body.String())
	}
	if len(np.delivered) != 1 || !strings.Contains(np.delivered[0], "pqc_wave.member_failed") || !strings.HasPrefix(np.delivered[0], "email|ops@example.com|") {
		t.Fatalf("member-failure deliveries: %v", np.delivered)
	}

	// Regression: through the hook directly.
	ap := &recordingAuditProvider{}
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	newWaveHooks(req, AuthPrincipal{ID: "approver"}, nil, ap).WaveOutcome("wave-r", migrateWaveExecutionResult{Regressed: true, Failed: 1})
	if len(np.delivered) != 2 || !strings.Contains(np.delivered[1], "pqc_wave.regressed") {
		t.Fatalf("regression deliveries: %v", np.delivered)
	}
	if r := auditRows(ap, "pqc.wave_regressed"); len(r) != 1 || r[0].Outcome != AuditOutcomeFailure {
		t.Fatalf("regressed rows = %+v", r)
	}
	// A non-regressed outcome stays silent.
	newWaveHooks(req, AuthPrincipal{ID: "approver"}, nil, ap).WaveOutcome("wave-r", migrateWaveExecutionResult{})
	if len(np.delivered) != 2 {
		t.Fatalf("non-regressed outcome alerted: %v", np.delivered)
	}
}
