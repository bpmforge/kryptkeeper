// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// W23-15: rotate-key is dual-controlled and ?mode=cross-sign exposes the
// cross-signed rollover. alice proposes, bob approves.

type rotateEnv struct {
	*importEnv
	root *ca.CA
}

func newRotateEnv(t *testing.T) *rotateEnv {
	t.Helper()
	e := newImportEnv(t, "unset") // D-122 default: dual control on
	root, err := e.engine.CreateRootCA("Rollover Root", pkix.Name{CommonName: "Rollover Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	return &rotateEnv{importEnv: e, root: root}
}

func (e *rotateEnv) path(mode string) string {
	p := "/api/v1/cas/" + e.root.ID + "/rotate-key"
	if mode != "" {
		p += "?mode=" + mode
	}
	return p
}

// approvedGrant proposes as alice and has bob approve; returns the action id.
func (e *rotateEnv) approvedGrant(t *testing.T, mode string) string {
	t.Helper()
	rec := e.do(e.alice, http.MethodPost, e.path(mode), map[string]any{})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("propose: want 202, got %d: %s", rec.Code, rec.Body.String())
	}
	id := actionID(t, rec)
	if rec := e.do(e.bob, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	return id
}

func (e *rotateEnv) leaf(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(generateTestCSRPEM(t, cn)))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := e.engine.IssueCertificate(e.root.ID, ca.IssuanceRequest{CSR: csr, Validity: time.Hour, KeyUsage: x509.KeyUsageDigitalSignature})
	if err != nil {
		t.Fatalf("issue %s: %v", cn, err)
	}
	return issued.Certificate
}

func parseCertPEM(t *testing.T, s string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRotateKey_DualControlOn_Returns202WithActionID(t *testing.T) {
	e := newRotateEnv(t)
	before := e.root.Certificate.Raw
	rec := e.do(e.alice, http.MethodPost, e.path("cross-sign"), map[string]any{})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", rec.Code, rec.Body.String())
	}
	_ = actionID(t, rec)
	after, _ := e.engine.GetCA(e.root.ID)
	if string(after.Certificate.Raw) != string(before) {
		t.Fatal("a proposal must not rotate the CA")
	}
	if !e.audited("ca.rotate_key", AuditOutcomeProposed) {
		t.Fatal("proposal must be audited")
	}
}

func TestRotateKey_ProposerCannotApproveOwn(t *testing.T) {
	e := newRotateEnv(t)
	id := actionID(t, e.do(e.alice, http.MethodPost, e.path("cross-sign"), map[string]any{}))
	if rec := e.do(e.alice, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("self-approval: want 403, got %d: %s", rec.Code, rec.Body.String())
	}
	// Unapproved grant must not redeem.
	rec := e.do(e.alice, http.MethodPost, e.path("cross-sign"), map[string]any{"approved_action_id": id})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("redeem unapproved: want 403, got %d", rec.Code)
	}
}

func TestRotateKey_CrossSign_AfterApproval_ProbeLeafBothAnchors(t *testing.T) {
	e := newRotateEnv(t)
	pre := e.leaf(t, "pre-rotation.example.com")
	oldCert := e.root.Certificate

	id := e.approvedGrant(t, "cross-sign")
	rec := e.do(e.alice, http.MethodPost, e.path("cross-sign"), map[string]any{"approved_action_id": id})
	if rec.Code != http.StatusOK {
		t.Fatalf("redeem: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data CAKeyRollover `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	cross := parseCertPEM(t, resp.Data.CrossCertPEM)
	oldFromResp := parseCertPEM(t, resp.Data.OldCertPEM)
	if resp.Data.OldKeyID == "" || resp.Data.LedgerID == "" {
		t.Fatalf("old_key_id and ledger_id must be set: %+v", resp.Data)
	}
	newCA, _ := e.engine.GetCA(e.root.ID)

	post := e.leaf(t, "post-rotation.example.com")
	newRoots := x509.NewCertPool()
	newRoots.AddCert(newCA.Certificate)
	if _, err := post.Verify(x509.VerifyOptions{Roots: newRoots}); err != nil {
		t.Fatalf("new leaf must verify against the new root: %v", err)
	}
	oldRoots := x509.NewCertPool()
	oldRoots.AddCert(oldFromResp)
	bridge := x509.NewCertPool()
	bridge.AddCert(cross)
	if _, err := post.Verify(x509.VerifyOptions{Roots: oldRoots, Intermediates: bridge}); err != nil {
		t.Fatalf("new leaf must verify against the OLD root via the cross cert: %v", err)
	}
	// The new leaf must NOT verify against the old root without the bridge.
	if _, err := post.Verify(x509.VerifyOptions{Roots: oldRoots}); err == nil {
		t.Fatal("new leaf verified against the old root with no bridge: the negative control failed")
	}
	if _, err := pre.Verify(x509.VerifyOptions{Roots: oldRoots}); err != nil {
		t.Fatalf("pre-rotation leaf must still verify against the old root: %v", err)
	}
	if string(oldFromResp.Raw) != string(oldCert.Raw) {
		t.Fatal("old_cert_pem must be the pre-rotation certificate")
	}
	if !e.audited("ca.rotate_key", AuditOutcomeSuccess) {
		t.Fatal("rotation must be audited")
	}
}

func TestRotateKey_NonAdminGets403(t *testing.T) {
	e := newRotateEnv(t)
	_, token, err := e.auth.CreateAPIKey("non-admin", "team-1", "service-account", []string{"read:certs"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"", "cross-sign"} {
		if rec := e.do(token, http.MethodPost, e.path(mode), map[string]any{}); rec.Code != http.StatusForbidden {
			t.Fatalf("mode %q: want 403, got %d", mode, rec.Code)
		}
	}
}

func TestRotateKey_GrantIsSingleUse(t *testing.T) {
	e := newRotateEnv(t)
	id := e.approvedGrant(t, "cross-sign")
	body := map[string]any{"approved_action_id": id}
	if rec := e.do(e.alice, http.MethodPost, e.path("cross-sign"), body); rec.Code != http.StatusOK {
		t.Fatalf("first redeem: %d %s", rec.Code, rec.Body.String())
	}
	rec := e.do(e.alice, http.MethodPost, e.path("cross-sign"), body)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "single-use") {
		t.Fatalf("second redeem: want 403 single-use, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRotateKey_GrantBoundToModeAndAlgorithm(t *testing.T) {
	e := newRotateEnv(t)
	id := e.approvedGrant(t, "cross-sign")
	// A cross-sign grant must not authorise a plain re-key, nor a different algorithm.
	for name, tc := range map[string]struct {
		mode string
		body map[string]any
	}{
		"other mode":      {"rekey", map[string]any{"approved_action_id": id}},
		"other algorithm": {"cross-sign", map[string]any{"approved_action_id": id, "algorithm": "ECDSA-P384"}},
	} {
		if rec := e.do(e.alice, http.MethodPost, e.path(tc.mode), tc.body); rec.Code != http.StatusForbidden {
			t.Fatalf("%s: want 403, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}
	after, _ := e.engine.GetCA(e.root.ID)
	if string(after.Certificate.Raw) != string(e.root.Certificate.Raw) {
		t.Fatal("a refused redemption must not rotate the CA")
	}
}

func TestRotateKey_UnknownModeIs400(t *testing.T) {
	e := newRotateEnv(t)
	rec := e.do(e.alice, http.MethodPost, e.path("bogus"), map[string]any{})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "mode must be rekey or cross-sign") {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRotateKey_RekeyModeAlsoDualControlled(t *testing.T) {
	e := newRotateEnv(t)
	rec := e.do(e.alice, http.MethodPost, e.path(""), map[string]any{})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("plain rotate-key with dual control on: want 202, got %d: %s", rec.Code, rec.Body.String())
	}
}

// W23-16: a rotation that fails and is rolled back is audited and answered 503.
func TestRotateKey_RolledBackIsAuditedAnd503(t *testing.T) {
	e := newImportEnv(t, "false")
	root, err := e.engine.CreateRootCA("RB Root", pkix.Name{CommonName: "RB Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	e.engine.SetRotationFaultHook(func(s ca.RotateStep) error {
		if s == ca.StepProbeVerify {
			return errors.New("forced")
		}
		return nil
	})
	for _, mode := range []string{"rekey", "cross-sign"} {
		rec := e.do(e.alice, http.MethodPost, "/api/v1/cas/"+root.ID+"/rotate-key?mode="+mode, map[string]any{})
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "rolled back") {
			t.Fatalf("%s: want 503 rolled back, got %d: %s", mode, rec.Code, rec.Body.String())
		}
	}
	if !e.audited("ca.rotate_key_rollback", AuditOutcomeFailure) {
		t.Fatal("rollback must be audited as ca.rotate_key_rollback")
	}
	after, _ := e.engine.GetCA(root.ID)
	if string(after.Certificate.Raw) != string(root.Certificate.Raw) {
		t.Fatal("rolled-back rotation changed the CA certificate")
	}
}
