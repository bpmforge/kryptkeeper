// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// W23-34: CA revocation under always-on dual control, and DeleteCA for
// revoked/expired CAs. alice proposes, bob approves.

type revokeEnv struct {
	*importEnv
	root, inter *ca.CA
	rs          *ca.MemRevocationStore
	counts      map[string]int
	inv         *serialInvalidator
}

type serialInvalidator struct {
	serials []string
	all     int
}

func (s *serialInvalidator) InvalidateAll() { s.all++ }

func newRevokeEnv(t *testing.T) *revokeEnv {
	t.Helper()
	e := newImportEnv(t, "false") // the env bypass must NOT weaken CA revoke
	root, err := e.engine.CreateRootCA("Revoke Root", pkix.Name{CommonName: "Revoke Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := e.engine.CreateIntermediateCA("Revoke Inter", pkix.Name{CommonName: "Revoke Inter"}, keystore.ECDSAP256, root.ID, 5*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	env := &revokeEnv{importEnv: e, root: root, inter: inter, rs: ca.NewMemRevocationStore(), counts: map[string]int{}}
	env.inv = &serialInvalidator{}
	provider := NewEngineCAProviderWithCounts(e.engine, func(context.Context) (map[string]int, error) { return env.counts, nil })
	if !AttachRevocation(provider, env.rs, invalidatorAdapter{env.inv}) {
		t.Fatal("AttachRevocation refused the engine provider")
	}
	mux := http.NewServeMux()
	registerCAHandlers(mux, e.auth, provider, NewTenantStoreFromEnv(), e.audit)
	registerPendingActionHandlers(mux, e.auth, NewFileCertificateProviderFromEnv(), NewPendingActionStoreFromEnv(), e.audit,
		map[string]ActionExecutor{ActionCARevoke: NewCARevokeExecutor(provider, e.audit)}, e.keys)
	e.mux = mux
	return env
}

type invalidatorAdapter struct{ s *serialInvalidator }

func (a invalidatorAdapter) InvalidateCache(serial *big.Int) {
	a.s.serials = append(a.s.serials, serial.String())
}
func (a invalidatorAdapter) InvalidateAll() { a.s.InvalidateAll() }

func (e *revokeEnv) propose(t *testing.T, id string) string {
	t.Helper()
	rec := e.do(e.alice, http.MethodPost, "/api/v1/cas/"+id+"/revoke", map[string]any{})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("propose revoke: want 202, got %d: %s", rec.Code, rec.Body.String())
	}
	return actionID(t, rec)
}

func (e *revokeEnv) revokeFully(t *testing.T, id string) {
	t.Helper()
	act := e.propose(t, id)
	if rec := e.do(e.bob, http.MethodPost, "/api/v1/pending-actions/"+act+"/approve", nil); rec.Code != http.StatusOK {
		t.Fatalf("approve revoke: %d %s", rec.Code, rec.Body.String())
	}
}

func (e *revokeEnv) status(t *testing.T, id string) string {
	t.Helper()
	c, err := e.engine.GetCA(id)
	if err != nil {
		t.Fatal(err)
	}
	return c.Status
}

func TestCARevokeProposesOnly(t *testing.T) {
	e := newRevokeEnv(t)
	e.propose(t, e.inter.ID)
	if got := e.status(t, e.inter.ID); got != "active" {
		t.Fatalf("a proposal must not revoke: status %q", got)
	}
	if l, _ := e.rs.ListRevoked(e.root.ID); len(l) != 0 {
		t.Fatalf("a proposal must not write a revocation row: %v", l)
	}
	if !e.audited("ca.revoke", AuditOutcomeProposed) {
		t.Fatal("proposal must be audited")
	}
}

func TestCARevokeNeedsSecondHuman(t *testing.T) {
	e := newRevokeEnv(t)
	act := e.propose(t, e.inter.ID)
	if rec := e.do(e.alice, http.MethodPost, "/api/v1/pending-actions/"+act+"/approve", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("self-approval: want 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := e.status(t, e.inter.ID); got != "active" {
		t.Fatalf("self-approval must not revoke: status %q", got)
	}
	if rec := e.do(e.bob, http.MethodPost, "/api/v1/pending-actions/"+act+"/approve", nil); rec.Code != http.StatusOK {
		t.Fatalf("second admin approve: %d %s", rec.Code, rec.Body.String())
	}
	if got := e.status(t, e.inter.ID); got != "revoked" {
		t.Fatalf("status after approval: %q", got)
	}
	if rec := e.do(e.alice, http.MethodPost, "/api/v1/cas/"+e.inter.ID+"/revoke", map[string]any{}); rec.Code != http.StatusConflict {
		t.Fatalf("re-revoke: want 409, got %d", rec.Code)
	}
}

func TestCARevokeNonAdmin403(t *testing.T) {
	e := newRevokeEnv(t)
	_, tok, err := e.auth.CreateAPIKeyAs("", "viewer-key", "viewer", "viewer", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rec := e.do(tok, http.MethodPost, "/api/v1/cas/"+e.inter.ID+"/revoke", map[string]any{}); rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if !e.audited("ca.revoke", AuditOutcomeDenied) {
		t.Fatal("denial must be audited")
	}
}

func TestCARevokeRejectsOtherReasonsAndMethods(t *testing.T) {
	e := newRevokeEnv(t)
	if rec := e.do(e.alice, http.MethodPost, "/api/v1/cas/"+e.inter.ID+"/revoke", map[string]any{"reason": "superseded"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("other reason: want 400, got %d", rec.Code)
	}
	if rec := e.do(e.alice, http.MethodGet, "/api/v1/cas/"+e.inter.ID+"/revoke", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: want 405, got %d", rec.Code)
	}
	if rec := e.do(e.alice, http.MethodPost, "/api/v1/cas/nope/revoke", map[string]any{}); rec.Code != http.StatusNotFound {
		t.Fatalf("missing CA: want 404, got %d", rec.Code)
	}
}

func TestCARevokeAuditHasBlastRadius(t *testing.T) {
	e := newRevokeEnv(t)
	e.counts[e.root.ID] = 1
	e.counts[e.inter.ID] = 4
	e.revokeFully(t, e.root.ID)
	e.audit.mu.Lock()
	defer e.audit.mu.Unlock()
	var proposed, executed string
	for _, en := range e.audit.entries {
		if en.Action != "ca.revoke" {
			continue
		}
		switch en.Outcome {
		case AuditOutcomeProposed:
			proposed = en.ChangeSummary
		case AuditOutcomeExecuted:
			executed = en.ChangeSummary
		}
	}
	for _, sum := range []string{proposed, executed} {
		for _, want := range []string{`"blast_radius"`, `"affected_certs":5`, `"descendant_cas":1`, "cACompromise"} {
			if !strings.Contains(sum, want) {
				t.Fatalf("change summary %q lacks %s", sum, want)
			}
		}
	}
}

func TestCARevokeIntermediateWritesParentCRLRow(t *testing.T) {
	e := newRevokeEnv(t)
	e.revokeFully(t, e.inter.ID)
	list, _ := e.rs.ListRevoked(e.root.ID)
	if len(list) != 1 || list[0].Serial.Cmp(e.inter.Certificate.SerialNumber) != 0 || list[0].ReasonCode != 2 {
		t.Fatalf("parent CRL rows: %+v", list)
	}
	if len(e.inv.serials) != 1 || e.inv.all != 1 {
		t.Fatalf("caches not invalidated: %+v", e.inv)
	}
}

func TestCARevokeRootIsStatusOnly(t *testing.T) {
	e := newRevokeEnv(t)
	e.revokeFully(t, e.root.ID)
	if got := e.status(t, e.root.ID); got != "revoked" {
		t.Fatalf("root status %q", got)
	}
	self, _ := e.rs.ListRevoked(e.root.ID)
	if len(self) != 1 || self[0].Serial.Cmp(e.root.Certificate.SerialNumber) != 0 {
		t.Fatalf("want one self-keyed record, got %+v", self)
	}
	if other, _ := e.rs.ListRevoked(e.inter.ID); len(other) != 0 {
		t.Fatalf("no other CA may gain a revocation row: %+v", other)
	}
}

func issueFrom(t *testing.T, e *revokeEnv, caID string) error {
	t.Helper()
	block, _ := pem.Decode([]byte(generateTestCSRPEM(t, "leaf.example.com")))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.engine.IssueCertificate(caID, ca.IssuanceRequest{CSR: csr, Validity: time.Hour, KeyUsage: x509.KeyUsageDigitalSignature})
	return err
}

func TestRevokedCAIssuanceRefused(t *testing.T) {
	e := newRevokeEnv(t)
	if err := issueFrom(t, e, e.inter.ID); err != nil {
		t.Fatalf("active CA must issue: %v", err)
	}
	e.revokeFully(t, e.root.ID)
	for _, id := range []string{e.root.ID, e.inter.ID} { // inter: parent revoked
		if err := issueFrom(t, e, id); !errors.Is(err, ca.ErrCARevoked) {
			t.Fatalf("issue from %s under a revoked chain: want ErrCARevoked, got %v", id, err)
		}
	}
}

func TestDeleteCA(t *testing.T) {
	e := newRevokeEnv(t)
	del := func(id string) int {
		return e.do(e.alice, http.MethodDelete, "/api/v1/cas/"+id, nil).Code
	}
	if c := del(e.inter.ID); c != http.StatusUnprocessableEntity {
		t.Fatalf("active CA: want 422, got %d", c)
	}
	e.revokeFully(t, e.inter.ID)
	e.counts[e.inter.ID] = 2
	if c := del(e.inter.ID); c != http.StatusConflict {
		t.Fatalf("revoked CA with active certs: want 409, got %d", c)
	}
	e.counts[e.inter.ID] = 0
	if c := del(e.root.ID); c != http.StatusUnprocessableEntity {
		t.Fatalf("active root: want 422, got %d", c)
	}
	if c := del(e.inter.ID); c != http.StatusNoContent {
		t.Fatalf("revoked CA: want 204, got %d", c)
	}
	if _, err := e.engine.GetCA(e.inter.ID); !errors.Is(err, ca.ErrCANotFound) {
		t.Fatalf("deleted CA must be gone: %v", err)
	}
	// An expired root with no children is deletable.
	if err := e.store.UpdateStatus(e.root.ID, "expired"); err != nil {
		t.Fatal(err)
	}
	e.engine.UpdateCAStatus(e.root.ID, "expired")
	if c := del(e.root.ID); c != http.StatusNoContent {
		t.Fatalf("expired CA: want 204, got %d", c)
	}
}

func TestDeleteCARefusedWithChildren(t *testing.T) {
	e := newRevokeEnv(t)
	e.revokeFully(t, e.root.ID)
	if c := e.do(e.alice, http.MethodDelete, "/api/v1/cas/"+e.root.ID, nil).Code; c != http.StatusConflict {
		t.Fatalf("revoked root with a child CA: want 409, got %d", c)
	}
}
