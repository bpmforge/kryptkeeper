// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// The CA-compromise flow must flag certificates through the REAL provider and
// schema: lifecycleFakeCertProvider once accepted "reissue_required" while the
// provider validator and the renewal_status CHECK constraint both rejected it.
func TestCompromiseFlowFlagsCertsThroughRealProviderAndSchema(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	caID := getFirstCAID(t, engine)

	var fps []string
	for _, cn := range []string{"a.example.com", "b.example.com"} {
		res, err := provider.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, CSRPEM: generateTestCSRPEM(t, cn, cn)})
		if err != nil {
			t.Fatalf("issue %s: %v", cn, err)
		}
		fps = append(fps, res.FingerprintSHA256)
	}

	store, err := keystore.NewSoftwareStore(t.TempDir(), []byte("lifecycle-test-passphrase-32-by!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	if _, err := store.GenerateKey("burned", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	caStore := ca.NewMemStore()
	if err := caStore.Save(&ca.CA{ID: caID, KeyID: "burned", Status: "active"}); err != nil {
		t.Fatalf("save ca: %v", err)
	}
	m, err := NewKeyLifecycleManager(db, false, store,
		WithLifecycleCARotation(&recordingRotator{}, caStore),
		WithLifecycleReissue(provider, &countingReissuer{}))
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	if err := m.SetPolicy("burned", "alice", nil, 0); err != nil {
		t.Fatalf("policy: %v", err)
	}

	report, err := m.MarkCompromised(ctx, "burned")
	if err != nil {
		t.Fatalf("compromise: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Fatalf("flagging must succeed against the real provider and schema: %v", report.Errors)
	}
	for _, fp := range fps {
		var status string
		if err := db.QueryRow(`SELECT renewal_status FROM certificates WHERE fingerprint_sha256 = ?`, fp).Scan(&status); err != nil {
			t.Fatalf("read back %s: %v", fp, err)
		}
		if status != "reissue_required" {
			t.Fatalf("cert %s persisted renewal_status=%q, want reissue_required", fp, status)
		}
	}
}
