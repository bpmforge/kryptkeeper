// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"strings"
	"testing"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

func TestParseAlgorithmAcceptsMLDSASpellings(t *testing.T) {
	cases := map[string]keystore.Algorithm{
		"ML-DSA-44":  keystore.MLDSA44,
		"ML-DSA-65":  keystore.MLDSA65,
		"ml-dsa-65":  keystore.MLDSA65,
		"mldsa65":    keystore.MLDSA65,
		"MLDSA87":    keystore.MLDSA87,
		"ml_dsa_87":  keystore.MLDSA87,
		"ECDSA-P256": keystore.ECDSAP256,
		"rsa-4096":   keystore.RSA4096,
	}
	for in, want := range cases {
		got, err := parseAlgorithm(in)
		if err != nil || got != want {
			t.Errorf("parseAlgorithm(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestParseAlgorithmRejectionNamesSupportedSet(t *testing.T) {
	_, err := parseAlgorithm("ML-DSA-99")
	if err == nil || !strings.Contains(err.Error(), "ML-DSA-65") {
		t.Fatalf("want an error listing the supported algorithms, got %v", err)
	}
}

// ML-DSA CAs are supported by the engine on the software key backend; the API
// used to reject every spelling because parseAlgorithm lacked the cases.
func TestCreateCAMLDSARootAndIntermediate(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-ca-passphrase-32chars-min!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	provider := NewEngineCAProvider(ca.NewEngine(keys, ca.NewMemStore()))

	root, err := provider.CreateCA(context.Background(), CACreateRequest{
		Name: "pqc-root", Type: "root", Algorithm: "ML-DSA-65", SubjectCN: "PQC Root",
	})
	if err != nil {
		t.Fatalf("create ML-DSA-65 root: %v", err)
	}
	if root.ID == "" {
		t.Fatal("root has no id")
	}
	if _, err := provider.CreateCA(context.Background(), CACreateRequest{
		Name: "pqc-int", Type: "intermediate", Algorithm: "mldsa65", SubjectCN: "PQC Intermediate", ParentCAID: root.ID,
	}); err != nil {
		t.Fatalf("create ML-DSA-65 intermediate: %v", err)
	}
}
