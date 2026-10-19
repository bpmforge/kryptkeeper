// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"testing"
	"time"

	"crypto/x509/pkix"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

func TestCAListItemRevocationSigning(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("revsigning-test-passphrase-32ch!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	for _, tc := range []struct {
		algo keystore.Algorithm
		want string
	}{
		{keystore.MLDSA65, "ml-dsa"},
		{keystore.ECDSAP256, "classical"},
	} {
		c, err := engine.CreateRootCA("rs-"+string(tc.algo), pkix.Name{CommonName: "rs-" + string(tc.algo)}, tc.algo, 24*time.Hour)
		if err != nil {
			t.Fatalf("%s: %v", tc.algo, err)
		}
		if got := caToListItem(c).RevocationSigning; got != tc.want {
			t.Errorf("%s: revocation_signing = %q, want %q", tc.algo, got, tc.want)
		}
	}
}
