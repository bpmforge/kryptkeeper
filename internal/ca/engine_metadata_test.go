// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509/pkix"
	"errors"
	"reflect"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

func metaEngine(t *testing.T, store Store) (*Engine, keystore.Store) {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-ca-passphrase-32chars-min!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	return NewEngine(keys, store), keys
}

func metaRoot(t *testing.T, e *Engine) *CA {
	t.Helper()
	root, err := e.CreateRootCA("Meta Root", pkix.Name{CommonName: "Meta Root"}, keystore.ECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	return root
}

func strp(s string) *string { return &s }

// The bug this guards: the PATCH edit lived only on the engine's cached
// struct, so a restart (a new Engine over the same store) lost it.
func TestUpdateCAMetadataSurvivesNewEngine(t *testing.T) {
	stores := map[string]func(t *testing.T) Store{
		"mem":    func(*testing.T) Store { return NewMemStore() },
		"sqlite": func(t *testing.T) Store { return NewDBStore(newTestDB(t), false) },
	}
	for name, mk := range stores {
		t.Run(name, func(t *testing.T) {
			store := mk(t)
			e, keys := metaEngine(t, store)
			root := metaRoot(t, e)

			crl := []string{"http://crl.example/a.crl", "ldap://dir.example/cn=x"}
			got, err := e.UpdateCAMetadata(root.ID, strp("Renamed"), &crl, strp("http://ocsp.example"))
			if err != nil {
				t.Fatalf("UpdateCAMetadata: %v", err)
			}
			if got.Name != "Meta Root" || got.DisplayName != "Renamed" {
				t.Fatalf("name must stay immutable, display change: %+v", got)
			}

			reloaded, err := NewEngine(keys, store).GetCA(root.ID)
			if err != nil {
				t.Fatalf("GetCA after restart: %v", err)
			}
			if reloaded.Name != "Meta Root" || reloaded.DisplayName != "Renamed" ||
				!reflect.DeepEqual(reloaded.CRLDistributionPoints, crl) ||
				reloaded.OCSPServiceURL != "http://ocsp.example" {
				t.Fatalf("metadata lost across restart: %+v", reloaded)
			}

			// An empty OCSP string clears it; nil fields are left alone.
			if _, err := e.UpdateCAMetadata(root.ID, nil, nil, strp("")); err != nil {
				t.Fatalf("clear ocsp: %v", err)
			}
			again, _ := NewEngine(keys, store).GetCA(root.ID)
			if again.OCSPServiceURL != "" || again.DisplayName != "Renamed" || len(again.CRLDistributionPoints) != 2 {
				t.Fatalf("clear/partial update wrong: %+v", again)
			}
		})
	}
}

func TestUpdateCAMetadataNotFound(t *testing.T) {
	e, _ := metaEngine(t, NewMemStore())
	if _, err := e.UpdateCAMetadata("nope", strp("x"), nil, nil); !errors.Is(err, ErrCANotFound) {
		t.Fatalf("want ErrCANotFound, got %v", err)
	}
}

func TestUpdateCAMetadataExternalCARefusesRevocationPointers(t *testing.T) {
	store := NewMemStore()
	if err := store.Save(&CA{ID: "ext-1", Name: "Ext", Type: CATypeExternal, Status: "active", ConnectorID: "c1"}); err != nil {
		t.Fatal(err)
	}
	e, _ := metaEngine(t, store)

	crl := []string{"http://crl.example"}
	if _, err := e.UpdateCAMetadata("ext-1", nil, &crl, nil); !errors.Is(err, ErrExternalRevocationPointers) {
		t.Fatalf("crl: want ErrExternalRevocationPointers, got %v", err)
	}
	if _, err := e.UpdateCAMetadata("ext-1", nil, nil, strp("http://ocsp.example")); !errors.Is(err, ErrExternalRevocationPointers) {
		t.Fatalf("ocsp: want ErrExternalRevocationPointers, got %v", err)
	}
	got, err := e.UpdateCAMetadata("ext-1", strp("Upstream label"), nil, nil)
	if err != nil || got.DisplayName != "Upstream label" {
		t.Fatalf("display name must stay editable: %+v, %v", got, err)
	}
}

func TestUpdateCAMetadataDoesNotAliasSlices(t *testing.T) {
	e, _ := metaEngine(t, NewMemStore())
	root := metaRoot(t, e)

	in := []string{"http://crl.example/a"}
	out, err := e.UpdateCAMetadata(root.ID, nil, &in, nil)
	if err != nil {
		t.Fatal(err)
	}
	in[0] = "http://mutated-input"
	out.CRLDistributionPoints[0] = "http://mutated-output"

	cached, _ := e.GetCA(root.ID)
	if cached.CRLDistributionPoints[0] != "http://crl.example/a" {
		t.Fatalf("caller mutation reached the cache: %v", cached.CRLDistributionPoints)
	}
	loaded, _ := e.store.Load(root.ID)
	loaded.CRLDistributionPoints[0] = "http://mutated-load"
	again, _ := e.store.Load(root.ID)
	if again.CRLDistributionPoints[0] != "http://crl.example/a" {
		t.Fatalf("MemStore returned an aliased slice: %v", again.CRLDistributionPoints)
	}
}
