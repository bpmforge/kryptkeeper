// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

type fakeCASvc struct {
	ca.Service
	cas       []*ca.CA
	listErr   error
	rootCalls int
}

func (f *fakeCASvc) ListCAs() ([]*ca.CA, error) { return f.cas, f.listErr }
func (f *fakeCASvc) CreateRootCA(string, pkix.Name, keystore.Algorithm, time.Duration) (*ca.CA, error) {
	f.rootCalls++
	return &ca.CA{ID: "new-root"}, nil
}

func TestAttachPolicyEngineFailureIsFatalUnlessAllowed(t *testing.T) {
	// A nil DB is how NewPolicyEngine fails; it must not be swallowed.
	engine := ca.NewEngine(nil, ca.NewMemStore())
	err := attachPolicyEngine(engine, nil, false, envMap(nil))
	if err == nil || !strings.Contains(err.Error(), "KRYPTKEEPER_ALLOW_NO_POLICY") {
		t.Fatalf("want fatal error naming the escape hatch, got %v", err)
	}
	if err := attachPolicyEngine(engine, nil, false, envMap(map[string]string{"KRYPTKEEPER_ALLOW_NO_POLICY": "true"})); err != nil {
		t.Fatalf("explicit opt-out must downgrade to a warning, got %v", err)
	}
}

func TestResolveDefaultCAListErrorDoesNotMintRoot(t *testing.T) {
	svc := &fakeCASvc{listErr: errors.New("db locked")}
	_, err := resolveDefaultCA(svc, envMap(map[string]string{"KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT": "true"}))
	if err == nil {
		t.Fatal("ListCAs error must be fatal")
	}
	if svc.rootCalls != 0 {
		t.Fatalf("a second root was minted after a transient ListCAs error (%d calls)", svc.rootCalls)
	}
}

func TestResolveDefaultCA(t *testing.T) {
	t.Run("explicit id wins", func(t *testing.T) {
		svc := &fakeCASvc{listErr: errors.New("unused")}
		id, err := resolveDefaultCA(svc, envMap(map[string]string{"KRYPTKEEPER_DEFAULT_CA_ID": "ca-x"}))
		if err != nil || id != "ca-x" {
			t.Fatalf("got %q, %v", id, err)
		}
	})
	t.Run("first existing CA", func(t *testing.T) {
		svc := &fakeCASvc{cas: []*ca.CA{{ID: "ca-1"}, {ID: "ca-2"}}}
		id, err := resolveDefaultCA(svc, envMap(nil))
		if err != nil || id != "ca-1" || svc.rootCalls != 0 {
			t.Fatalf("got %q, %v, roots=%d", id, err, svc.rootCalls)
		}
	})
	t.Run("empty without flag is an error", func(t *testing.T) {
		svc := &fakeCASvc{}
		_, err := resolveDefaultCA(svc, envMap(nil))
		if err == nil || svc.rootCalls != 0 {
			t.Fatalf("want error and no root, got %v roots=%d", err, svc.rootCalls)
		}
		if !strings.Contains(err.Error(), "KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true") || !strings.Contains(err.Error(), ".env") {
			t.Fatalf("error must tell compose users which .env line to add, got %q", err)
		}
	})
	t.Run("flag left set never mints a second root", func(t *testing.T) {
		svc := &fakeCASvc{cas: []*ca.CA{{ID: "ca-1"}}}
		id, err := resolveDefaultCA(svc, envMap(map[string]string{"KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT": "true"}))
		if err != nil || id != "ca-1" || svc.rootCalls != 0 {
			t.Fatalf("got %q, %v, roots=%d", id, err, svc.rootCalls)
		}
	})
	for _, v := range []string{"true", "TRUE", "1"} {
		t.Run("bootstrap flag "+v, func(t *testing.T) {
			svc := &fakeCASvc{}
			id, err := resolveDefaultCA(svc, envMap(map[string]string{"KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT": v}))
			if err != nil || id != "new-root" || svc.rootCalls != 1 {
				t.Fatalf("got %q, %v, roots=%d", id, err, svc.rootCalls)
			}
		})
	}
}
