// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"kryptkeeper/internal/egress"
)

// SEMGREP-002: the stored credential travels as a custom header; a redirect
// to another host must not carry it there.
func TestInventorySourceDoesNotLeakCredentialAcrossRedirect(t *testing.T) {
	leaked := ""
	thief := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("X-DC-DEVKEY")
	}))
	defer thief.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, thief.URL+"/collect", http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()

	creds := &renewalFakeCredStore{
		meta:    OutboundCredentialMeta{ID: "cred-dc", CredentialType: CredentialTypeAPIToken},
		payload: []byte("super-secret-key"),
	}
	source, err := buildInventorySource(context.Background(), InventorySourceRecord{
		ID: "invsrc-x", Type: "digicert",
		ConfigJSON: `{"base_url":"` + upstream.URL + `"}`, CredentialRef: "cred-dc",
	}, creds)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	_, err = source.Fetch(context.Background())
	if !errors.Is(err, egress.ErrBlockedDestination) {
		t.Fatalf("cross-host redirect must be refused, got %v", err)
	}
	if leaked != "" {
		t.Fatalf("credential leaked to redirect target: %q", leaked)
	}
}

func TestInventorySourceRefusesMetadataBaseURL(t *testing.T) {
	creds := &renewalFakeCredStore{
		meta:    OutboundCredentialMeta{ID: "cred-dc", CredentialType: CredentialTypeAPIToken},
		payload: []byte("k"),
	}
	source, err := buildInventorySource(context.Background(), InventorySourceRecord{
		ID: "invsrc-m", Type: "digicert",
		ConfigJSON: `{"base_url":"http://169.254.169.254"}`, CredentialRef: "cred-dc",
	}, creds)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := source.Fetch(context.Background()); !errors.Is(err, egress.ErrBlockedDestination) {
		t.Fatalf("metadata base_url must be refused, got %v", err)
	}
}
