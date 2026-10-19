// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"kryptkeeper/internal/egress"
)

// M-1: pushers built without a client must not reach metadata, loopback or
// plain-http hosts.
func TestDefaultPushClientsAreGuarded(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer plain.Close()
	k8s, err := NewK8sPusher(K8sConfig{BaseURL: "https://k.invalid"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	clients := map[string]*http.Client{
		"f5":     NewF5Pusher(F5Config{}, nil).client,
		"citrix": NewCitrixPusher(CitrixConfig{}, nil).client,
		"k8s":    k8s.client,
	}
	for name, c := range clients {
		for _, u := range []string{"https://169.254.169.254/", "https://127.0.0.1:1/", plain.URL} {
			if _, err := c.Get(u); !errors.Is(err, egress.ErrBlockedDestination) {
				t.Errorf("%s %s: want ErrBlockedDestination, got %v", name, u, err)
			}
		}
	}
}
