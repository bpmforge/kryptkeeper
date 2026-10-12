// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mintAdminToken mints a pki-admin API key for principalID, recording
// createdBy the way POST /api-keys does (the creator's canonical human).
// The Authenticator must have APP_API_KEY_PEPPER set.
func mintAdminToken(t *testing.T, auth *Authenticator, principalID, createdBy string) string {
	t.Helper()
	_, token, err := auth.CreateAPIKeyAs(createdBy, principalID+"-key", principalID, "pki-admin", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatalf("CreateAPIKeyAs(%s): %v", principalID, err)
	}
	return token
}

func bearerReq(token, method, url string, body []byte) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, url, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, url, nil)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	return r
}
