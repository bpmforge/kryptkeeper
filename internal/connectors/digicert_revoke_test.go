// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func digicertRevokeRun(t *testing.T, orders string, putStatus int) (error, []string) {
	t.Helper()
	var reqs []string
	var putBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs = append(reqs, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(orders))
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&putBody)
		w.WriteHeader(putStatus)
	}))
	defer srv.Close()
	c := NewDigiCertConnector("dc", DigiCertConfig{BaseURL: srv.URL, APIKey: "k", OrganizationID: 1}, srv.Client())
	err := c.Revoke(context.Background(), RevokeRequest{SerialHex: "0a1b", Reason: 1})
	if err == nil && putBody["revocation_reason"] != "keyCompromise" {
		t.Fatalf("body %v", putBody)
	}
	return err, reqs
}

func TestDigiCertRevoke(t *testing.T) {
	err, reqs := digicertRevokeRun(t, `{"orders":[{"certificate":{"id":77}}]}`, 204)
	if err != nil || len(reqs) != 2 || !strings.HasPrefix(reqs[1], "PUT /services/v2/certificate/77/revoke") || !strings.Contains(reqs[0], "0A1B") {
		t.Fatalf("err=%v reqs=%v", err, reqs)
	}
	if err, _ := digicertRevokeRun(t, `{"orders":[]}`, 204); err == nil {
		t.Fatal("zero matches must fail")
	}
	if err, _ := digicertRevokeRun(t, `{"orders":[{"certificate":{"id":1}},{"certificate":{"id":2}}]}`, 204); err == nil {
		t.Fatal("two matches must fail")
	}
	if err, _ := digicertRevokeRun(t, `{"orders":[{"certificate":{"id":77}}]}`, 201); err == nil {
		t.Fatal("pending approval must not count as revoked")
	}
}
