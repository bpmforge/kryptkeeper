// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kryptkeeper/internal/logging"
)

// W30-11 acceptance 2: every line the hub writes is a JSON record carrying
// level, ts, msg and request_id, whether it comes from the access log, a
// logging helper, or a provider warn function value.
func TestHubLogLinesAreJSON(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	logging.Setup(logging.Config{Writer: &buf})

	h := withRequestID(withAccessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logging.Warnf("handler saw %s", r.URL.Path)
		w.WriteHeader(http.StatusUnauthorized)
	})))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/things", nil))
	logging.Infof("outside a request %d", 1)
	notificationProviderWarnf("provider warning %s", "x")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected at least 4 lines, got %d: %s", len(lines), buf.String())
	}
	for _, ln := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("not JSON: %q: %v", ln, err)
		}
		for _, k := range []string{"level", "ts", "msg", "request_id"} {
			if _, ok := m[k]; !ok {
				t.Errorf("line missing %q: %s", k, ln)
			}
		}
	}
}
