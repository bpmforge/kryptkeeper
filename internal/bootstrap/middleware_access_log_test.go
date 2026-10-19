// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kryptkeeper/internal/logging"
)

func captureLogs(t *testing.T, level slog.Level) *bytes.Buffer {
	t.Helper()
	oldLogger, oldW, oldFlags, oldPrefix := slog.Default(), log.Writer(), log.Flags(), log.Prefix()
	t.Cleanup(func() {
		slog.SetDefault(oldLogger)
		log.SetOutput(oldW)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
	})
	buf := &bytes.Buffer{}
	logging.Setup(logging.Config{Level: level, Writer: buf})
	return buf
}

func TestAccessLogLineFields(t *testing.T) {
	buf := captureLogs(t, slog.LevelInfo)
	h := withRequestID(withAccessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("abc"))
	})))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/x?token=SEEDVALUE", nil))

	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m); err != nil {
		t.Fatalf("not one JSON line: %v: %q", err, buf)
	}
	if m["request_id"] != rec.Header().Get("X-Request-ID") || m["request_id"] == "" {
		t.Fatalf("request_id %v vs header %q", m["request_id"], rec.Header().Get("X-Request-ID"))
	}
	if m["method"] != "GET" || m["path"] != "/api/v1/x" || m["status"] != float64(http.StatusTeapot) || m["bytes"] != float64(3) {
		t.Fatalf("unexpected line: %v", m)
	}
	for _, k := range []string{"latency_ms", "tenant"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing %s: %v", k, m)
		}
	}
	if strings.Contains(buf.String(), "SEEDVALUE") {
		t.Fatalf("query string leaked: %s", buf)
	}
}

func TestAccessLogPreservesFlusher(t *testing.T) {
	captureLogs(t, slog.LevelInfo)
	var flushErr error
	var isFlusher bool
	h := withAccessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, isFlusher = w.(http.Flusher)
		flushErr = http.NewResponseController(w).Flush()
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/events", nil))
	if !isFlusher || flushErr != nil || !rec.Flushed {
		t.Fatalf("flusher=%v err=%v flushed=%v", isFlusher, flushErr, rec.Flushed)
	}
}

func TestHealthProbesLogAtDebug(t *testing.T) {
	buf := captureLogs(t, slog.LevelInfo)
	h := withAccessLog(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, p := range []string{"/healthz", "/readyz", "/metrics"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil))
	}
	if buf.Len() != 0 {
		t.Fatalf("probes logged at info: %s", buf)
	}
}

func TestAccessLogServerErrorIsErrorLevel(t *testing.T) {
	buf := captureLogs(t, slog.LevelInfo)
	h := withAccessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if !strings.Contains(buf.String(), `"level":"error"`) {
		t.Fatalf("want error level: %s", buf)
	}
}
