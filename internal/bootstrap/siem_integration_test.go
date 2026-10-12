// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSIEMStatusMasksWebhookAndReportsTargets(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DB_MODE", "sqlite")
	t.Setenv("SIEM_WEBHOOK_URL", "https://splunk.example.com:8088/services/collector?token=secret")
	t.Setenv("SIEM_WEBHOOK_TOKEN", "abc123")
	t.Setenv("SIEM_SYSLOG_ADDR", "10.0.0.5:514")
	t.Setenv("SIEM_SYSLOG_PROTO", "tcp")

	st := NewSIEMRouterFromEnv().Status()
	if !st.Enabled || !st.WebhookEnabled || !st.SyslogEnabled {
		t.Fatalf("expected all targets enabled: %+v", st)
	}
	if st.WebhookTarget != "https://splunk.example.com:8088" {
		t.Fatalf("webhook target not masked correctly: %q", st.WebhookTarget)
	}
	if !st.WebhookHasToken {
		t.Fatal("expected webhook_has_token true")
	}
	if st.SyslogAddr != "10.0.0.5:514" || st.SyslogProto != "tcp" {
		t.Fatalf("unexpected syslog status: %+v", st)
	}
}

func TestSIEMStatusDisabledWhenUnset(t *testing.T) {
	t.Setenv("SIEM_WEBHOOK_URL", "")
	t.Setenv("SIEM_SYSLOG_ADDR", "")
	st := NewSIEMRouterFromEnv().Status()
	if st.Enabled || st.WebhookEnabled || st.SyslogEnabled {
		t.Fatalf("expected SIEM disabled: %+v", st)
	}
}

func TestSIEMTestWebhookSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("SIEM_WEBHOOK_URL", srv.URL)
	t.Setenv("SIEM_SYSLOG_ADDR", "")

	result := NewSIEMRouterFromEnv().Test("admin")
	if !result.WebhookTested || !result.WebhookOK {
		t.Fatalf("expected webhook test ok: %+v", result)
	}
	if result.SyslogTested {
		t.Fatalf("syslog should not be tested when unset: %+v", result)
	}
}

func TestSIEMTestWebhookFailureReportsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("SIEM_WEBHOOK_URL", srv.URL)
	t.Setenv("SIEM_SYSLOG_ADDR", "")

	result := NewSIEMRouterFromEnv().Test("admin")
	if result.WebhookOK || result.WebhookError == "" {
		t.Fatalf("expected webhook failure with error: %+v", result)
	}
}

func TestSIEMHandlerStatusEndpoint(t *testing.T) {
	auth := newReportsTestAuth(t)
	t.Setenv("SIEM_WEBHOOK_URL", "https://hec.example.com/x")
	t.Setenv("SIEM_SYSLOG_ADDR", "")

	mux := http.NewServeMux()
	registerIntegrationsHandlers(mux, auth, stubAuditProvider{}, NewSIEMRouterFromEnv())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/integrations/siem", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data SIEMStatus `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Data.WebhookEnabled || resp.Data.WebhookTarget != "https://hec.example.com" {
		t.Fatalf("unexpected status payload: %+v", resp.Data)
	}
}

// TestFormatCEF_HeaderFieldCount validates the CEF spec's 8-field header
// shape (CEF:Version|Vendor|Product|DeviceVersion|SignatureID|Name|Severity|
// Extension) — W19-27 acceptance bar.
func TestFormatCEF_HeaderFieldCount(t *testing.T) {
	event := SIEMEvent{
		EventType:    "cert.revoked",
		Timestamp:    "2026-09-11T12:00:00Z",
		Severity:     "warning",
		ActorID:      "admin@example.com",
		ResourceType: "certificate",
		ResourceID:   "aa:bb:cc",
	}
	line := formatCEF(event)
	parts := strings.SplitN(line, "|", 8)
	if len(parts) != 8 {
		t.Fatalf("expected 8 pipe-delimited header fields, got %d: %q", len(parts), line)
	}
	if parts[0] != "CEF:0" {
		t.Errorf("expected CEF:0 prefix, got %q", parts[0])
	}
	if parts[1] != "Kryptkeeper" || parts[2] != "kryptkeeper" {
		t.Errorf("expected Vendor=Kryptkeeper Product=kryptkeeper, got %q / %q", parts[1], parts[2])
	}
	if parts[4] != "cert.revoked" {
		t.Errorf("expected Signature ID = event type, got %q", parts[4])
	}
	if parts[5] != "Certificate Revoked" {
		t.Errorf("expected Name = %q, got %q", "Certificate Revoked", parts[5])
	}
	if parts[6] != "6" {
		t.Errorf("expected warning severity = 6, got %q", parts[6])
	}
	ext := parts[7]
	for _, want := range []string{"suser=admin@example.com", "act=cert.revoked", "cs1=certificate", "cs2=aa:bb:cc"} {
		if !strings.Contains(ext, want) {
			t.Errorf("expected extension to contain %q, got %q", want, ext)
		}
	}
}

// TestFormatCEF_EscapesHeaderAndExtension proves the two escaping rules the
// CEF spec requires: backslash and pipe in header fields, backslash and
// equals in extension values.
func TestFormatCEF_EscapesHeaderAndExtension(t *testing.T) {
	event := SIEMEvent{
		EventType:    `weird|type\here`,
		Timestamp:    "2026-09-11T12:00:00Z",
		Severity:     "info",
		ActorID:      "user=admin\\path",
		ResourceType: "certificate",
		ResourceID:   "id1",
	}
	line := formatCEF(event)

	// Header: Signature ID field must have | and \ escaped.
	if !strings.Contains(line, `weird\|type\\here`) {
		t.Fatalf("expected header pipe/backslash escaping, got %q", line)
	}
	// The escaped header field must still leave the header at exactly 8
	// fields when split respecting escapes -- i.e. the raw string must NOT
	// contain a bare unescaped '|' where the event type's own pipe was.
	// SplitN on the raw text (which does not know about escaping) would
	// wrongly report 9 fields if escaping had not happened; assert the
	// escaped form is present instead of asserting field count here, since
	// SplitN can't itself validate escaping.

	// Extension: ActorID's '=' and '\' must be escaped.
	if !strings.Contains(line, `suser=user\=admin\\path`) {
		t.Fatalf("expected extension backslash/equals escaping, got %q", line)
	}
}

// TestSIEMFormat_DefaultsToJSON proves W19-27's acceptance bar that the
// unconfigured default is unchanged.
func TestSIEMFormat_DefaultsToJSON(t *testing.T) {
	t.Setenv("SIEM_FORMAT", "")
	if got := NewSIEMRouterFromEnv().format; got != "json" {
		t.Fatalf("expected default format json, got %q", got)
	}
}

// TestSIEMFormat_CEFSelectsCEFOutput proves SIEM_FORMAT=cef flips the
// webhook body to a CEF line instead of JSON.
func TestSIEMFormat_CEFSelectsCEFOutput(t *testing.T) {
	var gotBody string
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		gotBody = string(buf)
		gotContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("SIEM_WEBHOOK_URL", srv.URL)
	t.Setenv("SIEM_SYSLOG_ADDR", "")
	t.Setenv("SIEM_FORMAT", "cef")

	router := NewSIEMRouterFromEnv()
	if router.format != "cef" {
		t.Fatalf("expected format cef, got %q", router.format)
	}
	result := router.Test("admin")
	if !result.WebhookOK {
		t.Fatalf("expected webhook test ok: %+v", result)
	}
	if !strings.HasPrefix(gotBody, "CEF:0|") {
		t.Fatalf("expected CEF body, got %q", gotBody)
	}
	if !strings.HasPrefix(gotContentType, "text/plain") {
		t.Fatalf("expected text/plain content type for CEF, got %q", gotContentType)
	}
}

func TestSIEMTestHandlerRejectsWhenDisabled(t *testing.T) {
	auth := newReportsTestAuth(t)
	t.Setenv("SIEM_WEBHOOK_URL", "")
	t.Setenv("SIEM_SYSLOG_ADDR", "")

	mux := http.NewServeMux()
	registerIntegrationsHandlers(mux, auth, stubAuditProvider{}, NewSIEMRouterFromEnv())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/siem/test", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when no SIEM target, got %d", rec.Code)
	}
}
