// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

// Mock receivers for the first-party notify plugins (W38-02): Teams
// Workflows webhook, PagerDuty Events API v2, Opsgenie Alerts API. Each
// answers the way the vendor documents (202 on accept, 429 with Retry-After,
// 5xx on failure) and records what it accepted for NotifySuite.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"kryptkeeper/internal/plugins/delivery"
)

// notifyMock is the part every receiver shares: a TLS server, the failure
// switch and the list of accepted alerts.
type notifyMock struct {
	ts     *httptest.Server
	mu     sync.Mutex
	alerts []Alert
	fail   string
}

func (m *notifyMock) FailNext(mode string) { m.mu.Lock(); m.fail = mode; m.mu.Unlock() }
func (m *notifyMock) Reset()               { m.mu.Lock(); m.alerts, m.fail = nil, ""; m.mu.Unlock() }
func (m *notifyMock) Received() []Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Alert(nil), m.alerts...)
}

// takeFailure answers the armed failure, once, and reports whether it did.
func (m *notifyMock) takeFailure(w http.ResponseWriter) bool {
	m.mu.Lock()
	mode := m.fail
	m.fail = ""
	m.mu.Unlock()
	switch mode {
	case "server_error":
		w.WriteHeader(http.StatusInternalServerError)
	case "rate_limit":
		w.Header().Set("Retry-After", strconv.Itoa(RateLimitSeconds))
		w.WriteHeader(http.StatusTooManyRequests)
	default:
		return false
	}
	return true
}

func (m *notifyMock) record(a Alert) {
	m.mu.Lock()
	m.alerts = append(m.alerts, a)
	m.mu.Unlock()
}

func newNotifyMock(t *testing.T, handler func(*notifyMock) http.HandlerFunc) *notifyMock {
	m := &notifyMock{}
	m.ts = httptest.NewTLSServer(handler(m))
	t.Cleanup(m.ts.Close)
	return m
}

// --- Microsoft Teams (Workflows webhook) ---

type teamsMock struct{ *notifyMock }

func (teamsMock) KeepsDedupe() bool { return false }
func (teamsMock) CanResolve() bool  { return false }

func (m teamsMock) Env() delivery.Env {
	return anyHostEnv(m.ts, map[string]string{"webhook_url": "https://flow.example.com/workflows/abc/triggers/manual/paths/invoke?sig=teams-signature-xyz"},
		[]string{"webhook_url"}, nil)
}

func newTeamsMock(t *testing.T) teamsMock {
	return teamsMock{newNotifyMock(t, func(m *notifyMock) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if m.takeFailure(w) {
				return
			}
			var p struct {
				Type        string `json:"type"`
				Attachments []struct {
					ContentType string          `json:"contentType"`
					Content     json.RawMessage `json:"content"`
				} `json:"attachments"`
			}
			raw, _ := io.ReadAll(r.Body)
			if r.Method != http.MethodPost || json.Unmarshal(raw, &p) != nil || p.Type != "message" ||
				len(p.Attachments) != 1 || p.Attachments[0].ContentType != "application/vnd.microsoft.card.adaptive" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			m.record(Alert{Text: string(p.Attachments[0].Content)})
			w.WriteHeader(http.StatusAccepted)
		}
	})}
}

func TestTeamsPluginConforms(t *testing.T) {
	rt := newRuntime(t)
	NotifySuite(t, Load(t, rt, repoPath(t, "plugins/microsoft-teams")), newTeamsMock(t))
}

// --- PagerDuty (Events API v2) ---

const pdRoutingKey = "0123456789abcdef0123456789abcdef"

type pagerDutyMock struct{ *notifyMock }

func (pagerDutyMock) KeepsDedupe() bool { return true }
func (pagerDutyMock) CanResolve() bool  { return true }

func (m pagerDutyMock) Env() delivery.Env {
	return anyHostEnv(m.ts, map[string]string{"api_base": "https://events.pagerduty.com", "routing_key": pdRoutingKey}, []string{"routing_key"}, nil)
}

func newPagerDutyMock(t *testing.T) pagerDutyMock {
	return pagerDutyMock{newNotifyMock(t, func(m *notifyMock) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if m.takeFailure(w) {
				return
			}
			var e struct {
				RoutingKey  string `json:"routing_key"`
				EventAction string `json:"event_action"`
				DedupKey    string `json:"dedup_key"`
				Payload     struct {
					Summary  string `json:"summary"`
					Source   string `json:"source"`
					Severity string `json:"severity"`
				} `json:"payload"`
			}
			raw, _ := io.ReadAll(r.Body)
			bad := r.Method != http.MethodPost || r.URL.Path != "/v2/enqueue" || json.Unmarshal(raw, &e) != nil ||
				e.RoutingKey != pdRoutingKey || e.DedupKey == "" ||
				(e.EventAction != "trigger" && e.EventAction != "resolve") ||
				(e.EventAction == "trigger" && (e.Payload.Summary == "" || e.Payload.Source == "" ||
					!map[string]bool{"critical": true, "error": true, "warning": true, "info": true}[e.Payload.Severity]))
			if bad {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"status":"invalid event","message":"Event object is invalid"}`))
				return
			}
			m.record(Alert{Text: e.Payload.Summary, Key: e.DedupKey, Resolved: e.EventAction == "resolve"})
			w.WriteHeader(http.StatusAccepted)
			_, _ = fmt.Fprintf(w, `{"status":"success","message":"Event processed","dedup_key":%q}`, e.DedupKey)
		}
	})}
}

func TestPagerDutyPluginConforms(t *testing.T) {
	rt := newRuntime(t)
	NotifySuite(t, Load(t, rt, repoPath(t, "plugins/pagerduty")), newPagerDutyMock(t))
}

// --- Opsgenie (Alerts API) ---

const ogKey = "opsgenie-key-0123456789abcdef"

type opsgenieMock struct{ *notifyMock }

func (opsgenieMock) KeepsDedupe() bool { return true }
func (opsgenieMock) CanResolve() bool  { return true }

func (m opsgenieMock) Env() delivery.Env {
	return anyHostEnv(m.ts, map[string]string{"api_base": "https://api.opsgenie.com", "api_key": ogKey}, []string{"api_key"}, nil)
}

func newOpsgenieMock(t *testing.T) opsgenieMock {
	return opsgenieMock{newNotifyMock(t, func(m *notifyMock) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "GenieKey "+ogKey {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if m.takeFailure(w) {
				return
			}
			raw, _ := io.ReadAll(r.Body)
			accept := func(a Alert) {
				m.record(a)
				w.WriteHeader(http.StatusAccepted)
				_, _ = fmt.Fprintf(w, `{"result":"Request will be processed","took":0.1,"requestId":"req-%d"}`, len(m.Received()))
			}
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/v2/alerts":
				var b struct {
					Message  string `json:"message"`
					Alias    string `json:"alias"`
					Priority string `json:"priority"`
				}
				if json.Unmarshal(raw, &b) != nil || b.Message == "" || len(b.Message) > 130 || b.Alias == "" ||
					!strings.HasPrefix(b.Priority, "P") {
					w.WriteHeader(http.StatusUnprocessableEntity)
					return
				}
				accept(Alert{Text: b.Message, Key: b.Alias})
			case r.Method == http.MethodPost && strings.HasPrefix(r.URL.EscapedPath(), "/v2/alerts/") && strings.HasSuffix(r.URL.Path, "/close") &&
				r.URL.Query().Get("identifierType") == "alias":
				alias := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v2/alerts/"), "/close")
				accept(Alert{Key: alias, Resolved: true})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}
	})}
}

func TestOpsgeniePluginConforms(t *testing.T) {
	rt := newRuntime(t)
	NotifySuite(t, Load(t, rt, repoPath(t, "plugins/opsgenie")), newOpsgenieMock(t))
}

// A notify plugin the hub loads is never asked a delivery operation, and a
// delivery plugin is never asked to notify.
func TestKindsAreEnforcedOnRealModules(t *testing.T) {
	rt := newRuntime(t)
	nt := Load(t, rt, repoPath(t, "plugins/pagerduty"))
	if err := nt.Validate(t.Context(), newPagerDutyMock(t).Env()); err == nil || !strings.Contains(err.Error(), "not defined for this plugin's kind") {
		t.Fatalf("validate on a notify plugin: %v", err)
	}
	dp := Load(t, rt, repoPath(t, "plugins/example"))
	if dp.Kind() != "delivery" {
		t.Fatalf("example plugin kind %q", dp.Kind())
	}
}
