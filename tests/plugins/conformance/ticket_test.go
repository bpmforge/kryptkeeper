// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

// Mock services for the first-party ticket plugins (W38-09): Zendesk Tickets
// API and Freshservice v2 tickets. Each answers the way the vendor documents
// (201 on create, 404 for a missing ticket, 429 with Retry-After) and records
// what it accepted for TicketSuite.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/plugins/delivery"
)

type ticketMock struct {
	ts      *httptest.Server
	mu      sync.Mutex
	tickets map[string]*Ticket
	next    int
	fail    string
}

func (m *ticketMock) FailNext(mode string) { m.mu.Lock(); m.fail = mode; m.mu.Unlock() }
func (m *ticketMock) Reset() {
	m.mu.Lock()
	m.tickets, m.fail = map[string]*Ticket{}, ""
	m.mu.Unlock()
}
func (m *ticketMock) Ticket(key string) (Ticket, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tickets[key]; ok {
		return *t, true
	}
	return Ticket{}, false
}
func (m *ticketMock) Count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.tickets) }
func (m *ticketMock) Delete(key string) {
	m.mu.Lock()
	delete(m.tickets, key)
	m.mu.Unlock()
}

// takeFailure answers the armed failure, once, and reports whether it did.
func (m *ticketMock) takeFailure(w http.ResponseWriter) bool {
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
	case "unauthorized":
		w.WriteHeader(http.StatusUnauthorized)
	default:
		return false
	}
	return true
}

func (m *ticketMock) add(text string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	key := strconv.Itoa(1000 + m.next)
	m.tickets[key] = &Ticket{Key: key, Text: text}
	return key
}

func (m *ticketMock) resolve(key, note string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tickets[key]
	if ok {
		t.Resolved = true
		if note != "" {
			t.Note = note
		}
	}
	return ok
}

func newTicketMock(t *testing.T, handler func(*ticketMock) http.HandlerFunc) *ticketMock {
	m := &ticketMock{tickets: map[string]*Ticket{}}
	m.ts = httptest.NewTLSServer(handler(m))
	t.Cleanup(m.ts.Close)
	return m
}

func jsonBody(r *http.Request, into any) bool {
	raw, _ := io.ReadAll(r.Body)
	return json.Unmarshal(raw, into) == nil
}

// --- Zendesk ---

const zdToken = "zd-token-0123456789abcdef"

type zendeskMock struct{ *ticketMock }

func (m zendeskMock) Env() delivery.Env {
	return anyHostEnv(m.ts, map[string]string{"base_url": "https://acme.zendesk.com", "email": "ops@acme.example", "api_token": zdToken},
		[]string{"api_token"}, nil)
}

func newZendeskMock(t *testing.T) zendeskMock {
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("ops@acme.example/token:"+zdToken))
	return zendeskMock{newTicketMock(t, func(m *ticketMock) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != wantAuth {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if m.takeFailure(w) {
				return
			}
			path := r.URL.Path
			switch {
			case r.Method == http.MethodPost && path == "/api/v2/tickets.json":
				var b struct {
					Ticket struct {
						Subject string `json:"subject"`
						Comment struct {
							Body string `json:"body"`
						} `json:"comment"`
						Priority string `json:"priority"`
					} `json:"ticket"`
				}
				if !jsonBody(r, &b) || b.Ticket.Subject == "" || b.Ticket.Comment.Body == "" {
					w.WriteHeader(http.StatusUnprocessableEntity)
					return
				}
				key := m.add(b.Ticket.Subject + "\n" + b.Ticket.Comment.Body)
				w.WriteHeader(http.StatusCreated)
				_, _ = fmt.Fprintf(w, `{"ticket":{"id":%s,"status":"new"}}`, key)
			case strings.HasPrefix(path, "/api/v2/tickets/") && strings.HasSuffix(path, ".json"):
				key := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v2/tickets/"), ".json")
				t, ok := m.Ticket(key)
				if !ok {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"error":"RecordNotFound"}`))
					return
				}
				switch r.Method {
				case http.MethodGet:
					_, _ = fmt.Fprintf(w, `{"ticket":{"id":%s,"status":"open"}}`, key)
				case http.MethodPut:
					var b struct {
						Ticket struct {
							Status  string `json:"status"`
							Comment struct {
								Body   string `json:"body"`
								Public *bool  `json:"public"`
							} `json:"comment"`
						} `json:"ticket"`
					}
					if !jsonBody(r, &b) || b.Ticket.Status != "solved" {
						w.WriteHeader(http.StatusUnprocessableEntity)
						return
					}
					m.resolve(t.Key, b.Ticket.Comment.Body)
					_, _ = fmt.Fprintf(w, `{"ticket":{"id":%s,"status":"solved"}}`, key)
				default:
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}
	})}
}

func TestZendeskPluginConforms(t *testing.T) {
	rt := newRuntime(t)
	TicketSuite(t, Load(t, rt, repoPath(t, "plugins/zendesk")), newZendeskMock(t))
}

// --- Freshservice ---

const fsKey = "freshservice-key-0123456789"

type freshserviceMock struct{ *ticketMock }

func (m freshserviceMock) Env() delivery.Env {
	return anyHostEnv(m.ts, map[string]string{"base_url": "https://acme.freshservice.com", "api_key": fsKey, "requester_email": "ops@acme.example"},
		[]string{"api_key"}, nil)
}

func newFreshserviceMock(t *testing.T) freshserviceMock {
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(fsKey+":X"))
	return freshserviceMock{newTicketMock(t, func(m *ticketMock) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != wantAuth {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if m.takeFailure(w) {
				return
			}
			path := r.URL.Path
			switch {
			case r.Method == http.MethodPost && path == "/api/v2/tickets":
				var b struct {
					Subject     string `json:"subject"`
					Description string `json:"description"`
					Email       string `json:"email"`
					Status      int    `json:"status"`
					Priority    int    `json:"priority"`
				}
				if !jsonBody(r, &b) || b.Subject == "" || b.Description == "" || b.Email == "" || b.Status != 2 || b.Priority < 1 || b.Priority > 4 {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				key := m.add(b.Subject + "\n" + b.Description)
				w.WriteHeader(http.StatusCreated)
				_, _ = fmt.Fprintf(w, `{"ticket":{"id":%s,"status":2}}`, key)
			case strings.HasPrefix(path, "/api/v2/tickets/"):
				rest := strings.TrimPrefix(path, "/api/v2/tickets/")
				key, sub, _ := strings.Cut(rest, "/")
				if _, ok := m.Ticket(key); !ok {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				switch {
				case r.Method == http.MethodGet && sub == "":
					_, _ = fmt.Fprintf(w, `{"ticket":{"id":%s,"deleted":false}}`, key)
				case r.Method == http.MethodPut && sub == "":
					var b struct {
						Status int `json:"status"`
					}
					if !jsonBody(r, &b) || b.Status != 4 {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					m.resolve(key, "")
					_, _ = fmt.Fprintf(w, `{"ticket":{"id":%s,"status":4}}`, key)
				case r.Method == http.MethodPost && sub == "notes":
					var b struct {
						Body string `json:"body"`
					}
					if !jsonBody(r, &b) || b.Body == "" {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					m.resolve(key, b.Body)
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"conversation":{"id":1}}`))
				default:
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}
	})}
}

func TestFreshservicePluginConforms(t *testing.T) {
	rt := newRuntime(t)
	TicketSuite(t, Load(t, rt, repoPath(t, "plugins/freshservice")), newFreshserviceMock(t))
}

// A ticket plugin the hub loads is never asked a delivery or notify op, and
// the other kinds' plugins are never asked a ticket op.
func TestTicketKindIsEnforcedOnRealModules(t *testing.T) {
	rt := newRuntime(t)
	zd := Load(t, rt, repoPath(t, "plugins/zendesk"))
	if err := zd.Validate(t.Context(), newZendeskMock(t).Env()); err == nil || !strings.Contains(err.Error(), "not defined for this plugin's kind") {
		t.Fatalf("validate on a ticket plugin: %v", err)
	}
	pd := Load(t, rt, repoPath(t, "plugins/pagerduty"))
	if _, err := pd.TicketCreate(t.Context(), newPagerDutyMock(t).Env(), abi.TicketEvent{ID: "x"}); err == nil || !strings.Contains(err.Error(), "not defined for this plugin's kind") {
		t.Fatalf("ticket op on a notify plugin: %v", err)
	}
}
