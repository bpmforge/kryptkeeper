// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// W38-09: the real first-party ticket plugins (compiled to wasm) run through
// the hub's own ITSM service: plugin manager, plugin connector, the durable
// queue, reconcile and resolve, and audit, against local TLS stand-ins.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/notifications/itsm"
	plugindelivery "kryptkeeper/internal/plugins/delivery"
	"kryptkeeper/tests/plugins/conformance"
)

// ticketStandIn is a tiny ticket service. flavor "zendesk" or "freshservice"
// picks the paths and bodies; both keep tickets in memory so a test can delete
// one behind the hub's back.
type ticketStandIn struct {
	*standIn
	mu       sync.Mutex
	tickets  map[string]string // key -> "open" | "solved"
	notes    map[string]string
	next     int
	failWith int // when non-zero, every request answers it
	requests []string
}

func newTicketStandIn(t *testing.T, flavor string) *ticketStandIn {
	s := &ticketStandIn{tickets: map[string]string{}, notes: map[string]string{}}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.requests = append(s.requests, r.Method+" "+r.URL.Path)
		if s.failWith != 0 {
			w.WriteHeader(s.failWith)
			return
		}
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		path := r.URL.Path
		switch flavor {
		case "zendesk":
			switch {
			case r.Method == http.MethodPost && path == "/api/v2/tickets.json":
				s.next++
				key := strconv.Itoa(500 + s.next)
				s.tickets[key] = "open"
				w.WriteHeader(http.StatusCreated)
				_, _ = fmt.Fprintf(w, `{"ticket":{"id":%s}}`, key)
				return
			case strings.HasPrefix(path, "/api/v2/tickets/"):
				key := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v2/tickets/"), ".json")
				st, ok := s.tickets[key]
				switch {
				case !ok:
					w.WriteHeader(http.StatusNotFound)
				case r.Method == http.MethodGet:
					_, _ = fmt.Fprintf(w, `{"ticket":{"id":%s,"status":%q}}`, key, st)
				case r.Method == http.MethodPut:
					tk, _ := body["ticket"].(map[string]any)
					s.tickets[key] = "solved"
					if c, _ := tk["comment"].(map[string]any); c != nil {
						s.notes[key], _ = c["body"].(string)
					}
					_, _ = w.Write([]byte(`{"ticket":{}}`))
				}
				return
			}
		case "freshservice":
			switch {
			case r.Method == http.MethodPost && path == "/api/v2/tickets":
				s.next++
				key := strconv.Itoa(900 + s.next)
				s.tickets[key] = "open"
				w.WriteHeader(http.StatusCreated)
				_, _ = fmt.Fprintf(w, `{"ticket":{"id":%s}}`, key)
				return
			case strings.HasPrefix(path, "/api/v2/tickets/"):
				key, sub, _ := strings.Cut(strings.TrimPrefix(path, "/api/v2/tickets/"), "/")
				_, ok := s.tickets[key]
				switch {
				case !ok:
					w.WriteHeader(http.StatusNotFound)
				case r.Method == http.MethodGet:
					_, _ = fmt.Fprintf(w, `{"ticket":{"id":%s,"deleted":false}}`, key)
				case r.Method == http.MethodPut:
					s.tickets[key] = "solved"
					_, _ = w.Write([]byte(`{"ticket":{}}`))
				case r.Method == http.MethodPost && sub == "notes":
					s.notes[key], _ = body["body"].(string)
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"conversation":{}}`))
				}
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(ts.Close)
	s.standIn = &standIn{ts: ts}
	return s
}

func (s *ticketStandIn) setFail(code int) { s.mu.Lock(); s.failWith = code; s.mu.Unlock() }
func (s *ticketStandIn) del(key string)   { s.mu.Lock(); delete(s.tickets, key); s.mu.Unlock() }
func (s *ticketStandIn) state(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.tickets[key]
	return st, ok
}

func installTicketPlugin(t *testing.T, mgr *DeliveryPluginManager, name string) string {
	t.Helper()
	dir := repoDir("plugins/" + name)
	wasm := conformance.Build(t, dir)
	v, err := mgr.Install(context.Background(), conformance.PinManifest(t, dir, wasm), wasm, "", "admin")
	if err != nil {
		t.Fatalf("install %s: %v", name, err)
	}
	if v.Kind != abi.KindTicket {
		t.Fatalf("%s kind %q", name, v.Kind)
	}
	if v.CapabilityTier != abi.TierHigh {
		t.Fatalf("%s capability tier %q: a network grant from the credential is High, so enabling needs a second person", name, v.CapabilityTier)
	}
	if err := mgr.enable(context.Background(), v.PluginID, v.Version, "approver"); err != nil {
		t.Fatal(err)
	}
	return v.PluginID
}

func TestTicketPluginsRunThroughTheITSMService(t *testing.T) {
	cases := []struct {
		dir, flavor, secret, payload string
	}{
		{"zendesk", "zendesk", "zd-live-token-0123456789", `{"base_url":"https://acme.zendesk.com","email":"ops@acme.example","api_token":"zd-live-token-0123456789"}`},
		{"freshservice", "freshservice", "fs-live-key-0123456789", `{"base_url":"https://acme.freshservice.com","api_key":"fs-live-key-0123456789","requester_email":"ops@acme.example"}`},
	}
	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			ctx := context.Background()
			db := notifyPluginDB(t)
			mgr := NewDeliveryPluginManager(db, false, nil, nil)
			pluginID := installTicketPlugin(t, mgr, tc.dir)
			svc := newTicketStandIn(t, tc.flavor)
			pluginAudit := &scepRecordingAudit{}
			creds := &renewalFakeCredStore{meta: OutboundCredentialMeta{ID: "cred-1", CredentialType: CredentialTypeAPIToken}, payload: []byte(tc.payload)}
			connectors := NewITSMPluginConnectors(func() *DeliveryPluginManager { return mgr }, pluginAudit)
			connectors.creds = func() OutboundCredentialStore { return creds }
			connectors.client = svc.client()

			store := itsm.NewStore(db, false)
			var audits []itsm.AuditRecord
			var alerts []string
			service := itsm.NewService(itsm.Config{
				Store: store,
				Conns: itsm.NewConnectorSource(store, nil, nil, nil, connectors.Factory()),
				Audit: func(_ context.Context, r itsm.AuditRecord) { audits = append(audits, r) },
				Alert: func(_ context.Context, class, detail string) { alerts = append(alerts, class+":"+detail) },
			})
			conn, err := store.CreateConnection(ctx, itsm.Connection{ID: "itsm-plug", Kind: itsm.KindPlugin, Name: "Desk", CredentialRef: "cred-1", PluginID: pluginID, Enabled: true}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			ev := itsm.Event{ID: "renewal_failed:ab-cd:1", Class: "renewal_failed", CN: "shop.example.com", Serial: "01AB", Risk: "high", Fingerprint: "ab-cd", DeepLink: "https://kk.example.com/c/ab-cd"}

			// test connection: a read-only probe, not a Find that would pass blind.
			if err := service.TestConnection(ctx, conn.ID); err != nil {
				t.Fatalf("test connection: %v", err)
			}

			// create
			if err := service.Submit(ctx, conn.ID, ev); err != nil {
				t.Fatal(err)
			}
			if n, err := service.Drain(ctx); err != nil || n != 1 {
				t.Fatalf("drain = %d, %v", n, err)
			}
			row, _ := store.GetEvent(ctx, ev.ID)
			if row.Status != itsm.StatusCreated || row.TicketKey == "" || !strings.HasPrefix(row.TicketURL, "https://") {
				t.Fatalf("row %+v", row)
			}
			if st, ok := svc.state(row.TicketKey); !ok || st != "open" {
				t.Fatalf("stand-in ticket %q = %q, %v", row.TicketKey, st, ok)
			}

			// exists: a reconcile of a live ticket changes nothing
			if err := service.Reconcile(ctx, ev.ID); err != nil {
				t.Fatal(err)
			}
			if again, _ := store.GetEvent(ctx, ev.ID); again.Recreated || again.TicketKey != row.TicketKey {
				t.Fatalf("a live ticket was recreated: %+v", again)
			}

			// externally deleted -> reconcile recreates, once
			first := row.TicketKey
			svc.del(first)
			if err := service.Reconcile(ctx, ev.ID); err != nil {
				t.Fatal(err)
			}
			row, _ = store.GetEvent(ctx, ev.ID)
			if !row.Recreated || row.TicketKey == first {
				t.Fatalf("not recreated after external delete: %+v", row)
			}
			if _, ok := svc.state(row.TicketKey); !ok {
				t.Fatal("the recreated ticket is not at the service")
			}

			// resolve: the ticket closes with the comment, the row is resolved
			if n, err := service.ResolveByFingerprint(ctx, "ab-cd", "Certificate replaced and verified"); err != nil || n != 1 {
				t.Fatalf("resolve = %d, %v", n, err)
			}
			if st, _ := svc.state(row.TicketKey); st != "solved" {
				t.Fatalf("ticket state %q", st)
			}
			if got, _ := store.GetEvent(ctx, ev.ID); got.Status != itsm.StatusResolved {
				t.Fatalf("row status %q", got.Status)
			}

			// an outage retries; a refused credential fails the event for good
			ev2 := itsm.Event{ID: "renewal_failed:ee-ff:1", Class: "renewal_failed", CN: "b.example.com", Fingerprint: "ee-ff"}
			svc.setFail(http.StatusInternalServerError)
			if err := service.Submit(ctx, conn.ID, ev2); err != nil {
				t.Fatal(err)
			}
			if _, err := service.Drain(ctx); err != nil {
				t.Fatal(err)
			}
			row2, _ := store.GetEvent(ctx, ev2.ID)
			if row2.Status != itsm.StatusPending || row2.Attempts != 1 || !strings.Contains(row2.LastError, "temporary") {
				t.Fatalf("outage row %+v", row2)
			}
			svc.setFail(http.StatusUnauthorized)
			row2.NextAttemptAt = row2.NextAttemptAt.Add(-24 * time.Hour)
			if err := store.SaveEvent(ctx, row2, time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := service.Drain(ctx); err != nil {
				t.Fatal(err)
			}
			if row2, _ = store.GetEvent(ctx, ev2.ID); row2.Status != itsm.StatusFailed || !strings.Contains(row2.LastError, "permanent") {
				t.Fatalf("refused-credential row %+v", row2)
			}
			if err := service.TestConnection(ctx, conn.ID); !errors.Is(err, itsm.ErrPermanent) {
				t.Fatalf("test connection with a refused credential: %v", err)
			}

			// audit: native ticket rows, plugin rows with identity, no secret anywhere
			var created, resolved, pluginRows int
			everything := strings.Join(alerts, " ")
			for _, a := range audits {
				everything += a.ChangeSummary
				switch {
				case a.Action == itsm.ActionTicketCreate && a.Outcome == itsm.OutcomeSuccess:
					created++
				case a.Action == itsm.ActionTicketResolve && a.Outcome == itsm.OutcomeSuccess:
					resolved++
				}
			}
			for _, e := range pluginAudit.entries {
				everything += e.ChangeSummary
				if e.Action == "delivery_plugin.ticket" && e.ResourceID == pluginID && strings.Contains(e.ChangeSummary, "kind=ticket") && strings.Contains(e.ChangeSummary, "sha256=") {
					pluginRows++
				}
			}
			if created != 2 || resolved != 1 || pluginRows == 0 {
				t.Fatalf("audit rows: create=%d resolve=%d plugin=%d", created, resolved, pluginRows)
			}
			if strings.Contains(everything, tc.secret) || strings.Contains(row2.LastError, tc.secret) {
				t.Fatal("a credential leaked into an error, alert or audit row")
			}
		})
	}
}

func TestITSMPluginConnectionRefusals(t *testing.T) {
	ctx := context.Background()
	mgr := NewDeliveryPluginManager(notifyPluginDB(t), false, nil, nil)
	pluginID := installTicketPlugin(t, mgr, "zendesk")
	creds := &renewalFakeCredStore{meta: OutboundCredentialMeta{ID: "cred-1", CredentialType: CredentialTypeAPIToken}, payload: []byte(`{}`)}
	connectors := NewITSMPluginConnectors(func() *DeliveryPluginManager { return mgr }, nil)
	connectors.creds = func() OutboundCredentialStore { return creds }
	check := newITSMPluginCheck(connectors)
	pd := AuthPrincipal{ID: "admin", Role: "pki-admin"}

	if msg := check(ctx, pd, pluginID, "cred-1"); msg != "" {
		t.Fatalf("a good plugin and credential were refused: %s", msg)
	}
	if msg := check(ctx, pd, "no.such-plugin", "cred-1"); !strings.Contains(msg, "not an enabled plugin") {
		t.Errorf("unknown plugin: %q", msg)
	}
	creds.meta.CredentialType = "ssh_key"
	if msg := check(ctx, pd, pluginID, "cred-1"); !strings.Contains(msg, "api_token") {
		t.Errorf("wrong credential type: %q", msg)
	}
	creds.meta.CredentialType = CredentialTypeAPIToken

	// A notify plugin is not a ticket plugin.
	notifyID := installPlugin(t, mgr, "pagerduty")
	if msg := check(ctx, pd, notifyID, "cred-1"); !strings.Contains(msg, "not a ticket plugin") {
		t.Errorf("notify plugin as a ticket plugin: %q", msg)
	}
	f := connectors.Factory()
	if _, err := f(ctx, itsm.Connection{PluginID: notifyID, CredentialRef: "cred-1"}); err == nil || !strings.Contains(err.Error(), "not a ticket plugin") {
		t.Errorf("factory with a notify plugin: %v", err)
	}

	// A missing credential field fails before the plugin runs, naming the field and not any value.
	conn, err := f(ctx, itsm.Connection{PluginID: pluginID, CredentialRef: "cred-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Create(ctx, itsm.Event{ID: "e1", Class: "renewal_failed"}); err == nil || !strings.Contains(err.Error(), "missing required fields") {
		t.Errorf("incomplete credential: %v", err)
	}
	// The connector offers no approvals: the approval bridge skips it.
	if _, ok := conn.(itsm.ApprovalConnector); ok {
		t.Error("a plugin connector must not implement approvals in 1.1")
	}

	// Disabled: nothing runs; plugins off: fails closed.
	if err := mgr.Disable(ctx, pluginID); err != nil {
		t.Fatal(err)
	}
	if _, err := f(ctx, itsm.Connection{PluginID: pluginID, CredentialRef: "cred-1"}); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("disabled plugin: %v", err)
	}
	off := NewITSMPluginConnectors(func() *DeliveryPluginManager { return nil }, nil).Factory()
	if _, err := off(ctx, itsm.Connection{PluginID: pluginID}); err == nil || !strings.Contains(err.Error(), "turned off") {
		t.Errorf("plugins off: %v", err)
	}
}

func TestClassifyTicketError(t *testing.T) {
	if classifyTicketError(nil) != nil {
		t.Fatal("nil must stay nil")
	}
	perm := classifyTicketError(&plugindelivery.TicketError{Detail: "no"})
	if !errors.Is(perm, itsm.ErrPermanent) {
		t.Fatalf("%v", perm)
	}
	if !errors.Is(classifyTicketError(&plugindelivery.TicketError{Temporary: true}), itsm.ErrTemporary) || !errors.Is(classifyTicketError(errors.New("plugin trapped")), itsm.ErrTemporary) {
		t.Fatal("temporary failures and plugin errors must be retried")
	}
}
