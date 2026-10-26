// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// W38-02: the real first-party notify plugins (compiled to wasm), run through
// the hub's own path: plugin manager, "plugin" delivery channel, delivery
// worker, rule-target validation and audit, against local TLS stand-ins.

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/notifications/delivery"
	"kryptkeeper/tests/plugins/conformance"
)

type seenRequest struct {
	Path, Query, Auth string
	Body              map[string]any
}

// standIn is a TLS receiver that answers every request with status and
// records what it got.
type standIn struct {
	ts     *httptest.Server
	mu     sync.Mutex
	status int
	seen   []seenRequest
}

func newStandIn(t *testing.T) *standIn {
	s := &standIn{status: http.StatusAccepted}
	s.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		s.mu.Lock()
		s.seen = append(s.seen, seenRequest{Path: r.URL.Path, Query: r.URL.RawQuery, Auth: r.Header.Get("Authorization"), Body: body})
		status := s.status
		s.mu.Unlock()
		w.WriteHeader(status)
		if status == http.StatusAccepted {
			_, _ = w.Write([]byte(`{"requestId":"req-live-1","status":"success"}`))
		}
	}))
	t.Cleanup(s.ts.Close)
	return s
}

func (s *standIn) setStatus(code int) { s.mu.Lock(); s.status = code; s.mu.Unlock() }
func (s *standIn) requests() []seenRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]seenRequest(nil), s.seen...)
}

// client dials the stand-in whatever host the plugin names, verifying TLS
// against its certificate as example.com.
func (s *standIn) client() *http.Client {
	addr := s.ts.Listener.Addr().String()
	tr := s.ts.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12, ServerName: "example.com"}
	return &http.Client{Transport: tr}
}

func notifyPluginDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "notify-plugins.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	return db
}

func repoDir(rel string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", rel)
}

// installPlugin builds plugins/<name>, installs and enables it, and returns
// its id.
func installPlugin(t *testing.T, mgr *DeliveryPluginManager, name string) string {
	t.Helper()
	dir := repoDir("plugins/" + name)
	wasm := conformance.Build(t, dir)
	manifest := conformance.PinManifest(t, dir, wasm)
	v, err := mgr.Install(context.Background(), manifest, wasm, "", "admin")
	if err != nil {
		t.Fatalf("install %s: %v", name, err)
	}
	if v.Kind != abi.KindNotify {
		t.Fatalf("%s kind %q", name, v.Kind)
	}
	if err := mgr.enable(context.Background(), v.PluginID, v.Version, "approver"); err != nil {
		t.Fatal(err)
	}
	return v.PluginID
}

func notifyChannel(mgr *DeliveryPluginManager, creds OutboundCredentialStore, client *http.Client, audit AuditProvider) *PluginNotifyChannel {
	ch := NewPluginNotifyChannel(func() *DeliveryPluginManager { return mgr }, audit)
	ch.creds = func() OutboundCredentialStore { return creds }
	ch.client = client
	return ch
}

func TestNotifyPluginsRunInTheHub(t *testing.T) {
	cases := []struct {
		dir, secretKey, secret, payload string
		check                           func(t *testing.T, r seenRequest)
	}{
		{"pagerduty", "routing_key", "pd-routing-key-0123456789abcdef", `{"api_base":"https://events.pagerduty.com","routing_key":"pd-routing-key-0123456789abcdef"}`,
			func(t *testing.T, r seenRequest) {
				p, _ := r.Body["payload"].(map[string]any)
				if r.Path != "/v2/enqueue" || r.Body["event_action"] != "trigger" || r.Body["dedup_key"] != "expiry-abcd" || p["severity"] != "critical" {
					t.Fatalf("pagerduty saw %+v", r)
				}
			}},
		{"opsgenie", "api_key", "og-api-key-0123456789abcdef", `{"api_key":"og-api-key-0123456789abcdef"}`,
			func(t *testing.T, r seenRequest) {
				if r.Path != "/v2/alerts" || r.Auth != "GenieKey og-api-key-0123456789abcdef" || r.Body["alias"] != "expiry-abcd" || r.Body["priority"] != "P1" {
					t.Fatalf("opsgenie saw %+v", r)
				}
			}},
		{"microsoft-teams", "webhook_url", "https://flow.example.com/workflows/abc/invoke?sig=teams-secret-signature", `{"webhook_url":"https://flow.example.com/workflows/abc/invoke?sig=teams-secret-signature"}`,
			func(t *testing.T, r seenRequest) {
				atts, _ := r.Body["attachments"].([]any)
				if r.Path != "/workflows/abc/invoke" || r.Body["type"] != "message" || len(atts) != 1 {
					t.Fatalf("teams saw %+v", r)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			mgr := NewDeliveryPluginManager(notifyPluginDB(t), false, nil, nil)
			id := installPlugin(t, mgr, tc.dir)
			rx := newStandIn(t)
			audit := &scepRecordingAudit{}
			creds := &renewalFakeCredStore{meta: OutboundCredentialMeta{ID: "cred-1", CredentialType: CredentialTypeAPIToken}, payload: []byte(tc.payload)}
			ch := notifyChannel(mgr, creds, rx.client(), audit)
			// One attempt per Deliver: retry scheduling is the Retrier's own
			// concern (W32-31) and is tested there; this checks the plugin path.
			worker := delivery.NewRetrier([]delivery.Channel{ch}, delivery.Policy{MaxAttempts: 1, Base: time.Millisecond, Cap: time.Millisecond, Lease: time.Second}, nil, nil)
			ev := delivery.Event{
				ID: "expiry-abcd", Channel: pluginChannelName, Target: id + "/cred-1", Subject: "Certificate shop.example.com expires in 5 days",
				Message: "Renewal failed twice.", Priority: "critical", Class: "certificate.expiry",
				Fields: map[string]string{"common_name": "shop.example.com"}, DeepLink: "https://kk.example.com/certificates/abcd",
			}

			res := worker.Deliver(context.Background(), ev)
			if res.Status != "sent" || res.Attempts != 1 {
				t.Fatalf("result %+v", res)
			}
			got := rx.requests()
			if len(got) != 1 {
				t.Fatalf("stand-in saw %d requests", len(got))
			}
			tc.check(t, got[0])

			// A failing service is a failed delivery, and the plugin's error
			// carries neither the key nor the webhook URL.
			rx.setStatus(http.StatusInternalServerError)
			res = worker.Deliver(context.Background(), ev)
			if res.Status != "failed" || res.Attempts != 1 || !strings.Contains(res.Error, id) {
				t.Fatalf("failure result %+v", res)
			}
			rx.setStatus(http.StatusTooManyRequests)
			if res = worker.Deliver(context.Background(), ev); res.Status != "failed" {
				t.Fatalf("rate-limited result %+v", res)
			}

			var sawSuccess, sawFailure bool
			for _, e := range audit.entries {
				if e.Action != "delivery_plugin.notify" || e.ResourceID != id {
					continue
				}
				if !strings.Contains(e.ChangeSummary, "kind=notify") || !strings.Contains(e.ChangeSummary, "sha256=") {
					t.Fatalf("audit lacks plugin identity: %+v", e)
				}
				sawSuccess = sawSuccess || e.Outcome == AuditOutcomeSuccess
				sawFailure = sawFailure || e.Outcome == AuditOutcomeFailure
			}
			if !sawSuccess || !sawFailure {
				t.Fatalf("audit rows missing (success=%v failure=%v): %+v", sawSuccess, sawFailure, audit.entries)
			}
			everything := res.Error
			for _, e := range audit.entries {
				everything += e.ChangeSummary
			}
			if strings.Contains(everything, tc.secret) || strings.Contains(everything, "teams-secret-signature") {
				t.Fatalf("a credential leaked into errors or audit: %q", everything)
			}
		})
	}
}

func TestPluginChannelRefusals(t *testing.T) {
	ctx := context.Background()
	mgr := NewDeliveryPluginManager(notifyPluginDB(t), false, nil, nil)
	id := installPlugin(t, mgr, "pagerduty")
	creds := &renewalFakeCredStore{meta: OutboundCredentialMeta{ID: "cred-1", CredentialType: CredentialTypeAPIToken}, payload: []byte(`{"routing_key":"k-0123456789"}`)}
	ch := notifyChannel(mgr, creds, nil, nil)
	send := func(target string) error {
		return ch.Send(ctx, delivery.Event{ID: "e1", Channel: pluginChannelName, Target: target, Subject: "s", Priority: "high"})
	}

	for target, want := range map[string]string{
		"":                      "target must be",
		id:                      "target must be",
		id + "/":                "target must be",
		"no.such-plugin/cred-1": "not found",
	} {
		if err := send(target); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("target %q: %v, want %q", target, err, want)
		}
	}

	// A delivery plugin is not a notify plugin, even when enabled.
	wasm, _ := examplePlugin(t)
	if _, err := mgr.Install(ctx, manifestVariant(t, "1.0.0", nil), wasm, "", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.enable(ctx, "kryptkeeper.example-device", "1.0.0", "approver"); err != nil {
		t.Fatal(err)
	}
	if err := send("kryptkeeper.example-device/cred-1"); err == nil || !strings.Contains(err.Error(), "not a notify plugin") {
		t.Errorf("delivery plugin as notify target: %v", err)
	}

	// A wrong-typed credential is refused before the plugin runs.
	creds.meta.CredentialType = "ssh_key"
	if err := send(id + "/cred-1"); err == nil || !strings.Contains(err.Error(), "api_token") {
		t.Errorf("wrong credential type: %v", err)
	}
	creds.meta.CredentialType = CredentialTypeAPIToken

	// Disabled: nothing runs.
	if err := mgr.Disable(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := send(id + "/cred-1"); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("disabled plugin: %v", err)
	}

	// Plugins off: the channel fails closed.
	off := notifyChannel(nil, creds, nil, nil)
	if err := off.Send(ctx, delivery.Event{Target: id + "/cred-1"}); err == nil || !strings.Contains(err.Error(), "turned off") {
		t.Errorf("plugins off: %v", err)
	}
}

// A delivery plugin is never used for a renewal target when it is really a
// notify plugin, and a plugin id keeps its kind across versions.
func TestPluginKindsAreEnforcedInTheStore(t *testing.T) {
	ctx := context.Background()
	mgr := NewDeliveryPluginManager(notifyPluginDB(t), false, nil, nil)
	id := installPlugin(t, mgr, "pagerduty")

	exec := NewRenewalExecutor(nil, &renewalFakeCredStore{meta: OutboundCredentialMeta{CredentialType: CredentialTypeAPIToken}, payload: []byte(`{}`)}).WithPluginDeliverer(mgr, nil)
	if _, err := exec.preparePlugin(ctx, ManagedTarget{PluginID: id, CredentialRef: "c"}); err == nil || !strings.Contains(err.Error(), "not a delivery plugin") {
		t.Errorf("notify plugin as a delivery target: %v", err)
	}

	dir := repoDir("plugins/pagerduty")
	wasm := conformance.Build(t, dir)
	var m map[string]any
	if err := json.Unmarshal(conformance.PinManifest(t, dir, wasm), &m); err != nil {
		t.Fatal(err)
	}
	m["version"] = "1.0.1"
	delete(m, "kind")
	asDelivery, _ := json.Marshal(m)
	if _, err := mgr.Install(ctx, asDelivery, wasm, "", "admin"); err == nil || !strings.Contains(err.Error(), "keeps one kind") {
		t.Errorf("kind change across versions: %v", err)
	}

	// A kind the hub has no operations for yet is refused at install.
	m["kind"], m["version"], m["id"] = "inventory", "1.0.0", "kryptkeeper.future-inventory"
	future, _ := json.Marshal(m)
	if _, err := mgr.Install(ctx, future, wasm, "", "admin"); err == nil || !strings.Contains(err.Error(), "does not run plugins of that kind") {
		t.Errorf("unrunnable kind: %v", err)
	}
}

func TestPluginChannelTargetValidation(t *testing.T) {
	ctx := context.Background()
	mgr := NewDeliveryPluginManager(notifyPluginDB(t), false, nil, nil)
	id := installPlugin(t, mgr, "opsgenie")
	creds := &renewalFakeCredStore{meta: OutboundCredentialMeta{ID: "cred-1", CredentialType: CredentialTypeAPIToken}, payload: []byte(`{}`)}
	check := newPluginChannelTarget(notifyChannel(mgr, creds, nil, nil))
	pd := AuthPrincipal{ID: "admin", Role: "pki-admin"}

	if msg := check(ctx, pd, id+"/cred-1"); msg != "" {
		t.Fatalf("a good target was refused: %s", msg)
	}
	for target, want := range map[string]string{
		"nonsense":              "target must be",
		"no.such-plugin/cred-1": "not an enabled plugin",
	} {
		if msg := check(ctx, pd, target); !strings.Contains(msg, want) {
			t.Errorf("%q: %q, want %q", target, msg, want)
		}
	}
	creds.meta.CredentialType = "ssh_key"
	if msg := check(ctx, pd, id+"/cred-1"); !strings.Contains(msg, "api_token") {
		t.Errorf("wrong credential type: %q", msg)
	}
	if msg := pluginTargetProblem(ctx, nil, pd, id+"/cred-1"); !strings.Contains(msg, "not available") {
		t.Errorf("no plugin channel wired: %q", msg)
	}
}

func TestNotifyRequestMapping(t *testing.T) {
	r := notifyRequest(delivery.Event{ID: "e1", Subject: "s", Message: "m", Priority: "bogus"})
	if r.EventClass != "notification" || r.Severity != abi.SeverityMedium || r.DedupeKey != "e1" || r.Title != "s" || r.Body != "m" {
		t.Fatalf("%+v", r)
	}
	r = notifyRequest(delivery.Event{ID: "e2", Class: "certificate.expiry.resolved", Priority: "low"})
	if r.EventClass != "certificate.expiry.resolved" || r.Severity != abi.SeverityLow {
		t.Fatalf("%+v", r)
	}
}
