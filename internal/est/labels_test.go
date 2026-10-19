// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package est

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	_ "modernc.org/sqlite"

	"kryptkeeper/internal/ca"
)

// labelRecorder satisfies both recorder interfaces and notes which was used.
type labelRecorder struct {
	mu         sync.Mutex
	plain      int
	templateID []string
}

func (r *labelRecorder) RecordIssuedCertificate(context.Context, string, *x509.Certificate, []byte, string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plain++
	return nil
}

func (r *labelRecorder) RecordIssuedCertificateWithTemplate(_ context.Context, _ string, _ *x509.Certificate, _ []byte, _, templateID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.templateID = append(r.templateID, templateID)
	return nil
}

type labelFixture struct {
	*estFixture
	ts       *httptest.Server
	gateFor  []string // template ids the gate factory was asked for
	rec      *labelRecorder
	denyTmpl string
}

func newLabelFixture(t *testing.T) *labelFixture {
	t.Helper()
	lf := &labelFixture{estFixture: newFixture(t).withBasic(t, ".devices.example.com"), rec: &labelRecorder{}}
	store := NewMemLabelStore()
	for label, tmpl := range map[string]string{"iot": "tmpl-iot", "locked": "tmpl-locked"} {
		if _, err := store.Create(context.Background(), Label{Label: label, TemplateID: tmpl, CreatedBy: "t"}); err != nil {
			t.Fatal(err)
		}
	}
	lf.denyTmpl = "tmpl-locked"
	lf.srv.WithIssuedRecorder(lf.rec).WithLabels(store, func(id string) EnrollmentGate {
		lf.gateFor = append(lf.gateFor, id)
		return func(context.Context, string) error {
			if id == lf.denyTmpl {
				return fmt.Errorf("%w: not allowed", ca.ErrEnrollmentDenied)
			}
			return nil
		}
	})
	lf.ts = lf.tlsServer(t)
	return lf
}

func deviceCSR(t *testing.T) string {
	return csrB64(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "sensor.devices.example.com"}})
}

func TestLabelRouteIssuesUnderLabelTemplate(t *testing.T) {
	lf := newLabelFixture(t)
	resp := post(t, lf.ts, "/.well-known/est/iot/simpleenroll", deviceCSR(t), call{user: "enroller", pass: "pw"})
	issuedCert(t, resp)
	if len(lf.gateFor) != 1 || lf.gateFor[0] != "tmpl-iot" {
		t.Fatalf("gate factory asked for %v, want [tmpl-iot]", lf.gateFor)
	}
	if len(lf.rec.templateID) != 1 || lf.rec.templateID[0] != "tmpl-iot" || lf.rec.plain != 0 {
		t.Fatalf("recorder: template ids %v, plain %d", lf.rec.templateID, lf.rec.plain)
	}
	last := lf.audit[len(lf.audit)-1]
	if last.Outcome != "success" || !strings.Contains(last.Detail, "label=iot") {
		t.Fatalf("audit %+v", last)
	}
}

func TestUnknownLabel404(t *testing.T) {
	lf := newLabelFixture(t)
	var want string
	for _, path := range []string{
		"/.well-known/est/nope/simpleenroll",      // unknown label
		"/.well-known/est/cacerts/simpleenroll",   // reserved label
		"/.well-known/est/Bad_Label/simpleenroll", // malformed
		"/.well-known/est/iot/serverkeygen",       // unimplemented op
		"/.well-known/est/iot/",                   // missing op
		"/.well-known/est/iot",                    // missing op, no slash
		"/.well-known/est/iot/simpleenroll/x",     // extra segment
	} {
		resp := post(t, lf.ts, path, deviceCSR(t), call{user: "enroller", pass: "pw"})
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: got %d", path, resp.StatusCode)
		}
		if want == "" {
			want = string(body)
		} else if string(body) != want {
			t.Fatalf("%s: body differs: %q vs %q", path, body, want)
		}
	}
	if len(lf.gateFor) != 0 {
		t.Fatalf("a 404 reached the gate: %v", lf.gateFor)
	}
}

func TestNoLabelStoreIs404(t *testing.T) {
	f := newFixture(t).withBasic(t, ".devices.example.com")
	ts := f.tlsServer(t)
	resp := post(t, ts, "/.well-known/est/iot/simpleenroll", deviceCSR(t), call{user: "enroller", pass: "pw"})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestBareRouteIsDefaultLabel(t *testing.T) {
	lf := newLabelFixture(t)
	var defaultGate int
	lf.srv.WithEnrollmentGate(func(context.Context, string) error { defaultGate++; return nil })
	issuedCert(t, post(t, lf.ts, "/.well-known/est/simpleenroll", deviceCSR(t), call{user: "enroller", pass: "pw"}))
	if defaultGate != 1 || len(lf.gateFor) != 0 {
		t.Fatalf("default gate %d, label gate factory %v", defaultGate, lf.gateFor)
	}
	if lf.rec.plain != 1 || len(lf.rec.templateID) != 0 {
		t.Fatalf("recorder: plain %d template %v", lf.rec.plain, lf.rec.templateID)
	}
}

func TestLabelGateDenialIs403AndAudited(t *testing.T) {
	lf := newLabelFixture(t)
	resp := post(t, lf.ts, "/.well-known/est/locked/simpleenroll", deviceCSR(t), call{user: "enroller", pass: "pw"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d", resp.StatusCode)
	}
	last := lf.audit[len(lf.audit)-1]
	if last.Outcome != "denied" || !strings.Contains(last.Detail, "label=locked") {
		t.Fatalf("audit %+v", last)
	}
	if len(lf.rec.templateID) != 0 {
		t.Fatal("denied enrollment was recorded")
	}
}

func TestLabelWithoutGateFactoryFailsClosed(t *testing.T) {
	f := newFixture(t).withBasic(t, ".devices.example.com")
	store := NewMemLabelStore()
	_, _ = store.Create(context.Background(), Label{Label: "iot", TemplateID: "t", CreatedBy: "x"})
	f.srv.WithLabels(store, nil)
	ts := f.tlsServer(t)
	resp := post(t, ts, "/.well-known/est/iot/simpleenroll", deviceCSR(t), call{user: "enroller", pass: "pw"})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("issued without a label gate")
	}
}

func TestEveryRouteExceptCACertsRequiresCredentials(t *testing.T) {
	setups := map[string]func(*labelFixture){
		"users": func(*labelFixture) {},
		"client-cert-only": func(lf *labelFixture) {
			lf.srv.users = nil
			lf.srv.WithClientCertAnchors(x509.NewCertPool())
		},
	}
	for name, setup := range setups {
		t.Run(name, func(t *testing.T) {
			lf := newLabelFixture(t)
			lf.srv.WithReenrollment(ca.NewMemRevocationStore())
			setup(lf)
			for _, prefix := range []string{"/.well-known/est", "/.well-known/est/iot"} {
				routes := []struct{ method, op string }{
					{http.MethodPost, "simpleenroll"}, {http.MethodPost, "simplereenroll"}, {http.MethodGet, "csrattrs"},
				}
				for _, rt := range routes {
					req, _ := http.NewRequest(rt.method, lf.ts.URL+prefix+"/"+rt.op, strings.NewReader(deviceCSR(t)))
					resp, err := lf.ts.Client().Do(req)
					if err != nil {
						t.Fatal(err)
					}
					_ = resp.Body.Close()
					if resp.StatusCode != http.StatusUnauthorized {
						t.Errorf("%s %s/%s: got %d, want 401", rt.method, prefix, rt.op, resp.StatusCode)
					}
				}
				resp, err := lf.ts.Client().Get(lf.ts.URL + prefix + "/cacerts")
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("%s/cacerts: got %d, want 200", prefix, resp.StatusCode)
				}
			}
		})
	}
}

func TestCSRAttrsWithValidBasicIs204(t *testing.T) {
	lf := newLabelFixture(t)
	for _, prefix := range []string{"/.well-known/est", "/.well-known/est/iot"} {
		req, _ := http.NewRequest(http.MethodGet, lf.ts.URL+prefix+"/csrattrs", nil)
		req.SetBasicAuth("enroller", "pw")
		resp, err := lf.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("%s: got %d, want 204", prefix, resp.StatusCode)
		}
		req.SetBasicAuth("enroller", "wrong")
		resp, _ = lf.ts.Client().Do(req)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s bad password: got %d, want 401", prefix, resp.StatusCode)
		}
	}
}

func TestValidLabel(t *testing.T) {
	for in, want := range map[string]bool{
		"iot": true, "a": true, "a-b": true, "0day": true, strings.Repeat("a", 32): true,
		"": false, "-a": false, "a-": false, "A": false, "a_b": false, "a.b": false, strings.Repeat("a", 33): false,
		"cacerts": false, "simpleenroll": false, "simplereenroll": false, "csrattrs": false, "serverkeygen": false, "fullcmc": false,
	} {
		if got := ValidLabel(in); got != want {
			t.Errorf("ValidLabel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestLabelStores(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "l.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	dbs := NewDBLabelStore(db, false)
	if err := dbs.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, st := range map[string]LabelStore{"mem": NewMemLabelStore(), "db": dbs} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if _, err := st.Get(ctx, "a"); !errors.Is(err, ErrLabelNotFound) {
				t.Fatalf("get missing: %v", err)
			}
			if _, err := st.Create(ctx, Label{Label: "a", TemplateID: "t1", CreatedBy: "u"}); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Create(ctx, Label{Label: "a", TemplateID: "t1", CreatedBy: "u"}); !errors.Is(err, ErrLabelExists) {
				t.Fatalf("duplicate: %v", err)
			}
			if _, err := st.Update(ctx, "a", "t2", "d"); err != nil {
				t.Fatal(err)
			}
			got, err := st.Get(ctx, "a")
			if err != nil || got.TemplateID != "t2" || got.Description != "d" || got.CreatedBy != "u" {
				t.Fatalf("got %+v %v", got, err)
			}
			if l, _ := st.List(ctx); len(l) != 1 {
				t.Fatalf("list %v", l)
			}
			if _, err := st.Update(ctx, "zz", "t", ""); !errors.Is(err, ErrLabelNotFound) {
				t.Fatalf("update missing: %v", err)
			}
			if err := st.Delete(ctx, "a"); err != nil {
				t.Fatal(err)
			}
			if err := st.Delete(ctx, "a"); !errors.Is(err, ErrLabelNotFound) {
				t.Fatalf("delete missing: %v", err)
			}
		})
	}
}
