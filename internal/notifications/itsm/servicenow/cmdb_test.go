// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package servicenow

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"kryptkeeper/internal/notifications/itsm"
)

func cmdbConnector(t *testing.T, h http.HandlerFunc) *Connector {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, Credentials{testUser, testPass}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLookupOwner_Found(t *testing.T) {
	var query, fields string
	c := cmdbConnector(t, func(w http.ResponseWriter, r *http.Request) {
		query, fields = r.URL.Query().Get("sysparm_query"), r.URL.Query().Get("sysparm_fields")
		if r.URL.Path != "/api/now/table/cmdb_ci" {
			t.Errorf("path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"result":[{"owned_by.email":"o@example.com","support_group.name":"Platform"}]}`))
	})
	o, ok, err := c.LookupOwner(context.Background(), "Web01.Example.com")
	if err != nil || !ok || o.OwnerEmail != "o@example.com" || o.OwnerTeam != "Platform" {
		t.Fatalf("got %+v %v %v", o, ok, err)
	}
	if query != "fqdn=web01.example.com^ORname=web01.example.com" || fields != "owned_by.email,support_group.name" {
		t.Fatalf("query %q fields %q", query, fields)
	}
}

func TestLookupOwner_NotFoundCases(t *testing.T) {
	for name, body := range map[string]string{"empty": `{"result":[]}`, "blank": `{"result":[{"owned_by.email":"","support_group.name":""}]}`} {
		c := cmdbConnector(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
		if _, ok, err := c.LookupOwner(context.Background(), "h.example.com"); ok || err != nil {
			t.Errorf("%s: ok=%v err=%v", name, ok, err)
		}
	}
}

func TestLookupOwner_RejectsQueryInjection(t *testing.T) {
	c := cmdbConnector(t, func(http.ResponseWriter, *http.Request) { t.Error("must not call ServiceNow") })
	for _, h := range []string{"a^ORsys_idISNOTEMPTY", "*.example.com", "", "a b"} {
		if _, ok, err := c.LookupOwner(context.Background(), h); ok || err != nil {
			t.Errorf("%q: ok=%v err=%v", h, ok, err)
		}
	}
}

func TestLookupOwner_ErrorMapping(t *testing.T) {
	for code, want := range map[int]error{500: itsm.ErrTemporary, 429: itsm.ErrTemporary, 401: itsm.ErrPermanent, 403: itsm.ErrPermanent} {
		c := cmdbConnector(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
		if _, _, err := c.LookupOwner(context.Background(), "h.example.com"); !errors.Is(err, want) {
			t.Errorf("%d: %v", code, err)
		}
	}
}
