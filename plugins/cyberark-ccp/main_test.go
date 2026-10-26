// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

func TestQueryNeedsAppIDAndObject(t *testing.T) {
	q, err := query(map[string]string{"app_id": "Kryptkeeper"}, map[string]string{"safe": "Infra", "object": "web1-root"})
	if err != nil || q.Get("AppID") != "Kryptkeeper" || q.Get("Safe") != "Infra" || q.Get("Object") != "web1-root" {
		t.Fatalf("%v %v", q, err)
	}
	if _, err := query(map[string]string{}, map[string]string{"object": "o"}); err == nil {
		t.Error("a missing app_id must be refused")
	}
	if _, err := query(map[string]string{"app_id": "a"}, map[string]string{"safe": "s"}); err == nil {
		t.Error("a reference without an object must be refused")
	}
	for _, bad := range []string{"a+b", "a&b", "a%b"} {
		if _, err := query(map[string]string{"app_id": "a"}, map[string]string{"object": bad}); err == nil {
			t.Errorf("%q must be refused: CCP documents these characters as unsupported", bad)
		}
	}
}

func TestLookupIgnoresCase(t *testing.T) {
	rec := map[string]any{"Username": "svc", "Content": "pw", "Safe": 7}
	if v, ok := lookup(rec, "UserName"); !ok || v != "svc" {
		t.Fatalf("UserName -> %q %v", v, ok)
	}
	if _, ok := lookup(rec, "Safe"); ok {
		t.Fatal("a non-string field is not a credential field")
	}
}

func TestFailureNeverQuotesTheBody(t *testing.T) {
	got := failure(abi.HTTPResponse{Status: 404, Body: []byte(`{"ErrorCode":"APPAP004E","ErrorMsg":"Password object secret-object not found"}`)})
	if strings.Contains(got, "secret-object") || !strings.Contains(got, "APPAP004E") || !strings.Contains(got, "no such account") {
		t.Fatalf("%q", got)
	}
	if got := failure(abi.HTTPResponse{Status: 403, Body: []byte(`{"ErrorCode":"not a code"}`)}); strings.Contains(got, "not a code") {
		t.Fatalf("%q", got)
	}
}
