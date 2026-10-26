// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

func req(class string) abi.NotifySendRequest {
	return abi.NotifySendRequest{
		Invocation: abi.Invocation{Credential: map[string]string{"routing_key": "rk"}},
		EventClass: class, Severity: abi.SeverityHigh, Title: "T", Body: "B", DedupeKey: "k1",
		Fields: map[string]string{"cn": "a.example.com"}, DeepLink: "https://kk.example.com/c/1",
	}
}

func TestTriggerShape(t *testing.T) {
	ev, err := build(req("certificate.expiry"))
	if err != nil {
		t.Fatal(err)
	}
	if ev.EventAction != "trigger" || ev.DedupKey != "k1" || ev.Payload.Severity != "error" || ev.Payload.Summary != "T: B" || ev.Payload.Source != "kryptkeeper" {
		t.Fatalf("%+v %+v", ev, ev.Payload)
	}
	if len(ev.Links) != 1 || ev.Payload.CustomDetails["cn"] != "a.example.com" {
		t.Fatalf("links/details missing: %+v", ev)
	}
}

func TestResolveCarriesOnlyTheKey(t *testing.T) {
	ev, err := build(req("certificate.expiry.resolved"))
	if err != nil || ev.EventAction != "resolve" || ev.DedupKey != "k1" || ev.Payload != nil {
		t.Fatalf("%+v err %v", ev, err)
	}
}

func TestLimitsAndMapping(t *testing.T) {
	r := req("x")
	r.Title = strings.Repeat("é", 2000)
	ev, _ := build(r)
	if len(ev.Payload.Summary) > maxSummary {
		t.Fatalf("summary %d bytes", len(ev.Payload.Summary))
	}
	r.DedupeKey = strings.Repeat("a", 300)
	r2 := r
	r2.DedupeKey = strings.Repeat("a", 299) + "b"
	a, _ := build(r)
	b, _ := build(r2)
	if len(a.DedupKey) > maxDedup || a.DedupKey == b.DedupKey {
		t.Fatalf("long keys must hash to distinct short ones: %q %q", a.DedupKey, b.DedupKey)
	}
	r.DedupeKey = ""
	if _, err := build(r); err == nil {
		t.Fatal("a missing dedupe key must be refused")
	}
	for in, want := range map[string]string{"critical": "critical", "high": "error", "medium": "warning", "low": "info", "": "info"} {
		if got := severity(in); got != want {
			t.Errorf("severity(%q)=%q want %q", in, got, want)
		}
	}
	r.DedupeKey, r.DeepLink = "k", "http://insecure.example.com"
	if ev, _ := build(r); len(ev.Links) != 0 {
		t.Fatal("a non-https deep link must be dropped")
	}
}
