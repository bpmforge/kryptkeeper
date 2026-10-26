// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"crypto/hmac"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const webhookMaxSkew = 300 * time.Second

// verifyWebhook is the reference verifier; docs/ops/WEBHOOK_VERIFY.md mirrors it.
func verifyWebhook(secret string, h http.Header, body []byte, now time.Time) error {
	sigHdr := h.Get(HeaderWebhookSignature)
	if sigHdr == "" {
		return errors.New("missing signature")
	}
	ts := h.Get(HeaderWebhookTimestamp)
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("bad timestamp")
	}
	if d := now.Sub(time.Unix(sec, 0)); d > webhookMaxSkew || d < -webhookMaxSkew {
		return errors.New("stale timestamp")
	}
	want := "v1=" + webhookMAC(secret, ts, body)
	for _, got := range strings.Split(sigHdr, ",") {
		if hmac.Equal([]byte(strings.TrimSpace(got)), []byte(want)) {
			return nil
		}
	}
	return errors.New("signature mismatch")
}

type capturedReq struct {
	header http.Header
	body   []byte
}

func captureServer(t *testing.T, status func(n int) int) (*httptest.Server, func() []capturedReq) {
	t.Helper()
	var mu sync.Mutex
	var reqs []capturedReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, capturedReq{r.Header.Clone(), b})
		n := len(reqs)
		mu.Unlock()
		w.WriteHeader(status(n))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []capturedReq { mu.Lock(); defer mu.Unlock(); return append([]capturedReq(nil), reqs...) }
}

func ok200(int) int { return 200 }

func TestWebhookSignature_RecomputesAndMatches(t *testing.T) {
	srv, got := captureServer(t, ok200)
	ch := &WebhookChannel{URL: srv.URL, Secret: "s3cret"}
	ev := Event{ID: "evt-sig", Channel: "webhook", Subject: "x", CreatedAt: time.Unix(1700000000, 0).UTC()}
	if err := ch.Send(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	r := got()[0]
	ts := r.header.Get(HeaderWebhookTimestamp)
	if ts == "" || r.header.Get(HeaderWebhookEventID) != "evt-sig" {
		t.Fatalf("headers missing: ts=%q id=%q", ts, r.header.Get(HeaderWebhookEventID))
	}
	if want := "v1=" + webhookMAC("s3cret", ts, r.body); r.header.Get(HeaderWebhookSignature) != want {
		t.Fatalf("signature mismatch: %q", r.header.Get(HeaderWebhookSignature))
	}
}

func TestWebhookEventID_StableAcrossRetries(t *testing.T) {
	srv, got := captureServer(t, func(n int) int {
		if n <= 2 {
			return 500
		}
		return 200
	})
	w := newSyncWorker([]Channel{&WebhookChannel{URL: srv.URL, Secret: "k"}}, 3)
	res := w.Deliver(context.Background(), Event{ID: "evt-retry", Channel: "webhook"})
	if res.Status != "sent" {
		t.Fatalf("status = %s", res.Status)
	}
	reqs := got()
	if len(reqs) != 3 {
		t.Fatalf("requests = %d", len(reqs))
	}
	for _, r := range reqs {
		if r.header.Get(HeaderWebhookEventID) != "evt-retry" {
			t.Errorf("event id = %q", r.header.Get(HeaderWebhookEventID))
		}
		if _, err := strconv.ParseInt(r.header.Get(HeaderWebhookTimestamp), 10, 64); err != nil {
			t.Errorf("timestamp: %v", err)
		}
	}
}

func TestWebhookVerifier_RejectsUnsignedAndStale(t *testing.T) {
	now := time.Unix(1700000000, 0)
	body := []byte(`{"a":1}`)
	rejected := 0

	unsigned := http.Header{}
	unsigned.Set(HeaderWebhookTimestamp, strconv.FormatInt(now.Unix(), 10))
	if verifyWebhook("k", unsigned, body, now) != nil {
		rejected++
	}

	oldTS := strconv.FormatInt(now.Add(-6*time.Minute).Unix(), 10)
	stale := http.Header{}
	stale.Set(HeaderWebhookTimestamp, oldTS)
	stale.Set(HeaderWebhookSignature, "v1="+webhookMAC("k", oldTS, body))
	if verifyWebhook("k", stale, body, now) != nil {
		rejected++
	}
	if rejected != 2 {
		t.Fatalf("rejected %d of 2", rejected)
	}

	freshTS := strconv.FormatInt(now.Unix(), 10)
	fresh := http.Header{}
	fresh.Set(HeaderWebhookTimestamp, freshTS)
	fresh.Set(HeaderWebhookSignature, "v1="+webhookMAC("k", freshTS, body))
	if err := verifyWebhook("k", fresh, body, now); err != nil {
		t.Fatalf("fresh rejected: %v", err)
	}
}

func TestWebhookRotation_DualThenSingle(t *testing.T) {
	srv, got := captureServer(t, ok200)
	t0 := time.Unix(1700000000, 0)
	cur := t0.Add(time.Hour)
	ch := &WebhookChannel{URL: srv.URL, Secret: "new", PreviousSecret: "old", PreviousUntil: t0.Add(24 * time.Hour), Now: func() time.Time { return cur }}
	ev := Event{ID: "evt-rot", Channel: "webhook"}
	if err := ch.Send(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	cur = t0.Add(24*time.Hour + time.Second)
	if err := ch.Send(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	reqs := got()
	parts := strings.Split(reqs[0].header.Get(HeaderWebhookSignature), ",")
	if len(parts) != 2 {
		t.Fatalf("want 2 signatures, got %v", parts)
	}
	ts := reqs[0].header.Get(HeaderWebhookTimestamp)
	if parts[0] != "v1="+webhookMAC("new", ts, reqs[0].body) || parts[1] != "v1="+webhookMAC("old", ts, reqs[0].body) {
		t.Fatal("dual signatures do not verify (new first, old second)")
	}
	ts2 := reqs[1].header.Get(HeaderWebhookTimestamp)
	if s := reqs[1].header.Get(HeaderWebhookSignature); s != "v1="+webhookMAC("new", ts2, reqs[1].body) {
		t.Fatalf("after window want single new signature, got %q", s)
	}
}

func TestWebhookUnsignedWhenNoSecret(t *testing.T) {
	srv, got := captureServer(t, ok200)
	ch := &WebhookChannel{URL: srv.URL}
	if err := ch.Send(context.Background(), Event{ID: "e1", Channel: "webhook"}); err != nil {
		t.Fatal(err)
	}
	h := got()[0].header
	if h.Get(HeaderWebhookSignature) != "" || h.Get(HeaderWebhookTimestamp) == "" || h.Get(HeaderWebhookEventID) != "e1" {
		t.Fatalf("unexpected headers: %v", h)
	}
}
