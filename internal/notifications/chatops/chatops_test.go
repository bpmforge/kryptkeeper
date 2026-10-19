// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package chatops

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func sign(secret string, ts time.Time, body string) http.Header {
	t := strconv.FormatInt(ts.Unix(), 10)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("v0:" + t + ":" + body))
	h := http.Header{}
	h.Set("X-Slack-Request-Timestamp", t)
	h.Set("X-Slack-Signature", "v0="+hex.EncodeToString(m.Sum(nil)))
	return h
}

func TestVerifySlackSignature_Valid(t *testing.T) {
	now := time.Now()
	if err := VerifySlackSignature("s3cret", sign("s3cret", now, "a=b"), []byte("a=b"), now); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySlackSignature_BadSignature(t *testing.T) {
	now := time.Now()
	h := sign("other", now, "a=b")
	if err := VerifySlackSignature("s3cret", h, []byte("a=b"), now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong secret: %v", err)
	}
	h = sign("s3cret", now, "a=b")
	if err := VerifySlackSignature("s3cret", h, []byte("a=c"), now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered body: %v", err)
	}
	h.Set("X-Slack-Signature", "v1="+strings.TrimPrefix(h.Get("X-Slack-Signature"), "v0="))
	if err := VerifySlackSignature("s3cret", h, []byte("a=b"), now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong version: %v", err)
	}
}

func TestVerifySlackSignature_StaleTimestamp(t *testing.T) {
	now := time.Now()
	for _, d := range []time.Duration{-6 * time.Minute, 6 * time.Minute} {
		h := sign("s3cret", now.Add(d), "a=b")
		if err := VerifySlackSignature("s3cret", h, []byte("a=b"), now); !errors.Is(err, ErrStaleTimestamp) {
			t.Fatalf("%v: %v", d, err)
		}
	}
}

func TestVerifySlackSignature_MissingHeaders(t *testing.T) {
	now := time.Now()
	h := sign("s3cret", now, "a=b")
	h.Del("X-Slack-Signature")
	if err := VerifySlackSignature("s3cret", h, []byte("a=b"), now); !errors.Is(err, ErrMissingHeaders) {
		t.Fatal(err)
	}
	h = sign("s3cret", now, "a=b")
	h.Del("X-Slack-Request-Timestamp")
	if err := VerifySlackSignature("s3cret", h, []byte("a=b"), now); !errors.Is(err, ErrMissingHeaders) {
		t.Fatal(err)
	}
}

func TestVerifySlackSignature_EmptySecretFailsClosed(t *testing.T) {
	now := time.Now()
	if err := VerifySlackSignature("", sign("", now, "a=b"), []byte("a=b"), now); !errors.Is(err, ErrBadSignature) {
		t.Fatal(err)
	}
}

func TestReplayGuard_SecondUseRejected_ExpiresAfterWindow(t *testing.T) {
	g := NewReplayGuard()
	now := time.Now()
	if g.Seen("sig", now) {
		t.Fatal("first use flagged")
	}
	if !g.Seen("sig", now.Add(time.Minute)) {
		t.Fatal("second use not flagged")
	}
	if g.Seen("sig", now.Add(MaxSkew+2*time.Minute)) {
		t.Fatal("entry should have expired")
	}
}

func payloadBody(js string) []byte { return []byte("payload=" + url.QueryEscape(js)) }

func TestParseInteraction(t *testing.T) {
	js := `{"type":"block_actions","team":{"id":"T1"},"user":{"id":"U1","username":"ann"},
	 "actions":[{"action_id":"kk_approve","value":"approval:apr-1"}],"response_url":"https://hooks.slack.com/x"}`
	in, err := ParseInteraction(payloadBody(js))
	if err != nil {
		t.Fatal(err)
	}
	if in.TeamID != "T1" || in.UserID != "U1" || in.UserName != "ann" || in.ActionID != ActionApprove || in.Value != "approval:apr-1" || in.ResponseURL == "" {
		t.Fatalf("%+v", in)
	}
	for _, bad := range [][]byte{[]byte("x=y"), payloadBody(`{`), payloadBody(`{"type":"view_submission"}`),
		payloadBody(`{"type":"block_actions","team":{"id":"T"},"user":{"id":"U"},"actions":[]}`)} {
		if _, err := ParseInteraction(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestParseValue_RejectsTraversal(t *testing.T) {
	if k, id, err := ParseValue("action:abc-1_2"); err != nil || k != "action" || id != "abc-1_2" {
		t.Fatalf("%s %s %v", k, id, err)
	}
	for _, bad := range []string{"approval:../x", "approval:a/b", "approval:", "other:abc", "approval:" + strings.Repeat("a", 65), "approval:a b", "action:a?x=1", ""} {
		if _, _, err := ParseValue(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestSQLIdentityStore_RoundTrip(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := NewSQLIdentityStore(db, func(int) string { return "?" })
	ctx := context.Background()
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatal("not idempotent: ", err)
	}
	id := Identity{Platform: "slack", Workspace: "T1", ExternalID: "U1"}
	if _, ok, _ := s.Lookup(ctx, id); ok {
		t.Fatal("unexpected row")
	}
	if err := s.Upsert(ctx, Mapping{Identity: id, KryptkeeperUser: "u-a", Tenant: "acme", CreatedAt: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(ctx, Mapping{Identity: id, KryptkeeperUser: "u-b", Tenant: "acme", CreatedAt: "t2"}); err != nil {
		t.Fatal(err)
	}
	m, ok, err := s.Lookup(ctx, id)
	if err != nil || !ok || m.KryptkeeperUser != "u-b" {
		t.Fatalf("%+v %v %v", m, ok, err)
	}
	if l, _ := s.List(ctx, "acme"); len(l) != 1 {
		t.Fatalf("list %+v", l)
	}
	if l, _ := s.List(ctx, "other"); len(l) != 0 {
		t.Fatalf("tenant leak %+v", l)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Lookup(ctx, id); ok {
		t.Fatal("not deleted")
	}
}
