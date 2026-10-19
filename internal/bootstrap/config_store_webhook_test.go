// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
	"time"
)

func TestResolveWebhookSigning_PreviousWindowFromUpdatedAt(t *testing.T) {
	s := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()
	for k, v := range map[string]string{"notifications.webhook_secret": "new", "notifications.webhook_secret_previous": "old"} {
		if err := s.Set(ctx, k, v, "admin-1"); err != nil {
			t.Fatal(err)
		}
	}
	entry, _, _ := s.Get(ctx, "notifications.webhook_secret_previous")
	updated, err := time.Parse(time.RFC3339, entry.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	got := ResolveWebhookSigning(ctx, s, time.Unix(0, 0))
	if got.Secret != "new" || got.Previous != "old" {
		t.Fatalf("secrets = %q/%q", got.Secret, got.Previous)
	}
	if d := got.PreviousUntil.Sub(updated.Add(24 * time.Hour)); d < -2*time.Second || d > 2*time.Second {
		t.Fatalf("PreviousUntil off by %v", d)
	}

	t.Setenv("WEBHOOK_SECRET_PREVIOUS", "envold")
	since := time.Unix(1700000000, 0)
	env := ResolveWebhookSigning(ctx, newFreshConfigStore(t, []byte("test-passphrase")), since)
	if env.Previous != "envold" || !env.PreviousUntil.Equal(since.Add(24*time.Hour)) {
		t.Fatalf("env previous = %q until %v", env.Previous, env.PreviousUntil)
	}
}
