// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/notifications/delivery"
)

// TestDeliveryChannelsFromEnv_WebhookReceivesDelivery proves acceptance #2/#3
// for W8-16: a WEBHOOK_URL configured the same way main() reads it actually
// reaches delivery.WebhookChannel and gets delivered through the same
// delivery.Worker main() constructs for the other channels -- not merely
// that "webhook" is a registered channel name. event.Target is deliberately
// NOT the server URL: WebhookChannel.Send posts to its configured c.URL and
// never reads event.Target, so leaving Target equal to srv.URL would pass
// even if the channel ignored the env-configured URL entirely.
func TestDeliveryChannelsFromEnv_WebhookReceivesDelivery(t *testing.T) {
	t.Cleanup(delivery.AllowLoopbackForTest()) // httptest server is on loopback
	var received bool
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("WEBHOOK_URL", srv.URL)

	channels := deliveryChannelsFromEnv(nil)
	worker := delivery.NewWorker(channels, 1, time.Millisecond)

	result := worker.Deliver(context.Background(), delivery.Event{
		ID:      "test-webhook-1",
		Channel: "webhook",
		Target:  "unused-target",
		Subject: "cert expiring",
		Message: "test delivery",
	})

	if result.Status != "sent" {
		t.Fatalf("Deliver status = %q, want %q (error: %s)", result.Status, "sent", result.Error)
	}
	if !received {
		t.Fatal("webhook test server never received a request -- WebhookChannel is registered but not actually delivering")
	}
	if gotBody == "" {
		t.Error("webhook request had an empty body")
	}
}

// TestDeliveryChannelsFromEnv_IncludesAllFourChannels guards against a
// silent regression dropping one of the four channels main() wires.
func TestDeliveryChannelsFromEnv_IncludesAllFourChannels(t *testing.T) {
	channels := deliveryChannelsFromEnv(nil)
	got := make(map[string]bool, len(channels))
	for _, ch := range channels {
		got[ch.Name()] = true
	}
	for _, want := range []string{"email", "slack", "pagerduty", "webhook"} {
		if !got[want] {
			t.Errorf("deliveryChannelsFromEnv() missing channel %q, got %v", want, got)
		}
	}
}

// TestDeliveryChannelsFromEnv_DBOverrideChangesNextSend is the W8-13
// acceptance #2 test for the notification-channel consumer: a DB override
// written through the real config store must change the SAME
// delivery.Channel/Worker's behaviour on its next Send, with no
// reconstruction. SLACK_WEBHOOK_URL is left unset so the first send has
// nowhere to go and fails; only the DB override (not an env fallback) makes
// the second send succeed.
func TestDeliveryChannelsFromEnv_DBOverrideChangesNextSend(t *testing.T) {
	t.Cleanup(delivery.AllowLoopbackForTest()) // httptest server is on loopback
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("APP_CREDENTIAL_STORE_PASSPHRASE", "test-passphrase-for-main-test")
	t.Setenv("SLACK_WEBHOOK_URL", "")

	store := bootstrap.NewConfigStoreFromEnv()
	if store == nil {
		t.Fatal("expected a real config store with passphrase + data dir configured")
	}

	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	channels := deliveryChannelsFromEnv(store)
	worker := delivery.NewWorker(channels, 1, time.Millisecond)

	first := worker.Deliver(context.Background(), delivery.Event{
		ID: "before-override", Channel: "slack", Subject: "test", Message: "test",
	})
	if first.Status == "sent" {
		t.Fatal("expected slack send to fail before any webhook URL is configured")
	}

	if err := store.Set(context.Background(), "notifications.slack_webhook_url", srv.URL, "test-operator"); err != nil {
		t.Fatalf("write override: %v", err)
	}

	// Same worker/channels -- no reconstruction -- picks up the override on
	// this next send.
	second := worker.Deliver(context.Background(), delivery.Event{
		ID: "after-override", Channel: "slack", Subject: "test", Message: "test",
	})
	if second.Status != "sent" {
		t.Fatalf("expected slack send to succeed after DB override, got %q (error: %s)", second.Status, second.Error)
	}
	if atomic.LoadInt32(&received) != 1 {
		t.Fatalf("expected exactly 1 request to reach the test server, got %d", received)
	}
}

// TestResolvePublicBaseURL covers W19-13: the hub must never advertise its
// bind address as its public URL (UAT W19-04 observed
// "dial tcp 0.0.0.0:8091: connection refused" from a real ACME client).
func TestResolvePublicBaseURL(t *testing.T) {
	tests := []struct {
		name        string
		envValue    string
		envSet      bool
		bindAddr    string
		port        string
		tlsEnabled  bool
		wantBaseURL string
		wantWarn    bool
		wantErr     bool
	}{
		{
			name:     "unset env, concrete bind address passes through",
			bindAddr: "192.168.1.10", port: "8080",
			wantBaseURL: "http://192.168.1.10:8080",
		},
		{
			name:     "unset env, loopback bind address passes through",
			bindAddr: "127.0.0.1", port: "8080",
			wantBaseURL: "http://127.0.0.1:8080",
		},
		{
			name:     "unset env, wildcard IPv4 bind falls back to loopback with a warning",
			bindAddr: "0.0.0.0", port: "8091",
			wantBaseURL: "http://127.0.0.1:8091", wantWarn: true,
		},
		{
			name:     "unset env, wildcard IPv6 bind falls back to loopback with a warning",
			bindAddr: "::", port: "8091",
			wantBaseURL: "http://127.0.0.1:8091", wantWarn: true,
		},
		{
			name:     "unset env, empty bind falls back to loopback with a warning",
			bindAddr: "", port: "8091",
			wantBaseURL: "http://127.0.0.1:8091", wantWarn: true,
		},
		{
			name:     "env set wins over a wildcard bind, no warning",
			envValue: "https://kk.example.com", envSet: true, tlsEnabled: true,
			bindAddr: "0.0.0.0", port: "8091",
			wantBaseURL: "https://kk.example.com",
		},
		{
			name:     "env set strips a trailing slash",
			envValue: "http://kk.example.com/", envSet: true,
			bindAddr: "0.0.0.0", port: "8091",
			wantBaseURL: "http://kk.example.com",
		},
		{
			name:     "env set but not an absolute URL fails startup",
			envValue: "kk.example.com", envSet: true,
			bindAddr: "0.0.0.0", port: "8091",
			wantErr: true,
		},
		{
			name:     "env set but wrong scheme fails startup",
			envValue: "ftp://kk.example.com", envSet: true,
			bindAddr: "0.0.0.0", port: "8091",
			wantErr: true,
		},
		{
			// W19-14: an https:// KRYPTKEEPER_BASE_URL while the hub is
			// actually serving plain HTTP would tell clients to speak the
			// wrong protocol to a socket not listening on it.
			name:     "env set to https but TLS disabled fails startup",
			envValue: "https://kk.example.com", envSet: true, tlsEnabled: false,
			bindAddr: "0.0.0.0", port: "8091",
			wantErr: true,
		},
		{
			name:     "TLS enabled, concrete bind address advertises https",
			bindAddr: "192.168.1.10", port: "8443", tlsEnabled: true,
			wantBaseURL: "https://192.168.1.10:8443",
		},
		{
			name:     "TLS enabled, wildcard bind falls back to https loopback with a warning",
			bindAddr: "0.0.0.0", port: "8443", tlsEnabled: true,
			wantBaseURL: "https://127.0.0.1:8443", wantWarn: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envSet {
				t.Setenv("KRYPTKEEPER_BASE_URL", tt.envValue)
			} else {
				t.Setenv("KRYPTKEEPER_BASE_URL", "")
			}

			got, warn, err := resolvePublicBaseURL(tt.bindAddr, tt.port, tt.tlsEnabled)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got baseURL=%q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantBaseURL {
				t.Errorf("baseURL = %q, want %q", got, tt.wantBaseURL)
			}
			if (warn != "") != tt.wantWarn {
				t.Errorf("warning presence = %v, want %v (warning: %q)", warn != "", tt.wantWarn, warn)
			}
		})
	}
}

// TestDeliveryChannelsFromEnv_SMTPReadsPortUsernamePassword is the W19-07
// regression test: config_store.go has registered notifications.smtp_port,
// notifications.smtp_username and notifications.smtp_password since W8-13,
// but deliveryChannelsFromEnv's email builder never read any of the three --
// it hardcoded Port: 587 and left Username/Password empty, so a Mailpit
// container (SMTP on 1025, found live during the notifications UAT) or any
// authenticated relay could never be reached regardless of configuration.
// This proves the builder now threads all three through, DB-override-first
// exactly like the other channels (resolveConfigString/resolveConfigSecret).
func TestDeliveryChannelsFromEnv_SMTPReadsPortUsernamePassword(t *testing.T) {
	t.Setenv("SMTP_HOST", "127.0.0.1")
	t.Setenv("SMTP_PORT", "1025")
	t.Setenv("SMTP_FROM", "alerts@example.com")
	t.Setenv("SMTP_USERNAME", "uat-user")
	t.Setenv("SMTP_PASSWORD", "uat-pass")

	channels := deliveryChannelsFromEnv(nil)
	var emailCh *configuredChannel
	for _, ch := range channels {
		if ch.Name() == "email" {
			emailCh, _ = ch.(*configuredChannel)
		}
	}
	if emailCh == nil {
		t.Fatal("no email channel returned")
	}
	built, ok := emailCh.build(context.Background()).(*delivery.SMTPChannel)
	if !ok {
		t.Fatalf("email channel did not build a *delivery.SMTPChannel: %T", emailCh.build(context.Background()))
	}
	if built.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want 127.0.0.1", built.Host)
	}
	if built.Port != 1025 {
		t.Errorf("Port = %d, want 1025 (SMTP_PORT ignored -- would always dial 587)", built.Port)
	}
	if built.Username != "uat-user" {
		t.Errorf("Username = %q, want uat-user", built.Username)
	}
	if built.Password != "uat-pass" {
		t.Errorf("Password = %q, want uat-pass", built.Password)
	}
}

// TestDeliveryChannelsFromEnv_SMTPPortDefaultsTo587 guards the fallback: an
// unset/invalid SMTP_PORT must still default to 587, not 0.
func TestDeliveryChannelsFromEnv_SMTPPortDefaultsTo587(t *testing.T) {
	t.Setenv("SMTP_PORT", "")
	channels := deliveryChannelsFromEnv(nil)
	for _, ch := range channels {
		if ch.Name() != "email" {
			continue
		}
		built := ch.(*configuredChannel).build(context.Background()).(*delivery.SMTPChannel)
		if built.Port != 587 {
			t.Errorf("Port = %d, want default 587", built.Port)
		}
	}
}
