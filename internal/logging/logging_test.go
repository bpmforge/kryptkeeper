// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// isolate restores the process-global slog default and std log output.
func isolate(t *testing.T) {
	t.Helper()
	oldLogger, oldW, oldFlags, oldPrefix := slog.Default(), log.Writer(), log.Flags(), log.Prefix()
	t.Cleanup(func() {
		slog.SetDefault(oldLogger)
		log.SetOutput(oldW)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
	})
}

func setup(t *testing.T, cfg Config) *bytes.Buffer {
	t.Helper()
	isolate(t)
	buf := &bytes.Buffer{}
	cfg.Writer = buf
	Setup(cfg)
	return buf
}

func decode(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	line := strings.TrimSpace(buf.String())
	if strings.Count(line, "\n") != 0 || line == "" {
		t.Fatalf("want exactly one line, got %q", line)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("not JSON: %v: %q", err, line)
	}
	return m
}

func TestLinesAreJSONWithRequiredKeys(t *testing.T) {
	buf := setup(t, Config{})
	slog.InfoContext(WithRequestID(context.Background(), "req_abc"), "hello", "k", "v")
	m := decode(t, buf)
	if _, err := time.Parse(time.RFC3339Nano, m["ts"].(string)); err != nil {
		t.Fatalf("ts: %v", err)
	}
	if m["level"] != "info" || m["msg"] != "hello" || m["request_id"] != "req_abc" || m["k"] != "v" {
		t.Fatalf("unexpected line: %v", m)
	}
}

func TestRequestIDPresentOutsideRequest(t *testing.T) {
	buf := setup(t, Config{})
	slog.Info("boot")
	if !strings.Contains(buf.String(), `"request_id":""`) {
		t.Fatalf("request_id missing: %s", buf)
	}
	if strings.Contains(buf.String(), `"tenant"`) {
		t.Fatalf("tenant should be absent when unset: %s", buf)
	}
}

func TestTenantAndServiceFields(t *testing.T) {
	buf := setup(t, Config{Service: "hub"})
	slog.InfoContext(WithTenant(context.Background(), "acme"), "x")
	m := decode(t, buf)
	if m["tenant"] != "acme" || m["service"] != "hub" {
		t.Fatalf("unexpected line: %v", m)
	}
	if TenantFromContext(context.Background()) != "" {
		t.Fatal("tenant leaked into empty context")
	}
}

func TestStdLogBridgedToJSON(t *testing.T) {
	buf := setup(t, Config{})
	log.Printf("plain %d", 1)
	m := decode(t, buf)
	if m["level"] != "info" || m["msg"] != "plain 1" {
		t.Fatalf("unexpected line: %v", m)
	}
	if _, ok := m["request_id"]; !ok {
		t.Fatal("request_id missing")
	}
}

func TestSecretsNeverAppear(t *testing.T) {
	const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAfakefakefake\n-----END RSA PRIVATE KEY-----" // secret-scan:allow fake redaction fixture
	seeds := []string{
		"hunter2-S3cret", "abc123TOKENvalue",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig123",
		"MIIEowIBAAKCAQEAfakefakefake",
	}
	ctx := context.Background()
	cases := map[string]func(){
		"key password":   func() { slog.Info("m", "password", "hunter2-S3cret") },
		"authorization":  func() { slog.Info("m", "Authorization", "Bearer abc123TOKENvalue") },
		"bearer in val":  func() { slog.Info("m", "hdr", "Bearer abc123TOKENvalue") },
		"message kv":     func() { slog.Info("login password=hunter2-S3cret failed") },
		"std log":        func() { log.Printf("token: abc123TOKENvalue") },
		"error value":    func() { slog.Info("m", "err", errors.New("bad password=hunter2-S3cret")) },
		"nested group":   func() { slog.Info("m", slog.Group("req", slog.String("api_key", "hunter2-S3cret"))) },
		"jwt value":      func() { slog.Info("m", "note", "got eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig123") },
		"pem value":      func() { slog.Info("m", "blob", pem) },
		"pem message":    func() { slog.Info("key " + pem) },
		"context call":   func() { slog.InfoContext(ctx, "m", "client_secret", "hunter2-S3cret") },
		"cookie key":     func() { slog.Info("m", "Set-Cookie", "abc123TOKENvalue") },
		"private_key":    func() { slog.Info("m", "private_key", pem) },
		"credential":     func() { slog.Info("m", "credentials", "hunter2-S3cret") },
		"passphrase":     func() { slog.Info("m", "passphrase", "hunter2-S3cret") },
		"passwd":         func() { slog.Info("m", "passwd", "hunter2-S3cret") },
		"apikey":         func() { slog.Info("m", "apikey", "hunter2-S3cret") },
		"bearer key":     func() { slog.Info("m", "bearer", "abc123TOKENvalue") },
		"token key":      func() { slog.Info("m", "access_token", "abc123TOKENvalue") },
		"secret key":     func() { slog.Info("m", "secret", "hunter2-S3cret") },
		"json-ish value": func() { slog.Info(`body {"password":"hunter2-S3cret"}`) },
	}
	for name, emit := range cases {
		t.Run(name, func(t *testing.T) {
			buf := setup(t, Config{})
			emit()
			out := buf.String()
			for _, s := range seeds {
				if strings.Contains(out, s) {
					t.Fatalf("leaked %q in %s", s, out)
				}
			}
			if !strings.Contains(out, "[REDACTED") {
				t.Fatalf("no redaction marker in %s", out)
			}
		})
	}
}

func TestLevelFilterAndEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	buf := setup(t, ConfigFromEnv(env(map[string]string{"KRYPTKEEPER_LOG_LEVEL": "warn"})))
	slog.Info("quiet")
	slog.Warn("loud")
	if strings.Contains(buf.String(), "quiet") || !strings.Contains(buf.String(), "loud") {
		t.Fatalf("level filter wrong: %s", buf)
	}
	if got := ConfigFromEnv(env(map[string]string{"KRYPTKEEPER_LOG_LEVEL": "bogus"})).Level; got != slog.LevelInfo {
		t.Fatalf("bad level -> %v", got)
	}
	if got := ConfigFromEnv(env(nil)).Format; got != "json" {
		t.Fatalf("default format %q", got)
	}
	if got := ConfigFromEnv(env(map[string]string{"KRYPTKEEPER_LOG_LEVEL": "debug"})).Level; got != slog.LevelDebug {
		t.Fatalf("debug -> %v", got)
	}
}

func TestTextFormat(t *testing.T) {
	buf := setup(t, ConfigFromEnv(func(k string) string {
		if k == "KRYPTKEEPER_LOG_FORMAT" {
			return "text"
		}
		return ""
	}))
	slog.Info("hi", "password", "hunter2-S3cret")
	var m map[string]any
	if json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m) == nil {
		t.Fatalf("text format emitted JSON: %s", buf)
	}
	if strings.Contains(buf.String(), "hunter2-S3cret") {
		t.Fatalf("leak in text format: %s", buf)
	}
}

func TestWithAttrsAndGroupKeepRedaction(t *testing.T) {
	buf := setup(t, Config{})
	slog.Default().With("password", "hunter2-S3cret").WithGroup("g").Info("m", "token", "abc123TOKENvalue")
	out := buf.String()
	if strings.Contains(out, "hunter2-S3cret") || strings.Contains(out, "abc123TOKENvalue") {
		t.Fatalf("leak: %s", out)
	}
}

func TestEnsureDefaultDoesNotOverrideSetup(t *testing.T) {
	buf := setup(t, Config{})
	EnsureDefault()
	slog.Info("still mine")
	if !strings.Contains(buf.String(), "still mine") {
		t.Fatalf("EnsureDefault replaced the installed logger: %s", buf)
	}
}

func TestRedactLargeInput(t *testing.T) {
	// Guards against super-linear regex cost, not absolute speed: -race
	// slows regexp ~25x, so a wall-clock bound flakes in CI. Linear cost
	// means 4x the input takes ~4x the time; allow generous noise.
	unit := "password=x token:y Bearer z -----BEGIN PRIVATE KEY----- "
	timeIt := func(n int) time.Duration {
		big := strings.Repeat(unit, n/len(unit)+1)[:n]
		start := time.Now()
		_ = Redact(big)
		return time.Since(start)
	}
	small, large := timeIt(1<<18), timeIt(1<<20)
	if large > 10*small+50*time.Millisecond {
		t.Fatalf("Redact is super-linear: 256KiB took %v, 1MiB took %v", small, large)
	}
}
