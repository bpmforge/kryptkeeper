// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package logging is the hub's structured-logging foundation: a slog handler
// with stable keys (ts, level, msg, request_id), request/tenant context
// helpers, and secret redaction. It is stdlib-only and must not import
// internal/bootstrap (depguard), which is why the context keys live here.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config selects the handler. Zero value: Info, JSON, os.Stderr.
type Config struct {
	Level   slog.Level
	Format  string // "json" (default) | "text"
	Writer  io.Writer
	Service string // optional constant field "service"
}

// ConfigFromEnv reads KRYPTKEEPER_LOG_LEVEL and KRYPTKEEPER_LOG_FORMAT.
// Unknown values fall back to the defaults; it never fails, because a typo in
// a log setting must not stop the hub from starting.
func ConfigFromEnv(getenv func(string) string) Config {
	cfg := Config{Level: slog.LevelInfo, Format: "json"}
	switch strings.ToLower(strings.TrimSpace(getenv("KRYPTKEEPER_LOG_LEVEL"))) {
	case "debug":
		cfg.Level = slog.LevelDebug
	case "warn", "warning":
		cfg.Level = slog.LevelWarn
	case "error":
		cfg.Level = slog.LevelError
	}
	if strings.EqualFold(strings.TrimSpace(getenv("KRYPTKEEPER_LOG_FORMAT")), "text") {
		cfg.Format = "text"
	}
	return cfg
}

var (
	setupRan      atomic.Bool
	ensureDefault sync.Once
)

// Setup builds the logger, installs it as the slog default (which also routes
// the std `log` package through it) and returns it.
func Setup(cfg Config) *slog.Logger {
	w := cfg.Writer
	if w == nil {
		w = os.Stderr
	}
	opts := &slog.HandlerOptions{Level: cfg.Level, ReplaceAttr: replaceAttr}
	var inner slog.Handler
	if strings.EqualFold(cfg.Format, "text") {
		inner = slog.NewTextHandler(w, opts)
	} else {
		inner = slog.NewJSONHandler(w, opts)
	}
	if cfg.Service != "" {
		inner = inner.WithAttrs([]slog.Attr{slog.String("service", cfg.Service)})
	}
	l := slog.New(&contextHandler{inner: inner})
	slog.SetDefault(l)
	setupRan.Store(true)
	return l
}

// EnsureDefault installs the env-configured logger once, unless Setup already
// ran (a test or caller-installed logger must not be overridden).
func EnsureDefault() {
	ensureDefault.Do(func() {
		if setupRan.Load() {
			return
		}
		Setup(ConfigFromEnv(os.Getenv))
	})
}

type (
	requestIDKey struct{}
	tenantKey    struct{}
)

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func WithTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantKey{}, tenant)
}

func TenantFromContext(ctx context.Context) string {
	t, _ := ctx.Value(tenantKey{}).(string)
	return t
}

// contextHandler appends request_id (always) and tenant (when set) from the
// call's context. Redaction itself lives in replaceAttr so that it also covers
// attrs attached via With/WithGroup and nested groups.
type contextHandler struct{ inner slog.Handler }

func (h *contextHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	r.AddAttrs(slog.String("request_id", RequestIDFromContext(ctx)))
	if t := TenantFromContext(ctx); t != "" {
		r.AddAttrs(slog.String("tenant", t))
	}
	return h.inner.Handle(ctx, r)
}

func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *contextHandler) WithGroup(name string) slog.Handler {
	return &contextHandler{inner: h.inner.WithGroup(name)}
}

var sensitiveKeys = []string{
	"password", "passwd", "secret", "token", "authorization", "api_key", "apikey",
	"bearer", "private_key", "credential", "cookie", "passphrase",
}

func sensitiveKey(k string) bool {
	lk := strings.ToLower(k)
	for _, s := range sensitiveKeys {
		if strings.Contains(lk, s) {
			return true
		}
	}
	return false
}

func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 {
		switch a.Key {
		case slog.TimeKey:
			if t, ok := a.Value.Any().(time.Time); ok {
				return slog.String("ts", t.UTC().Format(time.RFC3339Nano))
			}
			return slog.Attr{Key: "ts", Value: a.Value}
		case slog.LevelKey:
			if l, ok := a.Value.Any().(slog.Level); ok {
				return slog.String("level", strings.ToLower(l.String()))
			}
		case slog.MessageKey:
			return slog.String(slog.MessageKey, Redact(a.Value.String()))
		}
	}
	if sensitiveKey(a.Key) {
		return slog.String(a.Key, "[REDACTED]")
	}
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, Redact(v.String()))
	case slog.KindAny:
		if err, ok := v.Any().(error); ok {
			return slog.String(a.Key, Redact(err.Error()))
		}
	}
	return a
}

var (
	reBearer = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]+`)
	reKV     = regexp.MustCompile(`(?i)\b(password|passwd|passphrase|secret|token|api[_-]?key|authorization)\b(["']?\s*[:=]\s*["']?)[^\s"',;&]+`)
	rePEM    = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)
	reJWT    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)
)

// Redact scrubs secret-shaped substrings. Patterns are RE2 (linear time), so
// attacker-sized messages cannot stall the logger.
func Redact(s string) string {
	s = rePEM.ReplaceAllString(s, "[REDACTED PRIVATE KEY]")
	s = reJWT.ReplaceAllString(s, "[REDACTED JWT]")
	s = reBearer.ReplaceAllString(s, "Bearer [REDACTED]")
	return reKV.ReplaceAllString(s, "${1}${2}[REDACTED]")
}

// exit is a var so tests can observe Fatal* without terminating the process.
var exit = os.Exit

// emit logs msg at level with the caller's caller as the record PC, so a
// `source` attribute names the call site and not this package. skip=3 skips
// runtime.Callers, emit and the exported helper.
func emit(level slog.Level, msg string) {
	l := slog.Default()
	ctx := context.Background()
	if !l.Enabled(ctx, level) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(3, pcs[:])
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	_ = l.Handler().Handle(ctx, r) // a failing log sink has nowhere to report to
}

// Printf-style helpers keep the pre-slog message text verbatim while routing
// every line through the redacting JSON handler. Non-constant messages must use
// the non-f variants (fmt.Sprint semantics, like the std Print).

func Infof(format string, a ...any)  { emit(slog.LevelInfo, fmt.Sprintf(format, a...)) }
func Warnf(format string, a ...any)  { emit(slog.LevelWarn, fmt.Sprintf(format, a...)) }
func Errorf(format string, a ...any) { emit(slog.LevelError, fmt.Sprintf(format, a...)) }
func Info(a ...any)                  { emit(slog.LevelInfo, fmt.Sprint(a...)) }
func Warn(a ...any)                  { emit(slog.LevelWarn, fmt.Sprint(a...)) }
func Error(a ...any)                 { emit(slog.LevelError, fmt.Sprint(a...)) }

// Fatalf logs at Error level and exits 1.
func Fatalf(format string, a ...any) {
	emit(slog.LevelError, fmt.Sprintf(format, a...))
	exit(1)
}

// Fatal logs at Error level and exits 1.
func Fatal(a ...any) {
	emit(slog.LevelError, fmt.Sprint(a...))
	exit(1)
}
