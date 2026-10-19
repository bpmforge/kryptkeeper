// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"runtime"
	"strings"
	"testing"
)

func TestHelpersEmitJSONAtLevels(t *testing.T) {
	var buf bytes.Buffer
	Setup(Config{Level: slog.LevelDebug, Writer: &buf})
	Infof("a %d", 1)
	Warnf("b %s", "x")
	Errorf("c")
	Info("d", 2)
	Warn("e")
	Error("f")
	want := []struct{ level, msg string }{
		{"info", "a 1"}, {"warn", "b x"}, {"error", "c"},
		{"info", "d2"}, {"warn", "e"}, {"error", "f"},
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d: %s", len(lines), len(want), buf.String())
	}
	for i, ln := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("line %d not JSON: %v", i, err)
		}
		if m["level"] != want[i].level || m["msg"] != want[i].msg {
			t.Errorf("line %d = %v, want %+v", i, m, want[i])
		}
		for _, k := range []string{"ts", "request_id"} {
			if _, ok := m[k]; !ok {
				t.Errorf("line %d missing %s", i, k)
			}
		}
	}
}

func TestHelpersRedactMessage(t *testing.T) {
	var buf bytes.Buffer
	Setup(Config{Writer: &buf})
	Infof("login password=%s", "hunter2")
	if strings.Contains(buf.String(), "hunter2") {
		t.Fatalf("secret leaked: %s", buf.String())
	}
}

type pcCapture struct{ pc uintptr }

func (c *pcCapture) Enabled(context.Context, slog.Level) bool { return true }
func (c *pcCapture) Handle(_ context.Context, r slog.Record) error {
	c.pc = r.PC
	return nil
}
func (c *pcCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *pcCapture) WithGroup(string) slog.Handler      { return c }

func TestHelperRecordPCIsCallSite(t *testing.T) {
	c := &pcCapture{}
	prev := slog.Default()
	defer slog.SetDefault(prev)
	slog.SetDefault(slog.New(c))
	Warnf("x")
	fr, _ := runtime.CallersFrames([]uintptr{c.pc}).Next()
	if !strings.HasSuffix(fr.Function, "TestHelperRecordPCIsCallSite") {
		t.Fatalf("record PC resolves to %q, want the caller", fr.Function)
	}
}

func TestFatalfExits(t *testing.T) {
	var buf bytes.Buffer
	Setup(Config{Writer: &buf})
	code := -1
	prev := exit
	exit = func(c int) { code = c }
	defer func() { exit = prev }()
	Fatalf("boom %d", 1)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	Fatal("again")
	if !strings.Contains(buf.String(), `"level":"error"`) || !strings.Contains(buf.String(), "boom 1") {
		t.Fatalf("fatal not logged at error: %s", buf.String())
	}
}
