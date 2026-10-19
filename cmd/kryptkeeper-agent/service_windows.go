// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	"kryptkeeper/internal/logging"
)

const serviceName = "KryptkeeperAgent"

// exitBadConfig is the service-specific exit code reported when agent.env
// cannot be loaded; the SCM records it (event 7024) next to our own message.
const exitBadConfig = 1

// serviceEnvPath is where the MSI's runbook says settings live; ProgramData is
// writable by the service account and survives upgrades of the install dir.
func serviceEnvPath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "Kryptkeeper", "agent.env")
}

// eventLogWriter sends the standard logger to the Windows Application log. A
// service has no console: without this every log line -- including the reason
// for a Fatalf exit -- is discarded and the operator sees only the SCM's
// generic "terminated unexpectedly".
type eventLogWriter struct{ el *eventlog.Log }

func (w eventLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\r\n")
	// EventCreate.exe (the registered message file) only defines IDs 1-1000.
	if err := w.el.Info(1, msg); err != nil {
		return 0, err
	}
	return len(p), nil
}

type agentService struct {
	run func(context.Context)
	el  *eventlog.Log
}

func (s *agentService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	// Settings are loaded after connecting to the SCM, not before: failing
	// before svc.Run leaves the SCM waiting 30s for a process that already
	// exited, and it then logs a timeout that names no cause.
	path := serviceEnvPath()
	if err := loadEnvFile(path); err != nil {
		msg := fmt.Sprintf("cannot start: load %s: %v", path, err)
		if s.el != nil {
			_ = s.el.Error(1, msg)
		} else {
			logging.Info(msg)
		}
		return true, exitBadConfig
	}
	serviceEnvFile = path

	const accepted = svc.AcceptStop | svc.AcceptShutdown
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			cancel()
			<-done
			return false, 0
		}
	}
	cancel()
	return false, 0
}

// runAsWindowsService reports whether the process was started by the SCM and,
// if so, runs the agent under it until stopped.
func runAsWindowsService(run func(context.Context)) bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return false
	}
	// The MSI registers the event source; if that is missing, Open still
	// works and Event Viewer shows the text with a "description not found"
	// preamble, which beats losing it.
	el, err := eventlog.Open(serviceName)
	if err == nil {
		defer el.Close()
		logging.Setup(logging.Config{Writer: eventLogWriter{el}})
	}
	if err := svc.Run(serviceName, &agentService{run: run, el: el}); err != nil {
		logging.Fatalf("service run: %v", err)
	}
	return true
}
