// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/crl"
)

type crlRecordingAudit struct {
	bootstrap.AuditProvider
	entries []bootstrap.AuditEntry
}

func (r *crlRecordingAudit) AppendEntry(_ context.Context, e bootstrap.AuditEntry) error {
	r.entries = append(r.entries, e)
	return nil
}

func TestCRLAuditSinkWritesRowAndAlertLog(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	audit := &crlRecordingAudit{}
	sink := crlAuditSink(audit)

	sink(crl.Event{Action: crl.ActionGenerate, CAID: "ca1", Detail: "number=1"})
	sink(crl.Event{Action: crl.ActionStale, CAID: "ca1", Detail: "kind=full", Failure: true})

	if len(audit.entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(audit.entries))
	}
	if e := audit.entries[0]; e.Action != "crl.generate" || e.Outcome != bootstrap.AuditOutcomeSuccess ||
		e.ResourceType != "crl" || e.ResourceID != "ca1" || e.ActorType != "system" || e.ChangeSummary != "number=1" {
		t.Fatalf("generate entry = %+v", e)
	}
	if e := audit.entries[1]; e.Action != "crl.stale" || e.Outcome != bootstrap.AuditOutcomeFailure {
		t.Fatalf("stale entry = %+v", e)
	}
	if n := strings.Count(buf.String(), "ALERT crl.stale ca=ca1"); n != 1 {
		t.Fatalf("alert lines = %d, log: %s", n, buf.String())
	}
}

func TestCRLDeltaIntervalFromEnv(t *testing.T) {
	for _, c := range []struct {
		val  string
		want time.Duration
	}{{"", 0}, {"0", 0}, {"0s", 0}, {"abc", 0}, {"-5m", 0}, {"15m", 15 * time.Minute}} {
		t.Setenv("KRYPTKEEPER_CRL_DELTA_INTERVAL", c.val)
		if got := crlDeltaIntervalFromEnv(); got != c.want {
			t.Errorf("interval(%q) = %v, want %v", c.val, got, c.want)
		}
	}
}
