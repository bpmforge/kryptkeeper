// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type scriptedRenewer struct{ err error }

func (s *scriptedRenewer) ExecuteRenewal(context.Context, string, ManagedTarget, RenewalInstallProfile) (RenewalExecuteResult, error) {
	return RenewalExecuteResult{}, s.err
}

// W32-32: a manual execute that fails opens a renewal_failed ticket through the
// scheduler's producer, once per certificate however often the operator retries.
func TestManualRenewalFailureOpensOneITSMTicket(t *testing.T) {
	svc, prov := itsmRoutingFixture(t)
	_, auth, certs, targets, creds, caID := newRenewalExecuteTestMuxAuth(t)
	ctx := context.Background()
	issued, err := certs.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: caID, CSRPEM: generateTestCSRPEM(t, "manual.example.com", "manual.example.com"),
		TemplateID: "file-backed-default", TeamID: "team-manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	fp := issued.CertificateItem.FingerprintSHA256
	target, err := targets.Create(ctx, ManagedTarget{
		ID: "tgt-manual", Name: "manual-target", Host: "127.0.0.1",
		DiscoveryMode: "none", InstallMode: "ssh", RenewalMethod: "manual", CredentialRef: "cred-manual",
	})
	if err != nil {
		t.Fatal(err)
	}

	runner := &scriptedRenewer{err: errors.New("install refused")}
	mux := http.NewServeMux()
	registerRenewalExecuteHandlerWithNotifs(mux, auth, certs, targets, creds, stubAuditProvider{}, runner, time.Minute, prov)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for i := 0; i < 3; i++ {
		if code, raw, err := postSlow(t, srv, fp, target.ID); err != nil || code != http.StatusServiceUnavailable {
			t.Fatalf("run %d: %d %s %v", i, code, raw, err)
		}
	}
	rows := itsmRows(t, svc, "renewal_failed")
	if len(rows) != 1 {
		t.Fatalf("want exactly one ticket for the certificate, got %+v", rows)
	}
	// Fingerprint is the key ResolveByFingerprint closes tickets by, so a later
	// verified renewal (notifyRenewalVerified) resolves this one too.
	if rows[0].Fingerprint != fp || !strings.HasPrefix(rows[0].EventID, manualRenewalFailedEventID(fp)) {
		t.Fatalf("row %+v", rows[0])
	}
	if !strings.Contains(rows[0].Payload, `"class":"renewal_failed"`) {
		t.Fatalf("payload %s", rows[0].Payload)
	}

	// Request errors that are the caller's doing (here: no such certificate)
	// are not renewal failures and open nothing.
	if code, _, _ := postSlow(t, srv, "no-such-fp", target.ID); code == http.StatusServiceUnavailable {
		t.Fatalf("unknown certificate answered %d", code)
	}
	if rows := itsmRows(t, svc, "renewal_failed"); len(rows) != 1 {
		t.Fatalf("bad request opened a ticket: %+v", rows)
	}
}

func TestManualRenewalFailureSilentWithoutNotifier(t *testing.T) {
	// nil provider (the plain RegisterRenewalExecuteHandler path) must not panic.
	announceManualRenewalFailed(context.Background(), nil, nil, "fp")
}
