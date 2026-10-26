// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"strings"
	"testing"

	"kryptkeeper/internal/ca"
)

type wireCAProvider struct {
	CAProvider
	issuer ca.ExternalIssuer
	obs    ca.ExternalRejectionObserver
}

func (w *wireCAProvider) SetExternalIssuer(x ca.ExternalIssuer) { w.issuer = x }
func (w *wireCAProvider) SetExternalRejectionObserver(fn ca.ExternalRejectionObserver) {
	w.obs = fn
}

type wireCertProvider struct {
	CertificateProvider
	revoker UpstreamRevoker
}

func (w *wireCertProvider) SetUpstreamRevoker(u UpstreamRevoker) { w.revoker = u }

type wireConnectorStore struct{ ConnectorStore }

// Production never called SetUpstreamRevoker or SetExternalRejectionObserver,
// so a Vault-issued certificate revoked as "unsupported" and a tampered
// upstream response left no audit row (found by tests/live/upstream-cas).
func TestWireExternalCAConnectsIssuerObserverAndRevoker(t *testing.T) {
	cp, certs, audit := &wireCAProvider{}, &wireCertProvider{}, &memAuditProvider{}
	wireExternalCA(cp, certs, wireConnectorStore{}, nil, nil, audit)
	if cp.issuer == nil || cp.obs == nil || certs.revoker == nil {
		t.Fatalf("not wired: issuer=%v observer=%v revoker=%v", cp.issuer != nil, cp.obs != nil, certs.revoker != nil)
	}

	cp.obs("ca-1", "conn-1", &ca.ExternalRejection{Reason: "public key differs from the request", Fingerprint: "abc"})
	res, err := audit.ListEntries(context.Background(), AuditListQuery{Action: "certificate.issue.upstream_rejected", Limit: 10})
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("audit rows = %d, err %v", len(res.Entries), err)
	}
	e := res.Entries[0]
	if e.Outcome != AuditOutcomeFailure || e.ResourceID != "abc" ||
		!strings.Contains(e.ChangeSummary, `"connector_id":"conn-1"`) || !strings.Contains(e.ChangeSummary, "public key differs") {
		t.Fatalf("unexpected audit entry: %+v", e)
	}
}

func TestWireExternalCASkipsWithoutConnectorStore(t *testing.T) {
	cp, certs := &wireCAProvider{}, &wireCertProvider{}
	wireExternalCA(cp, certs, nil, nil, nil, nil)
	if cp.issuer != nil || cp.obs != nil || certs.revoker != nil {
		t.Fatal("wired without a connector store")
	}
}
