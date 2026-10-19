// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"

	"kryptkeeper/internal/connectors"
)

// hubRenewSpy counts hub-CA renewals so tests can prove none happened.
type hubRenewSpy struct {
	CertificateProvider
	calls int
}

func (h *hubRenewSpy) RenewCertificate(context.Context, string, CertificateRenewRequest) (CertificateIssueResult, error) {
	h.calls++
	return CertificateIssueResult{}, nil
}

// DownloadCertificate fails: the replaces lookup (W26-27) is best-effort.
func (h *hubRenewSpy) DownloadCertificate(context.Context, string, string, bool) (CertificateDownloadResult, error) {
	return CertificateDownloadResult{}, errors.New("hub spy: no download")
}

func pinnedDetail() CertificateDetail {
	var d CertificateDetail
	d.RenewalConnectorID = "conn-up"
	return d
}

func TestRenewMaterialConnectorPinnedWithoutRegistryFailsClosed(t *testing.T) {
	hub := &hubRenewSpy{}
	e := NewRenewalExecutor(hub, nil)
	_, _, err := renewViaRouting(e, pinnedDetail(), []byte("csr"))
	if err == nil || !strings.Contains(err.Error(), "conn-up") {
		t.Fatalf("want connector-pinned renewal to fail, got %v", err)
	}
	if hub.calls != 0 {
		t.Fatalf("hub CA renewed a connector-pinned cert (%d calls)", hub.calls)
	}
}

func TestRenewMaterialRegistryFuncErrorAndUnknownConnectorFailClosed(t *testing.T) {
	hub := &hubRenewSpy{}
	e := NewRenewalExecutor(hub, nil).WithConnectorRegistryFunc(func(context.Context) (*connectors.Registry, error) {
		return nil, errors.New("store down")
	})
	if _, _, err := renewViaRouting(e, pinnedDetail(), nil); err == nil {
		t.Fatal("registry resolution error must fail the renewal")
	}
	// Registry present but connector deleted/unknown: Issue errors, no fallback.
	e = NewRenewalExecutor(hub, nil).WithConnectorRegistry(connectors.NewRegistry())
	if _, _, err := renewViaRouting(e, pinnedDetail(), nil); err == nil {
		t.Fatal("unknown connector must fail the renewal")
	}
	if hub.calls != 0 {
		t.Fatalf("hub CA used as fallback (%d calls)", hub.calls)
	}
}

func TestRenewMaterialRegistryFuncRebuiltPerRenewal(t *testing.T) {
	hub := &hubRenewSpy{}
	builds := 0
	e := NewRenewalExecutor(hub, nil).WithConnectorRegistryFunc(func(context.Context) (*connectors.Registry, error) {
		builds++
		r := connectors.NewRegistry()
		r.Register(recordingConnector{id: "conn-up", pem: "PEM"})
		return r, nil
	})
	for i := 0; i < 2; i++ {
		fp, chain, err := renewViaRouting(e, pinnedDetail(), nil)
		if err != nil || fp != "fp-upstream" || string(chain) != "PEM" {
			t.Fatalf("connector not used: %q %q %v", fp, chain, err)
		}
	}
	if builds != 2 || hub.calls != 0 {
		t.Fatalf("builds=%d hub=%d, want fresh registry per renewal and no hub call", builds, hub.calls)
	}
}

func TestRenewMaterialUnpinnedStillUsesHubCA(t *testing.T) {
	hub := &hubRenewSpy{}
	e := NewRenewalExecutor(hub, nil)
	if _, _, err := renewViaRouting(e, CertificateDetail{}, nil); err != nil {
		t.Fatal(err)
	}
	if hub.calls != 1 {
		t.Fatalf("hub calls = %d, want 1", hub.calls)
	}
}

// renewViaRouting mirrors the call sites: resolve the registry once, then
// hand it to renewMaterial.
func renewViaRouting(e *RenewalExecutor, detail CertificateDetail, csr []byte) (string, []byte, error) {
	reg, regErr := e.pinnedRegistry(context.Background(), detail)
	return e.renewMaterial(context.Background(), "fp", detail, reg, regErr, nil, csr)
}
