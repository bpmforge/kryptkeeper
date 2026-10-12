// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"errors"
	"testing"
)

type fakeConnector struct {
	id, typ, origin string
	health          Health
	issueErr        error
}

func (f fakeConnector) ID() string                    { return f.id }
func (f fakeConnector) Type() string                  { return f.typ }
func (f fakeConnector) Origin() string                { return f.origin }
func (f fakeConnector) Health(context.Context) Health { return f.health }
func (f fakeConnector) Issue(_ context.Context, req IssueRequest) (IssueResult, error) {
	if f.issueErr != nil {
		return IssueResult{}, f.issueErr
	}
	return IssueResult{FingerprintSHA256: "fp-" + f.id, CertificatePEM: "PEM-" + req.CSRPEM}, nil
}

func TestRegistryRoutesIssueByID(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeConnector{id: "int-1", typ: "internal", origin: "internal"})
	r.Register(fakeConnector{id: "acme-1", typ: "acme", origin: "synced"})

	res, err := r.Issue(context.Background(), "acme-1", IssueRequest{CSRPEM: "csr"})
	if err != nil || res.FingerprintSHA256 != "fp-acme-1" {
		t.Fatalf("routing wrong: %+v %v", res, err)
	}

	if _, err := r.Issue(context.Background(), "nope", IssueRequest{}); !errors.Is(err, ErrConnectorNotFound) {
		t.Fatalf("expected ErrConnectorNotFound, got %v", err)
	}
}

func TestRegistryListIsStableOrder(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeConnector{id: "b"})
	r.Register(fakeConnector{id: "a"})
	list := r.List()
	if len(list) != 2 || list[0].ID() != "a" || list[1].ID() != "b" {
		t.Fatalf("unstable order: %v", list)
	}
}

// An issue failure surfaces as an error to the caller — the registry never
// swallows it into a zero-value result.
func TestRegistryIssueFailureIsVisible(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeConnector{id: "broken", issueErr: errors.New("upstream 500")})
	_, err := r.Issue(context.Background(), "broken", IssueRequest{})
	if err == nil || err.Error() != "upstream 500" {
		t.Fatalf("expected visible upstream error, got %v", err)
	}
}
