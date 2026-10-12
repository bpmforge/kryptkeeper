// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package connectors makes the certificate issuer an interface (W11-03,
// V5/D-106) — the same move the keystore made for signing backends. The
// internal CA engine is the first implementation; upstream CAs (ACME et al,
// W11-04+) plug in beside it. A connector receives a CSR and returns
// certificate PEM: key material never crosses this boundary in either
// direction.
package connectors

import (
	"context"
	"crypto"
	"errors"
	"sort"
	"sync"
)

// Health is a connector's live probe result. A failing probe is a visible
// state, never a dropped listing (the S-50 lesson at the connector layer).
type Health struct {
	Status string `json:"status"` // healthy | degraded | unknown
	Detail string `json:"detail,omitempty"`
}

// IssueRequest carries what an issuer needs. CSRPEM is a key-adjacent field
// but holds no private material.
//
// Signer and Decrypter (W19-28) are in-process handles onto the requester's
// private key, never its bytes: a real SCEP PKIOperation must be signed by
// the key that produced CSRPEM, and its CertRep reply is encrypted back to
// that same key, so a connector speaking real SCEP cannot work from CSRPEM
// alone. Because these are interfaces wrapping live key material, only
// callers running in this same process (e.g. the renewal executor, which
// generates the key hub-side) can populate them -- there is no wire
// representation, and there must never be one. Connectors that don't need
// them (ACME, EST, WSTEP, the internal engine) ignore both fields.
type IssueRequest struct {
	CSRPEM     string
	TemplateID string
	TeamID     string
	Signer     crypto.Signer
	Decrypter  crypto.Decrypter
}

// IssueResult is the issued certificate. PEM may include the chain.
type IssueResult struct {
	FingerprintSHA256 string
	CertificatePEM    string
}

// IssuerConnector is the issuer abstraction. Origin is the estate origin
// value certificates issued through this connector carry (W11-01):
// "internal" for the in-process engine, "synced" for upstream CAs.
type IssuerConnector interface {
	ID() string
	Type() string
	Origin() string
	Health(ctx context.Context) Health
	Issue(ctx context.Context, req IssueRequest) (IssueResult, error)
}

var ErrConnectorNotFound = errors.New("connector not found")

// Registry is a concurrency-safe id→connector map. Construction-time
// registration only — no global state (house rule).
type Registry struct {
	mu         sync.RWMutex
	connectors map[string]IssuerConnector
}

func NewRegistry() *Registry {
	return &Registry{connectors: map[string]IssuerConnector{}}
}

func (r *Registry) Register(c IssuerConnector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connectors[c.ID()] = c
}

func (r *Registry) Get(id string) (IssuerConnector, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.connectors[id]
	if !ok {
		return nil, ErrConnectorNotFound
	}
	return c, nil
}

// List returns registered connectors in stable id order.
func (r *Registry) List() []IssuerConnector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]IssuerConnector, 0, len(r.connectors))
	for _, c := range r.connectors {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Issue resolves id and issues through it — the one call site the rest of
// the platform uses, so routing is uniform and testable.
func (r *Registry) Issue(ctx context.Context, id string, req IssueRequest) (IssueResult, error) {
	c, err := r.Get(id)
	if err != nil {
		return IssueResult{}, err
	}
	return c.Issue(ctx, req)
}
