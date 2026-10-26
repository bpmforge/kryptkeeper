// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"errors"
)

// W36-01 (D-306): revocation at the upstream CA. It is an optional interface
// rather than a new IssuerConnector method because that method set is frozen
// (W27-33): SCEP, EST and WSTEP upstreams have no revoke verb, and every
// existing fake would break.

// RevokeRequest identifies the certificate to revoke. SerialHex is the
// lower-case hex serial without separators; CertificatePEM is the leaf, for
// upstreams that revoke by certificate (RFC 8555) rather than by serial.
// Reason is the RFC 5280 CRLReason code.
type RevokeRequest struct {
	SerialHex      string
	CertificatePEM string
	Reason         int
}

// RevokingConnector is implemented by connectors whose upstream can revoke.
type RevokingConnector interface {
	Revoke(ctx context.Context, req RevokeRequest) error
}

// RevokeCapable is optionally implemented by a RevokingConnector that wraps
// another connector (the hub's lazy adapter), whose revoke support depends on
// the wrapped type. CanRevoke false makes Registry.SupportsRevoke report false.
type RevokeCapable interface {
	CanRevoke() bool
}

// ErrRevokeUnsupported means the connector's upstream offers no revocation.
var ErrRevokeUnsupported = errors.New("connector does not support upstream revocation")

// SupportsRevoke reports whether the connector registered under id can revoke.
func (r *Registry) SupportsRevoke(id string) bool {
	c, err := r.Get(id)
	if err != nil {
		return false
	}
	if _, ok := c.(RevokingConnector); !ok {
		return false
	}
	if rc, ok := c.(RevokeCapable); ok {
		return rc.CanRevoke()
	}
	return true
}

// Revoke revokes at the upstream behind id. It shares the connector's
// concurrency cap and 429 backoff with Issue, but not its daily budget.
func (r *Registry) Revoke(ctx context.Context, id string, req RevokeRequest) error {
	c, err := r.Get(id)
	if err != nil {
		return err
	}
	rc, ok := c.(RevokingConnector)
	if !ok {
		return ErrRevokeUnsupported
	}
	t := r.throttle
	if t == nil {
		t = DefaultThrottle
	}
	release, err := t.acquire(ctx, id, false)
	if err != nil {
		return err
	}
	err = rc.Revoke(r.withGate(ctx, t, id), req)
	release(err)
	return err
}
