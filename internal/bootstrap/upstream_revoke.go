// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/connectors"
)

// W36-03 (D-306): revocation at the issuing upstream CA is upstream-first and
// fails loudly. A certificate is marked revoked here only after the upstream
// accepted; recording a revocation relying parties will never see would be a
// false security claim.

// UpstreamRevoker revokes at the CA behind an issuer connector.
type UpstreamRevoker interface {
	SupportsRevoke(ctx context.Context, connectorID string) bool
	RevokeUpstream(ctx context.Context, connectorID string, req connectors.RevokeRequest) error
}

// ErrUpstreamRevokeUnsupported: the certificate came from an external CA
// whose connector cannot revoke; an admin may record it inventory-only.
var ErrUpstreamRevokeUnsupported = errors.New("the issuing CA's connector cannot revoke; revoke it at the CA, then retry with scope inventory_only to record it here")

// UpstreamRevokeError is an upstream refusal or outage. The certificate was
// not marked revoked.
type UpstreamRevokeError struct {
	ConnectorID string
	Err         error
}

func (e *UpstreamRevokeError) Error() string {
	return fmt.Sprintf("upstream CA (connector %s) did not revoke the certificate: %v", e.ConnectorID, e.Err)
}

func (e *UpstreamRevokeError) Unwrap() error { return e.Err }

// connectorRevoker is the production UpstreamRevoker: it materialises the
// stored connector row per call, so credentials resolve lazily and are never
// held between calls (the W27-35 pattern).
type connectorRevoker struct {
	store    ConnectorStore
	provider CertificateProvider
	creds    OutboundCredentialStore
}

// NewConnectorRevoker builds the upstream revoker over the connector store.
func NewConnectorRevoker(store ConnectorStore, provider CertificateProvider, creds OutboundCredentialStore) UpstreamRevoker {
	return &connectorRevoker{store: store, provider: provider, creds: creds}
}

func (r *connectorRevoker) registry(ctx context.Context, connectorID string) (*connectors.Registry, error) {
	if r.store == nil {
		return nil, errors.New("connector store not configured")
	}
	rec, err := r.store.Get(ctx, connectorID)
	if err != nil {
		return nil, err
	}
	c := buildRuntimeConnector(rec, r.provider, r.creds)
	if c == nil {
		return nil, fmt.Errorf("connector type %s has no runtime implementation", rec.Type)
	}
	reg := connectors.NewRegistry()
	reg.Register(c)
	return reg, nil
}

func (r *connectorRevoker) SupportsRevoke(ctx context.Context, connectorID string) bool {
	reg, err := r.registry(ctx, connectorID)
	return err == nil && reg.SupportsRevoke(connectorID)
}

func (r *connectorRevoker) RevokeUpstream(ctx context.Context, connectorID string, req connectors.RevokeRequest) error {
	reg, err := r.registry(ctx, connectorID)
	if err != nil {
		return err
	}
	return reg.Revoke(ctx, connectorID, req)
}

// upstreamSecretPattern matches bearer tokens and key=value secrets an
// upstream error body might echo back.
var upstreamSecretPattern = regexp.MustCompile(`(?i)(bearer\s+|(?:api[_-]?key|secret|token|password)["'=:\s]+)[^\s"',}]+`)

// scrubUpstreamError keeps an upstream's reason readable while masking
// anything shaped like a credential before it reaches an API response.
func scrubUpstreamError(msg string) string {
	return upstreamSecretPattern.ReplaceAllString(msg, "${1}[redacted]")
}

// writeExternalCAIssueError answers issuance failures that came from an
// external CA (W36) with the reason, instead of a bare 503: the operator
// needs to know whether the upstream refused, was unreachable, or returned a
// certificate the hub rejected (that last case is also audited as
// certificate.issue.upstream_rejected).
func writeExternalCAIssueError(w http.ResponseWriter, err error) bool {
	var rej *ca.ExternalRejection
	switch {
	case errors.As(err, &rej):
		writeJSONStatus(w, http.StatusBadGateway, map[string]string{
			"error": "upstream_response_rejected", "message": "the external CA returned a certificate that does not match the request: " + rej.Reason,
		})
	case errors.Is(err, ca.ErrExternalCAUnsupportedKey), errors.Is(err, ca.ErrExternalCAInvalid):
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bad_request", "message": err.Error()})
	case errors.Is(err, ca.ErrExternalCAUpstream):
		if ra, limited := connectors.RetryAfterOf(err); limited {
			if ra > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(int(ra.Seconds())))
			}
			writeJSONStatus(w, http.StatusTooManyRequests, map[string]string{"error": "upstream_rate_limited", "message": scrubUpstreamError(err.Error())})
			return true
		}
		writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": "upstream_issue_failed", "message": scrubUpstreamError(err.Error())})
	case errors.Is(err, ca.ErrExternalCANotConfigured):
		writeServiceUnavailable(w, err.Error())
	default:
		return false
	}
	return true
}
