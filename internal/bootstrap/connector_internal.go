// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"

	"kryptkeeper/internal/connectors"
)

// internalIssuerConnector proves the W11-03 issuer abstraction against a
// real issuer: it wraps the production CertificateProvider, so a connector-
// routed issue lands in inventory exactly like a direct one — persisted,
// estate-stamped origin=internal, risk-scored.
type internalIssuerConnector struct {
	id       string
	provider CertificateProvider
	// caID is the issuing CA this connector fronts. A connector instance is
	// one issuer identity, not a CA multiplexer.
	caID string
}

var _ connectors.IssuerConnector = (*internalIssuerConnector)(nil)

// NewInternalIssuerConnector fronts one internal CA as an IssuerConnector.
func NewInternalIssuerConnector(id string, provider CertificateProvider, caID string) connectors.IssuerConnector {
	return &internalIssuerConnector{id: id, provider: provider, caID: caID}
}

func (c *internalIssuerConnector) ID() string     { return c.id }
func (c *internalIssuerConnector) Type() string   { return "internal" }
func (c *internalIssuerConnector) Origin() string { return "internal" }

func (c *internalIssuerConnector) Health(ctx context.Context) connectors.Health {
	// The internal engine is healthy when its provider can answer for the
	// fronted CA's certificates — a cheap bounded list, not a signing op.
	if _, err := c.provider.ListCertificates(ctx, CertificateListQuery{CAID: c.caID, Limit: 1}); err != nil {
		return connectors.Health{Status: "degraded", Detail: err.Error()}
	}
	return connectors.Health{Status: "healthy"}
}

func (c *internalIssuerConnector) Issue(ctx context.Context, req connectors.IssueRequest) (connectors.IssueResult, error) {
	issued, err := c.provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       c.caID,
		CSRPEM:     req.CSRPEM,
		TemplateID: req.TemplateID,
		TeamID:     req.TeamID,
	})
	if err != nil {
		return connectors.IssueResult{}, err
	}
	fp := issued.CertificateItem.FingerprintSHA256
	download, err := c.provider.DownloadCertificate(ctx, fp, "pem", true)
	if err != nil {
		// The cert exists; a fetch failure must not masquerade as an
		// issuance failure (partial-state honesty).
		return connectors.IssueResult{FingerprintSHA256: fp},
			fmt.Errorf("issued %s but could not fetch its PEM: %w", fp, err)
	}
	return connectors.IssueResult{
		FingerprintSHA256: fp,
		CertificatePEM:    string(download.Body),
	}, nil
}
