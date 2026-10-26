// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/connectors"
)

// W36-02 (D-304, D-305, D-308): the bridge between an external CA row and the
// issuer connector that signs for it.

var errExternalCATenantMismatch = errors.New("external CA and connector belong to different tenants")

// externalConnectorTypeError refuses connector types that cannot sign a
// client-supplied CSR (D-305). An upstream SCEP or WSTEP PKIOperation is signed
// by, and encrypted to, the requester's own key, which the hub holds only for
// keys it generated, so those types are renewal paths and never external CAs.
func externalConnectorTypeError(connectorType string) error {
	switch connectorType {
	case "internal":
		return errors.New("an external CA cannot delegate to the hub's own internal connector")
	case "scep", "wstep":
		return fmt.Errorf("connector type %s can only renew hub-generated keys; use it as a renewal path, not as an external CA", connectorType)
	}
	return nil
}

// externalCAIssuer implements ca.ExternalIssuer over the connector store.
type externalCAIssuer struct {
	store    ConnectorStore
	provider CertificateProvider
	creds    OutboundCredentialStore
	tenants  TenantStore
	// build is buildRuntimeConnector; a field so tests can supply a stub type.
	build func(ConnectorRecord, CertificateProvider, OutboundCredentialStore) connectors.IssuerConnector
}

// NewExternalCAIssuer builds the ca.ExternalIssuer the engine calls to sign
// for an external CA. Every call re-checks the connector and the tenancy
// binding rather than trusting what was true when the CA was created, so a
// connector changed or re-stamped afterwards fails closed (D-308, D-202).
func NewExternalCAIssuer(store ConnectorStore, provider CertificateProvider, creds OutboundCredentialStore, tenants TenantStore) ca.ExternalIssuer {
	return &externalCAIssuer{store: store, provider: provider, creds: creds, tenants: tenants, build: buildRuntimeConnector}
}

func (x *externalCAIssuer) IssueExternal(ctx context.Context, caID, connectorID, csrPEM, templateID string) (string, error) {
	if x.store == nil {
		return "", errors.New("connector store not configured")
	}
	rec, err := x.store.Get(ctx, connectorID)
	if err != nil {
		return "", fmt.Errorf("external CA %s: connector %s: %w", caID, connectorID, err)
	}
	if err := externalConnectorTypeError(rec.Type); err != nil {
		return "", err
	}
	if multiTenancyEnabled() {
		if err := x.checkTenancy(ctx, caID, rec); err != nil {
			return "", err
		}
	}
	c := x.build(rec, x.provider, x.creds)
	if c == nil {
		return "", fmt.Errorf("connector type %s is not supported for issuance", rec.Type)
	}
	reg := connectors.NewRegistry()
	reg.Register(c)
	res, err := reg.Issue(ctx, connectorID, connectors.IssueRequest{CSRPEM: csrPEM, TemplateID: templateID})
	if err != nil {
		return "", err
	}
	return res.CertificatePEM, nil
}

func (x *externalCAIssuer) checkTenancy(ctx context.Context, caID string, rec ConnectorRecord) error {
	if x.tenants == nil {
		return errors.New("external CA tenancy cannot be checked: tenant store unavailable")
	}
	caTenant, err := x.tenants.CATenant(ctx, caID)
	if err != nil {
		return fmt.Errorf("external CA tenancy cannot be checked: %w", err)
	}
	if caTenant == "" {
		caTenant = DefaultTenant
	}
	connTenant := rec.Tenant
	if connTenant == "" {
		connTenant = DefaultTenant
	}
	if connTenant != caTenant {
		return errExternalCATenantMismatch
	}
	if rec.CredentialRef != "" && x.creds != nil {
		meta, err := x.creds.Get(ctx, rec.CredentialRef)
		if err != nil {
			return fmt.Errorf("external CA credential cannot be checked: %w", err)
		}
		if meta.Tenant != "" && meta.Tenant != caTenant && meta.Tenant != DefaultTenant {
			return errExternalCATenantMismatch
		}
	}
	return nil
}
