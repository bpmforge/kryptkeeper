// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/pem"
	"errors"

	"golang.org/x/crypto/acme"
	"kryptkeeper/internal/connectors"
)

var _ connectors.RevokingConnector = (*acmeIssuerConnector)(nil)

func (c *acmeIssuerConnector) CanRevoke() bool { return true }

// Revoke revokes through RFC 8555 section 7.6, signed by the stored account
// key. An ephemeral account (no account_key_pem) is a different account on
// every call and is not authorized to revoke what an earlier one issued, so
// that case fails loudly instead of sending a request the CA will refuse.
func (c *acmeIssuerConnector) Revoke(ctx context.Context, req connectors.RevokeRequest) error {
	block, _ := pem.Decode([]byte(req.CertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("acme revoke needs the certificate PEM")
	}
	payload, err := c.credential(ctx)
	if err != nil {
		return err
	}
	if payload.AccountKeyPEM == "" {
		return errors.New("acme revoke needs a stored account_key_pem; the connector uses an ephemeral account")
	}
	client, err := c.accountClient(ctx, payload)
	if err != nil {
		return err
	}
	return client.RevokeCert(ctx, nil, block.Bytes, acme.CRLReasonCode(req.Reason))
}
