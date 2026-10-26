// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

var digicertReasons = map[int]string{
	1: "keyCompromise", 3: "affiliationChanged", 4: "superseded", 5: "cessationOfOperation",
}

var _ RevokingConnector = (*DigiCertConnector)(nil)

// Revoke finds the certificate id from its serial, then submits a revocation
// with skip_approval so a 204 means DigiCert accepted it (an API key without
// admin rights gets a pending request, reported as an error rather than a
// false success). Documented at
// https://dev.digicert.com/en/certcentral-apis/services-api/orders/list-orders.html
// (filters[serial_number]) and
// https://dev.digicert.com/en/certcentral-apis/services-api/certificates/revoke-certificate.html
// (PUT /services/v2/certificate/{id}/revoke).
func (c *DigiCertConnector) Revoke(ctx context.Context, req RevokeRequest) error {
	err := c.revoke(ctx, req)
	c.recordError(err)
	return err
}

func (c *DigiCertConnector) revoke(ctx context.Context, req RevokeRequest) error {
	serial := strings.ToUpper(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(req.SerialHex)), "0x"))
	if serial == "" {
		return fmt.Errorf("digicert %s: revoke needs a serial number", c.id)
	}
	_, raw, err := c.do(ctx, http.MethodGet, "/services/v2/order/certificate?filters[serial_number]="+url.QueryEscape(serial), nil)
	if err != nil {
		return err
	}
	var found struct {
		Orders []struct {
			Certificate struct {
				ID int `json:"id"`
			} `json:"certificate"`
		} `json:"orders"`
	}
	if err := json.Unmarshal(raw, &found); err != nil {
		return fmt.Errorf("digicert %s: order search response unparseable", c.id)
	}
	if len(found.Orders) != 1 || found.Orders[0].Certificate.ID == 0 {
		return fmt.Errorf("digicert %s: serial matched %d orders, need exactly one", c.id, len(found.Orders))
	}
	reason, ok := digicertReasons[req.Reason]
	if !ok {
		reason = "unspecified"
	}
	status, _, err := c.do(ctx, http.MethodPut, fmt.Sprintf("/services/v2/certificate/%d/revoke", found.Orders[0].Certificate.ID),
		map[string]any{"revocation_reason": reason, "comments": "revoked by Kryptkeeper", "skip_approval": true})
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return fmt.Errorf("digicert %s: revocation not applied (HTTP %d); it may be awaiting approval, which needs an admin API key to skip", c.id, status)
	}
	return nil
}
