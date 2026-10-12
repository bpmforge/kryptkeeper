// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package cloudinventory provides read-only inventory connectors for cloud certificate stores.
//
// Supported sources:
//   - AWS Certificate Manager (ACM)
//   - Azure Key Vault (certificates)
//   - GCP Certificate Manager
package cloudinventory

import "time"

// CloudCertificate is a normalized certificate record from any cloud provider.
type CloudCertificate struct {
	Provider     string    `json:"provider"`    // aws-acm, azure-keyvault, gcp-certmanager
	Region       string    `json:"region"`      // AWS region, Azure location, GCP region
	ResourceID   string    `json:"resource_id"` // provider-specific identifier
	CommonName   string    `json:"common_name"`
	DNSNames     []string  `json:"dns_names"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before,omitempty"`
	NotAfter     time.Time `json:"not_after,omitempty"`
	Status       string    `json:"status"` // ISSUED, PENDING_VALIDATION, EXPIRED, etc.
	KeyAlgorithm string    `json:"key_algorithm"`
	InUse        bool      `json:"in_use"` // attached to a load balancer / CDN / etc.
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
