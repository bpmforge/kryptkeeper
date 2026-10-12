// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package adsync

import (
	"fmt"
	"strings"
)

// GPOCheckResult holds the outcome of a GPO configuration validation.
type GPOCheckResult struct {
	Check   string `json:"check"`
	Status  string `json:"status"` // pass, warn, fail
	Message string `json:"message"`
}

// GPOConfig represents the GPO settings needed for Windows auto-enrollment.
type GPOConfig struct {
	AutoEnrollEnabled      bool
	EnrollmentPolicyURL    string // XCEP endpoint URL
	EnrollmentServiceURL   string // WSTEP endpoint URL
	CACertificateInstalled bool
	TemplateNames          []string
}

// ValidateGPOConfig checks whether a GPO configuration is correct for auto-enrollment.
func ValidateGPOConfig(config GPOConfig) []GPOCheckResult {
	var results []GPOCheckResult

	// Check auto-enrollment is enabled.
	if config.AutoEnrollEnabled {
		results = append(results, GPOCheckResult{Check: "auto_enroll_enabled", Status: "pass", Message: "Auto-enrollment is enabled in GPO"})
	} else {
		results = append(results, GPOCheckResult{Check: "auto_enroll_enabled", Status: "fail", Message: "Auto-enrollment must be enabled in Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies"})
	}

	// Check XCEP URL.
	if config.EnrollmentPolicyURL != "" {
		if strings.HasPrefix(config.EnrollmentPolicyURL, "https://") {
			results = append(results, GPOCheckResult{Check: "xcep_url", Status: "pass", Message: fmt.Sprintf("XCEP endpoint configured: %s", config.EnrollmentPolicyURL)})
		} else {
			results = append(results, GPOCheckResult{Check: "xcep_url", Status: "fail", Message: "XCEP URL must use HTTPS"})
		}
	} else {
		results = append(results, GPOCheckResult{Check: "xcep_url", Status: "fail", Message: "Certificate Enrollment Policy URL not configured"})
	}

	// Check WSTEP URL.
	if config.EnrollmentServiceURL != "" {
		if strings.HasPrefix(config.EnrollmentServiceURL, "https://") {
			results = append(results, GPOCheckResult{Check: "wstep_url", Status: "pass", Message: fmt.Sprintf("WSTEP endpoint configured: %s", config.EnrollmentServiceURL)})
		} else {
			results = append(results, GPOCheckResult{Check: "wstep_url", Status: "fail", Message: "WSTEP URL must use HTTPS"})
		}
	} else {
		results = append(results, GPOCheckResult{Check: "wstep_url", Status: "fail", Message: "Certificate Enrollment Service URL not configured"})
	}

	// Check CA cert is installed.
	if config.CACertificateInstalled {
		results = append(results, GPOCheckResult{Check: "ca_cert_trusted", Status: "pass", Message: "CA certificate is in the Trusted Root store"})
	} else {
		results = append(results, GPOCheckResult{Check: "ca_cert_trusted", Status: "fail", Message: "CA certificate must be distributed via GPO to Trusted Root Certification Authorities"})
	}

	// Check templates.
	if len(config.TemplateNames) > 0 {
		results = append(results, GPOCheckResult{Check: "templates_configured", Status: "pass", Message: fmt.Sprintf("%d template(s) available for enrollment", len(config.TemplateNames))})
	} else {
		results = append(results, GPOCheckResult{Check: "templates_configured", Status: "warn", Message: "No certificate templates configured — enrollment will have no available templates"})
	}

	return results
}

// GPOAllPassing returns true if all checks passed.
func GPOAllPassing(results []GPOCheckResult) bool {
	for _, r := range results {
		if r.Status == "fail" {
			return false
		}
	}
	return true
}
