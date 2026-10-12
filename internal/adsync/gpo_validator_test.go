// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package adsync

import "testing"

func TestValidateGPOConfigAllValid(t *testing.T) {
	cfg := GPOConfig{
		AutoEnrollEnabled:      true,
		EnrollmentPolicyURL:    "https://pki.example.com/xcep",
		EnrollmentServiceURL:   "https://pki.example.com/wstep",
		CACertificateInstalled: true,
		TemplateNames:          []string{"WebServer"},
	}
	results := ValidateGPOConfig(cfg)
	for _, r := range results {
		if r.Status == "fail" {
			t.Errorf("expected pass for %q, got fail: %s", r.Check, r.Message)
		}
	}
}

func TestValidateGPOConfigMissingEndpoint(t *testing.T) {
	cfg := GPOConfig{
		AutoEnrollEnabled:    true,
		EnrollmentPolicyURL:  "",
		EnrollmentServiceURL: "",
	}
	results := ValidateGPOConfig(cfg)
	found := false
	for _, r := range results {
		if r.Status == "fail" {
			found = true
		}
	}
	if !found {
		t.Error("expected at least one failing check for missing endpoint")
	}
}

func TestGPOAllPassingTrue(t *testing.T) {
	results := []GPOCheckResult{{Check: "a", Status: "pass"}, {Check: "b", Status: "pass"}}
	if !GPOAllPassing(results) {
		t.Error("expected all passing")
	}
}

func TestGPOAllPassingFalse(t *testing.T) {
	results := []GPOCheckResult{{Check: "a", Status: "pass"}, {Check: "b", Status: "fail"}}
	if GPOAllPassing(results) {
		t.Error("expected not all passing")
	}
}
