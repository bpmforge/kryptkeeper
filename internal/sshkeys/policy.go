// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package sshkeys

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// A01S-4 / FR-P70: SSH certificates are issued against a certificate
// template, and the template's SSH policy names the principals it may sign.
// Anything the policy does not list is refused; there is no "any principal"
// setting.

// Policy is the SSH section of a certificate template.
type Policy struct {
	// CertTypes is a non-empty subset of {"user", "host"}.
	CertTypes []string `json:"cert_types"`
	// AllowedPrincipals are exact login names (user certificates).
	AllowedPrincipals []string `json:"allowed_principals,omitempty"`
	// HostPatterns are exact lowercase DNS names or "*.suffix" (host certificates).
	HostPatterns []string `json:"host_patterns,omitempty"`
	// MaxTTLHours caps a requested TTL; a request above it is refused.
	MaxTTLHours float64 `json:"max_ttl_hours"`
}

var (
	errPolicyInvalid = errors.New("invalid ssh policy")
	// ErrPolicyDenied wraps every refusal of a request by a valid policy.
	ErrPolicyDenied = errors.New("ssh certificate request not permitted by the template's ssh policy")

	principalRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
	dnsLabelRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

func (p Policy) allows(certType string) bool {
	return contains(p.CertTypes, certType)
}

func validHostName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !dnsLabelRe.MatchString(label) {
			return false
		}
	}
	return true
}

// Validate checks the policy as an admin configures it on a template.
func (p Policy) Validate() error {
	if len(p.CertTypes) == 0 {
		return fmt.Errorf("%w: cert_types is required", errPolicyInvalid)
	}
	seen := map[string]bool{}
	for _, t := range p.CertTypes {
		if t != "user" && t != "host" {
			return fmt.Errorf("%w: cert_types may only contain user and host", errPolicyInvalid)
		}
		if seen[t] {
			return fmt.Errorf("%w: duplicate cert type %q", errPolicyInvalid, t)
		}
		seen[t] = true
	}
	if seen["user"] {
		if len(p.AllowedPrincipals) == 0 {
			return fmt.Errorf("%w: allowed_principals is required for user certificates", errPolicyInvalid)
		}
		for _, pr := range p.AllowedPrincipals {
			if !principalRe.MatchString(pr) {
				return fmt.Errorf("%w: principal %q must be 1-64 characters of [a-zA-Z0-9._-] with no wildcards", errPolicyInvalid, pr)
			}
		}
	} else if len(p.AllowedPrincipals) > 0 {
		return fmt.Errorf("%w: allowed_principals is only meaningful with the user cert type", errPolicyInvalid)
	}
	if seen["host"] {
		if len(p.HostPatterns) == 0 {
			return fmt.Errorf("%w: host_patterns is required for host certificates", errPolicyInvalid)
		}
		for _, hp := range p.HostPatterns {
			if !validHostName(strings.TrimPrefix(hp, "*.")) {
				return fmt.Errorf("%w: host pattern %q must be a lowercase DNS name or a single leading *. label", errPolicyInvalid, hp)
			}
		}
	} else if len(p.HostPatterns) > 0 {
		return fmt.Errorf("%w: host_patterns is only meaningful with the host cert type", errPolicyInvalid)
	}
	if p.MaxTTLHours <= 0 {
		return fmt.Errorf("%w: max_ttl_hours must be greater than zero", errPolicyInvalid)
	}
	if seen["user"] && p.MaxTTLHours > UserCertMaxTTL.Hours() {
		return fmt.Errorf("%w: max_ttl_hours exceeds the %gh user certificate ceiling", errPolicyInvalid, UserCertMaxTTL.Hours())
	}
	if p.MaxTTLHours > HostCertMaxTTL.Hours() {
		return fmt.Errorf("%w: max_ttl_hours exceeds the %gh host certificate ceiling", errPolicyInvalid, HostCertMaxTTL.Hours())
	}
	return nil
}

// MatchesHost reports whether name satisfies a host pattern: exact match, or
// "*.suffix" matching exactly one extra label.
func MatchesHost(pattern, name string) bool {
	pattern, name = strings.ToLower(pattern), strings.ToLower(name)
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == name
	}
	suffix := pattern[1:] // ".suffix"
	if !strings.HasSuffix(name, suffix) {
		return false
	}
	label := strings.TrimSuffix(name, suffix)
	return label != "" && !strings.Contains(label, ".")
}

// Check refuses a request the policy does not cover. It returns the TTL to
// issue with: a zero request takes the type default, lowered to the policy
// maximum, so a default can never exceed the template. An explicit TTL above
// the maximum is refused, never clamped.
func (p Policy) Check(certType string, principals []string, ttl time.Duration) (time.Duration, error) {
	if !p.allows(certType) {
		return 0, fmt.Errorf("%w: cert_type %q is not allowed", ErrPolicyDenied, certType)
	}
	if len(principals) == 0 {
		return 0, fmt.Errorf("%w: principals are required", ErrPolicyDenied)
	}
	for _, pr := range principals {
		if certType == "user" {
			if !contains(p.AllowedPrincipals, pr) {
				return 0, fmt.Errorf("%w: principal %q is not allowed", ErrPolicyDenied, pr)
			}
			continue
		}
		ok := false
		for _, hp := range p.HostPatterns {
			if MatchesHost(hp, pr) {
				ok = true
				break
			}
		}
		if !ok {
			return 0, fmt.Errorf("%w: host %q matches no host pattern", ErrPolicyDenied, pr)
		}
	}
	maxTTL := time.Duration(p.MaxTTLHours * float64(time.Hour))
	if ttl > maxTTL {
		return 0, fmt.Errorf("%w: ttl %s exceeds the template maximum %s", ErrPolicyDenied, ttl, maxTTL)
	}
	if ttl <= 0 {
		ttl = UserCertDefaultTTL
		if certType == "host" {
			ttl = HostCertDefaultTTL
		}
		if ttl > maxTTL {
			ttl = maxTTL
		}
	}
	return ttl, nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
