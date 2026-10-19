// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cloudinventory

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// W24-17: a scan walks N scopes (an AWS account+region, an Azure vault, a GCP
// project+location). One connector instance serves exactly one scope, so a
// failing scope can only ever fail its own result.

const (
	ProviderAWSACM         = "aws-acm"
	ProviderAzureKeyVault  = "azure-keyvault"
	ProviderGCPCertManager = "gcp-certmanager"

	defaultFanOutParallel = 4
	scopeTimeout          = 5 * time.Minute
)

// Scope selects one cloud inventory source. Credentials are never part of
// it: the AWS profile names an entry in the shared config, and Azure/GCP
// credentials still come from the process environment.
type Scope struct {
	Provider  string `json:"provider"`
	Region    string `json:"region,omitempty"`     // aws region; gcp location (default "global")
	Profile   string `json:"profile,omitempty"`    // aws shared-config profile (the account)
	VaultURL  string `json:"vault_url,omitempty"`  // azure: one scope per vault
	ProjectID string `json:"project_id,omitempty"` // gcp
}

// Key is the stable identity of a scope, used in messages and for dedupe.
func (s Scope) Key() string {
	switch s.Provider {
	case ProviderAWSACM:
		profile := s.Profile
		if profile == "" {
			profile = "default"
		}
		return ProviderAWSACM + "/" + profile + "/" + s.Region
	case ProviderAzureKeyVault:
		host := s.VaultURL
		if u, err := url.Parse(s.VaultURL); err == nil && u.Host != "" {
			host = u.Host
		}
		return ProviderAzureKeyVault + "/" + host
	case ProviderGCPCertManager:
		region := s.Region
		if region == "" {
			region = "global"
		}
		return ProviderGCPCertManager + "/" + s.ProjectID + "/" + region
	default:
		return s.Provider
	}
}

func (s Scope) Validate() error {
	switch s.Provider {
	case ProviderAWSACM:
		if strings.TrimSpace(s.Region) == "" {
			return fmt.Errorf("aws-acm scope requires region")
		}
	case ProviderAzureKeyVault:
		u, err := url.Parse(s.VaultURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("azure-keyvault scope requires an https vault_url")
		}
	case ProviderGCPCertManager:
		if strings.TrimSpace(s.ProjectID) == "" {
			return fmt.Errorf("gcp-certmanager scope requires project_id")
		}
	default:
		return fmt.Errorf("unknown cloud provider %q", s.Provider)
	}
	return nil
}

type Lister interface {
	ListCertificates(ctx context.Context) ([]CloudCertificate, error)
}

type ScopeResult struct {
	Scope Scope
	Certs []CloudCertificate
	Err   string
}

// FanOut builds and lists every scope with at most maxParallel in flight
// (<=0 means 4). Each scope gets its own timeout; a panic or error becomes
// that scope's Err. Results are in input order.
func FanOut(ctx context.Context, scopes []Scope, build func(context.Context, Scope) (Lister, error), maxParallel int) []ScopeResult {
	if maxParallel <= 0 {
		maxParallel = defaultFanOutParallel
	}
	results := make([]ScopeResult, len(scopes))
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for i, sc := range scopes {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = runScope(ctx, sc, build)
		}()
	}
	wg.Wait()
	return results
}

func runScope(ctx context.Context, sc Scope, build func(context.Context, Scope) (Lister, error)) (res ScopeResult) {
	res.Scope = sc
	defer func() {
		if r := recover(); r != nil {
			res.Certs = nil
			res.Err = fmt.Sprintf("panic: %v", r)
		}
	}()
	sctx, cancel := context.WithTimeout(ctx, scopeTimeout)
	defer cancel()
	lister, err := build(sctx, sc)
	if err != nil {
		res.Err = fmt.Sprintf("connector init: %v", err)
		return res
	}
	certs, err := lister.ListCertificates(sctx)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	key := sc.Key()
	for i := range certs {
		certs[i].Scope = key
	}
	res.Certs = certs
	return res
}

// MergeUnique de-duplicates by provider|scope|resource id, keeping the first
// occurrence in stable order.
func MergeUnique(rs []ScopeResult) []CloudCertificate {
	seen := make(map[string]bool)
	var out []CloudCertificate
	for _, r := range rs {
		for _, c := range r.Certs {
			k := c.Provider + "|" + c.Scope + "|" + c.ResourceID
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, c)
		}
	}
	return out
}
