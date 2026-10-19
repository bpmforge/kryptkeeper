// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cloudinventory

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type stubLister struct {
	certs []CloudCertificate
	err   error
	hold  func()
}

func (s stubLister) ListCertificates(context.Context) ([]CloudCertificate, error) {
	if s.hold != nil {
		s.hold()
	}
	return s.certs, s.err
}

func awsScope(region string) Scope {
	return Scope{Provider: ProviderAWSACM, Profile: "prod", Region: region}
}

func TestFanOutIsolatesFailure(t *testing.T) {
	scopes := []Scope{awsScope("us-east-1"), awsScope("eu-west-1"), awsScope("ap-south-1")}
	res := FanOut(context.Background(), scopes, func(_ context.Context, s Scope) (Lister, error) {
		if s.Region == "eu-west-1" {
			return stubLister{err: errors.New("list certificates: AccessDenied")}, nil
		}
		return stubLister{certs: []CloudCertificate{{Provider: s.Provider, ResourceID: "arn:" + s.Region}}}, nil
	}, 0)
	if len(res) != 3 || res[0].Scope.Region != "us-east-1" || res[1].Scope.Region != "eu-west-1" || res[2].Scope.Region != "ap-south-1" {
		t.Fatalf("order not preserved: %+v", res)
	}
	if res[0].Err != "" || res[2].Err != "" || res[1].Err != "list certificates: AccessDenied" {
		t.Fatalf("errors: %+v", res)
	}
	if res[0].Certs[0].Scope != "aws-acm/prod/us-east-1" {
		t.Fatalf("scope not stamped: %+v", res[0].Certs[0])
	}
}

func TestFanOutBuildErrorIsPerScope(t *testing.T) {
	res := FanOut(context.Background(), []Scope{awsScope("a"), awsScope("b")}, func(_ context.Context, s Scope) (Lister, error) {
		if s.Region == "a" {
			return nil, errors.New("no creds")
		}
		return stubLister{}, nil
	}, 1)
	if res[0].Err != "connector init: no creds" || res[1].Err != "" {
		t.Fatalf("%+v", res)
	}
}

func TestFanOutPanicBecomesErr(t *testing.T) {
	res := FanOut(context.Background(), []Scope{awsScope("a"), awsScope("b")}, func(_ context.Context, s Scope) (Lister, error) {
		if s.Region == "a" {
			panic("boom")
		}
		return stubLister{certs: []CloudCertificate{{ResourceID: "x"}}}, nil
	}, 2)
	if res[0].Err == "" || res[1].Err != "" || len(res[1].Certs) != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestFanOutBoundedParallel(t *testing.T) {
	var inFlight, maxSeen atomic.Int32
	scopes := make([]Scope, 10)
	for i := range scopes {
		scopes[i] = awsScope(string(rune('a' + i)))
	}
	FanOut(context.Background(), scopes, func(context.Context, Scope) (Lister, error) {
		return stubLister{hold: func() {
			n := inFlight.Add(1)
			for {
				m := maxSeen.Load()
				if n <= m || maxSeen.CompareAndSwap(m, n) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
			inFlight.Add(-1)
		}}, nil
	}, 3)
	if got := maxSeen.Load(); got > 3 || got < 2 {
		t.Fatalf("max in flight %d, want 2..3", got)
	}
}

func TestMergeUniqueAcrossRuns(t *testing.T) {
	c := CloudCertificate{Provider: ProviderAWSACM, Scope: "aws-acm/prod/us-east-1", ResourceID: "arn:1"}
	other := c
	other.Scope = "aws-acm/prod/eu-west-1" // same id in another scope is a different resource
	got := MergeUnique([]ScopeResult{{Certs: []CloudCertificate{c, c}}, {Certs: []CloudCertificate{c, other}}})
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
}

func TestScopeValidate(t *testing.T) {
	cases := []struct {
		name string
		s    Scope
		ok   bool
	}{
		{"aws ok", Scope{Provider: ProviderAWSACM, Region: "us-east-1"}, true},
		{"aws no region", Scope{Provider: ProviderAWSACM}, false},
		{"azure ok", Scope{Provider: ProviderAzureKeyVault, VaultURL: "https://a.vault.azure.net"}, true},
		{"azure http", Scope{Provider: ProviderAzureKeyVault, VaultURL: "http://a.vault.azure.net"}, false},
		{"azure empty", Scope{Provider: ProviderAzureKeyVault}, false},
		{"gcp ok", Scope{Provider: ProviderGCPCertManager, ProjectID: "p1"}, true},
		{"gcp no project", Scope{Provider: ProviderGCPCertManager}, false},
		{"unknown", Scope{Provider: "oracle"}, false},
	}
	for _, c := range cases {
		if err := c.s.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: err=%v", c.name, err)
		}
	}
}

func TestScopeKey(t *testing.T) {
	cases := map[string]Scope{
		"aws-acm/prod/eu-west-1":           {Provider: ProviderAWSACM, Profile: "prod", Region: "eu-west-1"},
		"aws-acm/default/us-east-1":        {Provider: ProviderAWSACM, Region: "us-east-1"},
		"azure-keyvault/a.vault.azure.net": {Provider: ProviderAzureKeyVault, VaultURL: "https://a.vault.azure.net/"},
		"gcp-certmanager/p1/global":        {Provider: ProviderGCPCertManager, ProjectID: "p1"},
		"gcp-certmanager/p1/europe-west1":  {Provider: ProviderGCPCertManager, ProjectID: "p1", Region: "europe-west1"},
	}
	for want, s := range cases {
		if got := s.Key(); got != want {
			t.Errorf("Key() = %q, want %q", got, want)
		}
	}
}
