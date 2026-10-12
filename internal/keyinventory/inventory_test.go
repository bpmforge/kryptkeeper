// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keyinventory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// W15-01: unified key inventory — PQC scoring, aggregation with
// non-fatal provider errors, and each provider against a fake/fixture.

func TestScoreKeyPQC(t *testing.T) {
	cases := map[string]string{
		"RSA_2048":          "vulnerable",
		"ECC_NIST_P256":     "vulnerable",
		"SYMMETRIC_DEFAULT": "vulnerable",
		"ML-DSA-65":         "quantum_safe",
		"ML-KEM-768":        "quantum_safe",
		"DILITHIUM3":        "quantum_safe",
		"":                  "unknown",
		"SOMETHING_NEW":     "unknown",
	}
	for alg, want := range cases {
		if got := scoreKeyPQC(alg); got != want {
			t.Errorf("scoreKeyPQC(%q) = %q, want %q", alg, got, want)
		}
	}
}

type errSource struct{}

func (errSource) Provider() string                        { return "aws-kms" }
func (errSource) ListKeys(context.Context) ([]Key, error) { return nil, fmt.Errorf("access denied") }

type okSource struct{ keys []Key }

func (okSource) Provider() string                          { return "gcp-kms" }
func (s okSource) ListKeys(context.Context) ([]Key, error) { return s.keys, nil }

func TestCollectIsNonFatalPerProvider(t *testing.T) {
	inv := Collect(context.Background(),
		errSource{},
		okSource{keys: []Key{{Provider: "gcp-kms", KeyID: "k1"}}},
	)
	if len(inv.Keys) != 1 {
		t.Fatalf("healthy provider's keys must survive a failing one: %+v", inv.Keys)
	}
	if len(inv.Errors) != 1 || !strings.Contains(inv.Errors[0], "access denied") {
		t.Fatalf("failing provider must land in Errors: %v", inv.Errors)
	}
}

// fakeKMS implements awsKMSAPI over in-memory data.
type fakeKMS struct {
	specs    map[string]types.KeySpec
	rotation map[string]bool
}

func (f *fakeKMS) ListKeys(context.Context, *kms.ListKeysInput, ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	var entries []types.KeyListEntry
	for id := range f.specs {
		entries = append(entries, types.KeyListEntry{KeyId: aws.String(id)})
	}
	return &kms.ListKeysOutput{Keys: entries}, nil
}
func (f *fakeKMS) DescribeKey(_ context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return &kms.DescribeKeyOutput{KeyMetadata: &types.KeyMetadata{
		KeyId: in.KeyId, KeySpec: f.specs[aws.ToString(in.KeyId)],
		KeyUsage: types.KeyUsageTypeSignVerify, KeyState: types.KeyStateEnabled,
	}}, nil
}
func (f *fakeKMS) GetKeyRotationStatus(_ context.Context, in *kms.GetKeyRotationStatusInput, _ ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	return &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: f.rotation[aws.ToString(in.KeyId)]}, nil
}

func TestAWSKeySourceInventoriesKeys(t *testing.T) {
	fake := &fakeKMS{
		specs:    map[string]types.KeySpec{"key-rsa": types.KeySpecRsa2048, "key-ec": types.KeySpecEccNistP256},
		rotation: map[string]bool{"key-rsa": true},
	}
	src := newAWSKeySourceWithAPI(fake, "us-east-1")
	keys, err := src.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	byID := map[string]Key{}
	for _, k := range keys {
		byID[k.KeyID] = k
	}
	if byID["key-rsa"].Algorithm != "RSA_2048" || !byID["key-rsa"].RotationEnabled || byID["key-rsa"].PQCReadiness != "vulnerable" {
		t.Fatalf("rsa key: %+v", byID["key-rsa"])
	}
	if byID["key-ec"].RotationEnabled {
		t.Fatalf("ec key should not report rotation: %+v", byID["key-ec"])
	}
}

func TestAzureKeyVaultSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer az-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/keys" {
			kid := "http://" + r.Host + "/keys/app-signing"
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{
				{"kid": kid, "attributes": map[string]any{"enabled": true}},
			}})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/keys/app-signing") {
			_ = json.NewEncoder(w).Encode(map[string]any{"key": map[string]any{"kty": "RSA", "n": "abc"}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	keys, err := NewAzureKeyVaultSource(srv.URL, "az-token", srv.Client()).ListKeys(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 || keys[0].Algorithm != "RSA" || keys[0].PQCReadiness != "vulnerable" || keys[0].State != "enabled" {
		t.Fatalf("azure key: %+v", keys)
	}
}

func TestGCPKMSSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gcp-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"cryptoKeys": []map[string]any{
			{"name": "projects/p/locations/l/keyRings/r/cryptoKeys/signer",
				"purpose": "ASYMMETRIC_SIGN", "rotationPeriod": "7776000s",
				"versionTemplate": map[string]any{"algorithm": "EC_SIGN_P256_SHA256"}},
		}})
	}))
	t.Cleanup(srv.Close)

	keys, err := NewGCPKMSSource(srv.URL, "projects/p/locations/l/keyRings/r", "gcp-token", srv.Client()).ListKeys(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 || !keys[0].RotationEnabled || keys[0].PQCReadiness != "vulnerable" {
		t.Fatalf("gcp key: %+v", keys)
	}
}

// Review fix (concurrency challenger #2): a P-521 EC key (Azure
// "EC-P-521" shape) is fully classical and must score "vulnerable",
// not "unknown".
func TestScoreKeyPQCClassifiesP521AndAzureEC(t *testing.T) {
	for _, alg := range []string{"EC-P-521", "P-521", "EC-P-256", "ECC_NIST_P521"} {
		if got := scoreKeyPQC(alg); got != "vulnerable" {
			t.Errorf("classical EC %q must be vulnerable, got %q", alg, got)
		}
	}
}

// Review fix (concurrency challenger #1): Azure ListKeys must follow
// nextLink so a vault larger than one page is fully inventoried.
func TestAzureKeyVaultPaginatesNextLink(t *testing.T) {
	var page int
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer az-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		host := "http://" + r.Host
		if strings.HasSuffix(r.URL.Path, "/keys/k1") || strings.HasSuffix(r.URL.Path, "/keys/k2") {
			_ = json.NewEncoder(w).Encode(map[string]any{"key": map[string]any{"kty": "RSA"}})
			return
		}
		if r.URL.Path == "/keys" && r.URL.Query().Get("marker") == "" {
			page++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value":    []map[string]any{{"kid": host + "/keys/k1", "attributes": map[string]any{"enabled": true}}},
				"nextLink": host + "/keys?api-version=7.4&marker=page2",
			})
			return
		}
		// page 2 (via nextLink)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{{"kid": host + "/keys/k2", "attributes": map[string]any{"enabled": true}}},
		})
	}))
	t.Cleanup(srv.Close)

	keys, err := NewAzureKeyVaultSource(srv.URL, "az-token", srv.Client()).ListKeys(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("both pages must be inventoried, got %d", len(keys))
	}
}
