// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// CLOUD-002: the AWS create call carries the managed tags.
func TestAWSCreateKeyInputCarriesManagedTags(t *testing.T) {
	t.Setenv(envKMSTags, `{"team":"pki"}`)
	in, err := awsCreateKeyInput("ca-root", types.KeySpecEccNistP256)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, tg := range in.Tags {
		got[*tg.TagKey] = *tg.TagValue
	}
	if got["kryptkeeper:managed"] != "true" || got["kryptkeeper:key-id"] != "ca-root" || got["team"] != "pki" {
		t.Fatalf("tags = %v", got)
	}
	if in.KeyUsage != types.KeyUsageTypeSignVerify {
		t.Fatalf("usage = %v", in.KeyUsage)
	}
}

func TestOperatorTagsRejectReservedPrefixAndBadJSON(t *testing.T) {
	for _, v := range []string{`{"kryptkeeper:managed":"false"}`, `{"Kryptkeeper_x":"1"}`, `not json`, `{"a":1}`} {
		t.Setenv(envKMSTags, v)
		if _, err := awsKeyTags("k"); err == nil {
			t.Errorf("%s: expected error", v)
		}
	}
}

func TestCloudKeyIDValidation(t *testing.T) {
	for _, bad := range []string{"", "x&skipInitialVersionCreation=true", "a/b", "a?b", "..", "a#b", strings.Repeat("a", 64)} {
		if validateCloudKeyID(bad) == nil {
			t.Errorf("id %q must be refused", bad)
		}
	}
	if err := validateCloudKeyID("ca-root_1"); err != nil {
		t.Fatal(err)
	}
	store, _ := NewCloudKMSStore("gcp")
	if _, err := store.GenerateKey("x&skipInitialVersionCreation=true", ECDSAP256); err == nil || !strings.Contains(err.Error(), "invalid key id") {
		t.Fatalf("GenerateKey must refuse a hostile id before any cloud call, got %v", err)
	}
}

// roundTripFunc lets the GCP test intercept the hard-coded KMS base URL.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func gcpCreateBody(t *testing.T, protectionEnv string) (map[string]any, error) {
	t.Helper()
	var body map[string]any
	prev := gcpHTTPClient
	gcpHTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(`{"error":"stop"}`)), Header: http.Header{}}, nil
	})}
	t.Cleanup(func() { gcpHTTPClient = prev })
	t.Setenv("KRYPTKEEPER_GCP_PROJECT", "p")
	t.Setenv("KRYPTKEEPER_GCP_KEYRING", "r")
	t.Setenv("GOOGLE_ACCESS_TOKEN", "tok")
	t.Setenv(envGCPProtection, protectionEnv)
	_, _, err := generateKeyGCP("My-Key", ECDSAP256)
	return body, err
}

// CLOUD-003: HSM by default, SOFTWARE only when the operator asks; labels sent.
func TestGCPCreateProtectionLevelAndLabels(t *testing.T) {
	body, err := gcpCreateBody(t, "")
	if err == nil || !strings.Contains(err.Error(), envGCPProtection) {
		t.Fatalf("a rejected HSM create must hint at the opt-down, got %v", err)
	}
	vt := body["versionTemplate"].(map[string]any)
	if vt["protectionLevel"] != "HSM" {
		t.Fatalf("default protection = %v, want HSM", vt["protectionLevel"])
	}
	labels := body["labels"].(map[string]any)
	if labels["kryptkeeper_managed"] != "true" || labels["kryptkeeper_key_id"] != "my-key" {
		t.Fatalf("labels = %v", labels)
	}

	body, _ = gcpCreateBody(t, "software")
	if body["versionTemplate"].(map[string]any)["protectionLevel"] != "SOFTWARE" {
		t.Fatalf("software opt-down not honoured: %v", body)
	}

	if _, err := gcpCreateBody(t, "bogus"); err == nil {
		t.Fatal("an unknown protection value must be refused, not defaulted")
	}
}

type azureCapture struct {
	body map[string]any
	path string
}

func azureCreate(t *testing.T, hsmEnv string, algo Algorithm, status int) (azureCapture, error) {
	t.Helper()
	var cap azureCapture
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			_, _ = w.Write([]byte(`{"access_token":"tok"}`))
			return
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &cap.body)
		cap.path = r.URL.EscapedPath()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":{"message":"not supported"}}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("AZURE_KEYVAULT_URL", srv.URL)
	t.Setenv("AZURE_AUTHORITY_HOST", srv.URL)
	t.Setenv("AZURE_TENANT_ID", "tenant")
	t.Setenv("AZURE_CLIENT_ID", "client")
	t.Setenv("AZURE_CLIENT_SECRET", "not-a-real-secret")
	t.Setenv(envAzureKeyHSM, hsmEnv)
	_, _, err := generateKeyAzure("ca-key", algo)
	return cap, err
}

// CLOUD-003: Azure creates EC-HSM / RSA-HSM by default and says what to do
// when a Standard vault refuses them.
func TestAzureCreateHSMByDefault(t *testing.T) {
	c, err := azureCreate(t, "", ECDSAP256, 400)
	if c.body["kty"] != "EC-HSM" {
		t.Fatalf("kty = %v, want EC-HSM", c.body["kty"])
	}
	if err == nil || !strings.Contains(err.Error(), "Premium vault") {
		t.Fatalf("expected an actionable HSM error, got %v", err)
	}
	tags := c.body["tags"].(map[string]any)
	if tags["kryptkeeper_managed"] != "true" || tags["kryptkeeper_key_id"] != "ca-key" {
		t.Fatalf("tags = %v", tags)
	}

	c, _ = azureCreate(t, "true", RSA2048, 400)
	if c.body["kty"] != "RSA-HSM" || c.body["key_size"] != float64(2048) {
		t.Fatalf("rsa body = %v", c.body)
	}

	c, err = azureCreate(t, "false", ECDSAP384, 400)
	if c.body["kty"] != "EC" {
		t.Fatalf("software opt-down kty = %v, want EC", c.body["kty"])
	}
	if err != nil && strings.Contains(err.Error(), "Premium vault") {
		t.Fatalf("the HSM hint must not appear for software keys: %v", err)
	}

	if _, err := azureCreate(t, "maybe", ECDSAP256, 400); err == nil || !strings.Contains(err.Error(), envAzureKeyHSM) {
		t.Fatalf("an unparseable value must be refused, got %v", err)
	}
}

func TestAzureParseJWKAcceptsHSMKeyTypes(t *testing.T) {
	// P-256 generator point coordinates (public, well-known test vector).
	x := "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY"
	y := "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
	for _, kty := range []string{"EC", "EC-HSM"} {
		if _, err := azureParseJWK(kty, "", "", x, y, "P-256"); err != nil {
			t.Errorf("%s: %v", kty, err)
		}
	}
}
