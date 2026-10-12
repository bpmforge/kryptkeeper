// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const gcpKMSBase = "https://cloudkms.googleapis.com/v1"

// signGCP calls Google Cloud KMS AsymmetricSign.
// s.config.KeyURI must be the full resource name:
//
//	projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}/cryptoKeyVersions/{version}
func (s *CloudKMSSigner) signGCP(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	token, err := gcpKMSToken(context.Background())
	if err != nil {
		return nil, fmt.Errorf("gcp kms: get token: %w", err)
	}

	algo, err := gcpSigningAlgorithm(s.publicKey, opts)
	if err != nil {
		return nil, fmt.Errorf("gcp kms: %w", err)
	}

	body, _ := json.Marshal(map[string]any{
		"digest": map[string]string{
			gcpDigestField(opts): base64.StdEncoding.EncodeToString(digest),
		},
		"digestCrc32c": nil, // optional integrity check
		"algorithm":    algo,
	})

	url := fmt.Sprintf("%s/%s:asymmetricSign", gcpKMSBase, s.config.KeyURI)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := gcpHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gcp kms: asymmetricSign: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcp kms: asymmetricSign returned %d: %s", resp.StatusCode, gcpTruncate(string(raw)))
	}

	var out struct {
		Signature string `json:"signature"` // base64-encoded DER signature
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("gcp kms: parse sign response: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(out.Signature)
	if err != nil {
		return nil, fmt.Errorf("gcp kms: decode signature: %w", err)
	}
	return sig, nil
}

// gcpKMSGetPublicKey retrieves the public key for a GCP KMS asymmetric key version.
func gcpKMSGetPublicKey(keyVersionName string) (crypto.PublicKey, error) {
	token, err := gcpKMSToken(context.Background())
	if err != nil {
		return nil, fmt.Errorf("gcp kms: get token: %w", err)
	}

	url := fmt.Sprintf("%s/%s/publicKey", gcpKMSBase, keyVersionName)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := gcpHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gcp kms: getPublicKey: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcp kms: getPublicKey returned %d: %s", resp.StatusCode, gcpTruncate(string(raw)))
	}

	var out struct {
		Pem string `json:"pem"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("gcp kms: parse public key response: %w", err)
	}

	block, _ := pem.Decode([]byte(out.Pem))
	if block == nil {
		return nil, fmt.Errorf("gcp kms: no PEM block in public key response")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("gcp kms: parse public key DER: %w", err)
	}
	return pub, nil
}

// gcpKMSToken retrieves a GCP OAuth2 token via GOOGLE_ACCESS_TOKEN env var or
// the GCE metadata server.
func gcpKMSToken(ctx context.Context) (string, error) {
	if tok := os.Getenv("GOOGLE_ACCESS_TOKEN"); tok != "" {
		return tok, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("gcp metadata server unreachable (set GOOGLE_ACCESS_TOKEN): %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gcp metadata server returned %d (set GOOGLE_ACCESS_TOKEN)", resp.StatusCode)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("parse metadata token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("gcp metadata server returned an empty access token")
	}
	return tok.AccessToken, nil
}

func gcpSigningAlgorithm(pub crypto.PublicKey, opts crypto.SignerOpts) (string, error) {
	_ = pub
	_ = opts
	// GCP KMS determines the algorithm from the key — pass empty string and
	// let the API use the key's configured algorithm. For explicit control,
	// map hash + key type to the GCP algorithm enum.
	return "", nil
}

func gcpDigestField(opts crypto.SignerOpts) string {
	switch opts.HashFunc() {
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	default:
		return "sha256"
	}
}

// generateKeyGCP is the CloudKMSStore method that delegates to the package-level
// function and stores the result.
func (s *CloudKMSStore) generateKeyGCP(id string, algo Algorithm) (KeyMetadata, error) {
	pub, keyURI, err := generateKeyGCP(id, algo)
	if err != nil {
		return KeyMetadata{}, err
	}
	meta := KeyMetadata{
		ID:        id,
		Algorithm: algo,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	s.keys[id] = &cloudKMSKeyEntry{
		meta:   meta,
		pubKey: pub,
		config: CloudKMSConfig{Provider: "gcp", KeyURI: keyURI},
	}
	return meta, nil
}

// generateKeyGCP (package-level) creates a new asymmetric signing key in Google Cloud KMS.
//
// Required env vars:
//
//	KRYPTKEEPER_GCP_PROJECT  — GCP project ID
//	KRYPTKEEPER_GCP_LOCATION — GCP region (default: global)
//	KRYPTKEEPER_GCP_KEYRING  — Key ring name
func generateKeyGCP(id string, algo Algorithm) (crypto.PublicKey, string, error) {
	project := os.Getenv("KRYPTKEEPER_GCP_PROJECT")
	location := os.Getenv("KRYPTKEEPER_GCP_LOCATION")
	if location == "" {
		location = "global"
	}
	keyRing := os.Getenv("KRYPTKEEPER_GCP_KEYRING")
	if project == "" || keyRing == "" {
		return nil, "", fmt.Errorf("gcp kms: KRYPTKEEPER_GCP_PROJECT and KRYPTKEEPER_GCP_KEYRING are required")
	}

	gcpAlgo, err := gcpKeyAlgorithm(algo)
	if err != nil {
		return nil, "", fmt.Errorf("gcp kms: %w", err)
	}

	token, err := gcpKMSToken(context.Background())
	if err != nil {
		return nil, "", fmt.Errorf("gcp kms: get token: %w", err)
	}

	parent := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", project, location, keyRing)
	createURL := fmt.Sprintf("%s/%s/cryptoKeys?cryptoKeyId=%s", gcpKMSBase, parent, url.QueryEscape(id))

	protection, err := gcpProtectionLevel()
	if err != nil {
		return nil, "", fmt.Errorf("gcp kms: %w", err)
	}
	labels, err := gcpKeyLabels(id)
	if err != nil {
		return nil, "", fmt.Errorf("gcp kms: %w", err)
	}
	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"purpose": "ASYMMETRIC_SIGN",
		"labels":  labels,
		"versionTemplate": map[string]interface{}{
			"algorithm":       gcpAlgo,
			"protectionLevel": protection,
		},
	})

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, createURL, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := gcpHTTPClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("gcp kms: create key: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		hint := ""
		if protection == "HSM" {
			hint = " (HSM protection requested; if this location does not offer HSM keys set " + envGCPProtection + "=software)"
		}
		return nil, "", fmt.Errorf("gcp kms: create key returned %d: %s%s", resp.StatusCode, gcpTruncate(string(raw)), hint)
	}

	// The response contains the key resource name; append /cryptoKeyVersions/1 for the public key.
	var created struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		return nil, "", fmt.Errorf("gcp kms: parse create response: %w", err)
	}
	keyVersionName := created.Name + "/cryptoKeyVersions/1"

	pub, err := gcpKMSGetPublicKey(keyVersionName)
	if err != nil {
		return nil, "", fmt.Errorf("gcp kms: get public key after create: %w", err)
	}
	return pub, keyVersionName, nil
}

func gcpKeyAlgorithm(algo Algorithm) (string, error) {
	switch algo {
	case ECDSAP256:
		return "EC_SIGN_P256_SHA256", nil
	case ECDSAP384:
		return "EC_SIGN_P384_SHA384", nil
	case RSA2048:
		return "RSA_SIGN_PKCS1_2048_SHA256", nil
	case RSA4096:
		return "RSA_SIGN_PKCS1_4096_SHA256", nil
	default:
		return "", fmt.Errorf("unsupported algorithm %s for GCP KMS", algo)
	}
}

var gcpHTTPClient = &http.Client{Timeout: 30 * time.Second}

func gcpTruncate(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
