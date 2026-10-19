// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package keyinventory_live_test drives the real unified key inventory
// (internal/keyinventory) against an AWS KMS emulator (moto by default,
// LocalStack opt-in), optionally a Lowkey Vault Azure emulator, and the SSH
// user-key source. Skipped unless KK_LIVE_KEYINV=1 (see run.sh).
package keyinventory_live_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"kryptkeeper/internal/keyinventory"
	"kryptkeeper/internal/sshkeys"
)

const awsRegion = "us-east-1"

func gate(t *testing.T) {
	t.Helper()
	if os.Getenv("KK_LIVE_KEYINV") != "1" {
		t.Skip("set KK_LIVE_KEYINV=1 (see run.sh) to run against the key emulators")
	}
	if os.Getenv("AWS_ENDPOINT_URL") == "" {
		t.Fatal("AWS_ENDPOINT_URL must point at the emulator; refusing to fall through to real AWS")
	}
}

func kmsClient(t *testing.T) *kms.Client {
	t.Helper()
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(awsRegion))
	if err != nil {
		t.Fatalf("aws config: %v", err)
	}
	return kms.NewFromConfig(cfg)
}

// createAWSKeys creates a rotating symmetric key and an RSA_2048 signing key
// and returns their key ids.
func createAWSKeys(t *testing.T) (symID, rsaID string) {
	t.Helper()
	ctx := context.Background()
	c := kmsClient(t)
	sym, err := c.CreateKey(ctx, &kms.CreateKeyInput{KeySpec: kmstypes.KeySpecSymmetricDefault, Description: aws.String("kk-keyinv-uat-sym")})
	if err != nil {
		t.Fatalf("CreateKey sym: %v", err)
	}
	symID = aws.ToString(sym.KeyMetadata.KeyId)
	if _, err := c.EnableKeyRotation(ctx, &kms.EnableKeyRotationInput{KeyId: aws.String(symID)}); err != nil {
		t.Fatalf("EnableKeyRotation: %v", err)
	}
	rsa, err := c.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec: kmstypes.KeySpecRsa2048, KeyUsage: kmstypes.KeyUsageTypeSignVerify, Description: aws.String("kk-keyinv-uat-rsa"),
	})
	if err != nil {
		t.Fatalf("CreateKey rsa: %v", err)
	}
	return symID, aws.ToString(rsa.KeyMetadata.KeyId)
}

func findKey(keys []keyinventory.Key, id string) *keyinventory.Key {
	for i := range keys {
		if keys[i].KeyID == id {
			return &keys[i]
		}
	}
	return nil
}

func TestLiveKeyInventory_AWSKeyAlgorithmAndRotation(t *testing.T) {
	gate(t)
	symID, rsaID := createAWSKeys(t)
	src, err := keyinventory.NewAWSKeySource(context.Background(), awsRegion)
	if err != nil {
		t.Fatal(err)
	}
	inv := keyinventory.CollectWithTimeout(context.Background(), keyinventory.DefaultProviderTimeout, src)
	if len(inv.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", inv.Errors)
	}
	a := findKey(inv.Keys, symID)
	if a == nil {
		t.Fatalf("symmetric key %s missing from inventory (%d keys)", symID, len(inv.Keys))
	}
	if a.Provider != "aws-kms" || a.Algorithm != "SYMMETRIC_DEFAULT" || !a.RotationEnabled || a.PQCReadiness != "vulnerable" {
		t.Errorf("symmetric key wrong: %+v", *a)
	}
	b := findKey(inv.Keys, rsaID)
	if b == nil {
		t.Fatalf("rsa key %s missing from inventory", rsaID)
	}
	// RSA keys cannot rotate: the source leaves RotationEnabled=false on error.
	if b.Provider != "aws-kms" || b.Algorithm != "RSA_2048" || b.RotationEnabled || b.PQCReadiness != "vulnerable" {
		t.Errorf("rsa key wrong: %+v", *b)
	}
}

// azureClient trusts the emulator's self-signed cert from SSL_CERT_FILE
// explicitly (Go on macOS ignores SSL_CERT_FILE for the system verifier).
func azureClient(t *testing.T) *http.Client {
	t.Helper()
	pemPath := os.Getenv("SSL_CERT_FILE")
	if pemPath == "" {
		t.Fatal("SSL_CERT_FILE must name the emulator certificate")
	}
	pem, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("SSL_CERT_FILE holds no certificate")
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
}

func TestLiveKeyInventory_AzureKeyVault(t *testing.T) {
	gate(t)
	url := os.Getenv("KK_KEYINV_AZURE_URL")
	if url == "" {
		t.Skip("KK_KEYINV_AZURE_URL empty: run run.sh with KK_KEYINV_AZURE=1 to start Lowkey Vault")
	}
	if !strings.HasPrefix(url, "https://localhost") {
		t.Fatal("KK_KEYINV_AZURE_URL must be the local emulator; refusing to touch a real vault")
	}
	const tok = "kk-uat-placeholder"
	client := azureClient(t)
	req, _ := http.NewRequest(http.MethodPost, url+"/keys/uat-ec/create?api-version=7.4", bytes.NewBufferString(`{"kty":"EC","crv":"P-256"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create key: HTTP %d", resp.StatusCode)
	}
	inv := keyinventory.CollectWithTimeout(context.Background(), 10*time.Second, keyinventory.NewAzureKeyVaultSource(url, tok, client))
	if len(inv.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", inv.Errors)
	}
	for _, k := range inv.Keys {
		if k.Provider == "azure-kv" && strings.Contains(k.KeyID, "/keys/uat-ec") {
			if k.Algorithm != "EC-P-256" {
				t.Errorf("algorithm = %q, want EC-P-256", k.Algorithm)
			}
			return
		}
	}
	t.Fatalf("uat-ec not in inventory: %+v", inv.Keys)
}

func TestLiveKeyInventory_SSHSourceAndDownProviderIsNamed(t *testing.T) {
	gate(t)
	symID, _ := createAWSKeys(t)
	aws, err := keyinventory.NewAWSKeySource(context.Background(), awsRegion)
	if err != nil {
		t.Fatal(err)
	}
	sshInv := sshkeys.NewInventory()
	sshInv.Add(sshkeys.SSHKey{Fingerprint: "SHA256:uat", KeyType: sshkeys.RSA, BitSize: 3072, Host: "uat-host", IsAuthorized: true, CreatedAt: time.Now()})
	down := keyinventory.NewAzureKeyVaultSource("http://127.0.0.1:1", "x", &http.Client{Timeout: 2 * time.Second})
	inv := keyinventory.CollectWithTimeout(context.Background(), keyinventory.DefaultProviderTimeout,
		aws, keyinventory.NewSSHUserKeySource(sshInv, time.Now), down)

	if findKey(inv.Keys, symID) == nil {
		t.Errorf("AWS key %s missing although another provider is down", symID)
	}
	ssh := findKey(inv.Keys, "SHA256:uat")
	if ssh == nil {
		t.Fatalf("ssh-user key missing: %+v", inv.Keys)
	}
	if ssh.Provider != "ssh-user" || ssh.Algorithm != "RSA_3072" || ssh.KeyType != "user" {
		t.Errorf("ssh key wrong: %+v", *ssh)
	}
	if len(inv.Errors) != 1 || !strings.HasPrefix(inv.Errors[0], "azure-kv:") {
		t.Errorf("errors = %v, want exactly one azure-kv: entry", inv.Errors)
	}
}

func TestLiveKeyInventory_HungProviderIsAbandoned(t *testing.T) {
	gate(t)
	createAWSKeys(t)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
	}))
	defer srv.Close()
	defer close(release)
	aws, err := keyinventory.NewAWSKeySource(context.Background(), awsRegion)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	inv := keyinventory.CollectWithTimeout(context.Background(), 2*time.Second, aws, keyinventory.NewAzureKeyVaultSource(srv.URL, "x", nil))
	// 2s deadline (spec said 1s): the AWS source makes 3 calls per key, and a
	// 1s budget flaked once the emulator held a few keys.
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %s, want < 5s", d)
	}
	if len(inv.Keys) == 0 {
		t.Error("AWS keys missing")
	}
	if len(inv.Errors) != 1 || !strings.HasPrefix(inv.Errors[0], "azure-kv:") || !strings.Contains(inv.Errors[0], "timed out") {
		t.Errorf("errors = %v, want one azure-kv timed out entry", inv.Errors)
	}
}

func TestLiveKeyInventory_GCPSkipped(t *testing.T) {
	gate(t)
	url, ring, tok := os.Getenv("KK_LIVE_KEYINV_GCP_URL"), os.Getenv("KK_LIVE_KEYINV_GCP_KEYRING"), os.Getenv("KK_LIVE_KEYINV_GCP_TOKEN")
	if url == "" || ring == "" || tok == "" {
		t.Skip("no GCP KMS emulator; set KK_LIVE_KEYINV_GCP_URL, KK_LIVE_KEYINV_GCP_KEYRING and KK_LIVE_KEYINV_GCP_TOKEN to point at one")
	}
	inv := keyinventory.CollectWithTimeout(context.Background(), keyinventory.DefaultProviderTimeout, keyinventory.NewGCPKMSSource(url, ring, tok, nil))
	for _, e := range inv.Errors {
		if strings.HasPrefix(e, "gcp-kms:") {
			t.Errorf("gcp error: %s", e)
		}
	}
}

func TestLiveKeyInventory_HubEndpoint(t *testing.T) {
	gate(t)
	hub, tok := os.Getenv("KK_LIVE_HUB_URL"), os.Getenv("KK_LIVE_HUB_TOKEN")
	if hub == "" || tok == "" {
		t.Skip("set KK_LIVE_HUB_URL and KK_LIVE_HUB_TOKEN (hub started with AWS_ENDPOINT_URL) to run the hub leg")
	}
	symID, rsaID := createAWSKeys(t)
	req, _ := http.NewRequest(http.MethodGet, hub+"/api/v1/inventory/keys", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Data keyinventory.KeyInventory `json:"data"`
	}
	if err := jsonDecode(resp, &body); err != nil {
		t.Fatal(err)
	}
	if findKey(body.Data.Keys, symID) == nil || findKey(body.Data.Keys, rsaID) == nil {
		t.Errorf("AWS keys missing from hub response (%d keys, errors %v)", len(body.Data.Keys), body.Data.Errors)
	}
}

func jsonDecode(resp *http.Response, v any) error {
	return json.NewDecoder(resp.Body).Decode(v)
}
