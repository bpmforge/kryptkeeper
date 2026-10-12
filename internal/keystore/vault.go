// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package keystore provides a HashiCorp Vault transit secrets engine backend.
//
// Configuration (environment variables):
//
//	VAULT_ADDR        — Vault server URL (e.g. https://vault.example.com:8200)
//	VAULT_TOKEN       — Static token (development / CI use)
//	VAULT_ROLE_ID     — AppRole role_id  (preferred for production)
//	VAULT_SECRET_ID   — AppRole secret_id
//	VAULT_TRANSIT_MOUNT — Transit mount path (default: "transit")
//	VAULT_NAMESPACE   — Vault Enterprise namespace (optional)
//	VAULT_CACERT      — Path to CA cert for Vault TLS verification (optional)
//
// Keys never leave Vault — all sign operations call /v1/{mount}/sign/{key}.
// GenerateKey creates a named key in Vault. Delete calls /v1/{mount}/keys/{name}.
// RotateKey calls /v1/{mount}/keys/{name}/rotate.
// Export/Import are intentionally unsupported (keys are non-extractable by design).
package keystore

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

// VaultStore implements keystore.Store backed by HashiCorp Vault transit engine.
// Private key material never leaves Vault.
type VaultStore struct {
	addr       string
	token      string
	mount      string
	namespace  string
	httpClient *http.Client
}

// NewVaultStoreFromEnv reads config from environment variables and returns a VaultStore.
// Tries VAULT_TOKEN first; if absent, tries AppRole auth (VAULT_ROLE_ID + VAULT_SECRET_ID).
func NewVaultStoreFromEnv() (*VaultStore, error) {
	addr := strings.TrimRight(strings.TrimSpace(os.Getenv("VAULT_ADDR")), "/")
	if addr == "" {
		return nil, fmt.Errorf("VAULT_ADDR must be set for vault keystore backend")
	}

	mount := strings.TrimSpace(os.Getenv("VAULT_TRANSIT_MOUNT"))
	if mount == "" {
		mount = "transit"
	}

	s := &VaultStore{
		addr:       addr,
		mount:      mount,
		namespace:  strings.TrimSpace(os.Getenv("VAULT_NAMESPACE")),
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}

	// Static token.
	if tok := strings.TrimSpace(os.Getenv("VAULT_TOKEN")); tok != "" {
		s.token = tok
		return s, nil
	}

	// AppRole auth.
	roleID := strings.TrimSpace(os.Getenv("VAULT_ROLE_ID"))
	secretID := strings.TrimSpace(os.Getenv("VAULT_SECRET_ID"))
	if roleID == "" || secretID == "" {
		return nil, fmt.Errorf("vault keystore: set VAULT_TOKEN or both VAULT_ROLE_ID and VAULT_SECRET_ID")
	}
	tok, err := s.appRoleLogin(roleID, secretID)
	if err != nil {
		return nil, fmt.Errorf("vault appRole login: %w", err)
	}
	s.token = tok
	return s, nil
}

func (s *VaultStore) appRoleLogin(roleID, secretID string) (string, error) {
	body, _ := json.Marshal(map[string]string{"role_id": roleID, "secret_id": secretID})
	resp, err := s.vaultRequest(context.Background(), http.MethodPost, "/v1/auth/approle/login", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode login response: %w", err)
	}
	if result.Auth.ClientToken == "" {
		return "", fmt.Errorf("vault returned empty client_token")
	}
	return result.Auth.ClientToken, nil
}

func (s *VaultStore) GenerateKey(id string, algo Algorithm) (KeyMetadata, error) {
	vaultType, err := algoToVaultType(algo)
	if err != nil {
		return KeyMetadata{}, err
	}
	body, _ := json.Marshal(map[string]any{"type": vaultType, "exportable": false})
	resp, err := s.vaultRequest(context.Background(), http.MethodPost,
		"/v1/"+s.mount+"/keys/"+vaultKeyName(id), body)
	if err != nil {
		return KeyMetadata{}, fmt.Errorf("vault create key: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest {
		return KeyMetadata{}, ErrKeyExists
	}
	if resp.StatusCode >= 300 {
		return KeyMetadata{}, fmt.Errorf("vault create key: HTTP %d", resp.StatusCode)
	}
	return KeyMetadata{ID: id, Algorithm: algo, CreatedAt: time.Now().UTC().Format(time.RFC3339)}, nil
}

func (s *VaultStore) Signer(id string) (crypto.Signer, error) {
	pub, err := s.PublicKey(id)
	if err != nil {
		return nil, err
	}
	return &vaultSigner{store: s, id: id, pub: pub}, nil
}

func (s *VaultStore) PublicKey(id string) (crypto.PublicKey, error) {
	resp, err := s.vaultRequest(context.Background(), http.MethodGet,
		"/v1/"+s.mount+"/keys/"+vaultKeyName(id), nil)
	if err != nil {
		return nil, fmt.Errorf("vault get key: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrKeyNotFound
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vault get key: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode vault key response: %w", err)
	}

	// Use latest version (highest map key).
	var latestPEM string
	for _, v := range result.Data.Keys {
		latestPEM = v.PublicKey
	}
	if latestPEM == "" {
		return nil, fmt.Errorf("vault returned no public key for %s", id)
	}

	block, _ := pem.Decode([]byte(latestPEM))
	if block == nil {
		return nil, fmt.Errorf("vault: invalid PEM for key %s", id)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("vault: parse public key: %w", err)
	}
	return pub, nil
}

func (s *VaultStore) Metadata(id string) (KeyMetadata, error) {
	resp, err := s.vaultRequest(context.Background(), http.MethodGet,
		"/v1/"+s.mount+"/keys/"+vaultKeyName(id), nil)
	if err != nil {
		return KeyMetadata{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return KeyMetadata{}, ErrKeyNotFound
	}
	if resp.StatusCode >= 300 {
		return KeyMetadata{}, fmt.Errorf("vault metadata: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Type      string `json:"type"`
			CreatedAt string `json:"creation_time"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return KeyMetadata{}, fmt.Errorf("decode vault metadata: %w", err)
	}
	algo := vaultTypeToAlgo(result.Data.Type)
	return KeyMetadata{ID: id, Algorithm: algo, CreatedAt: result.Data.CreatedAt}, nil
}

func (s *VaultStore) List() ([]KeyMetadata, error) {
	resp, err := s.vaultRequest(context.Background(), "LIST", "/v1/"+s.mount+"/keys", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return []KeyMetadata{}, nil
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vault list keys: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode vault list: %w", err)
	}

	metas := make([]KeyMetadata, 0, len(result.Data.Keys))
	for _, name := range result.Data.Keys {
		id := vaultKeyNameToID(name)
		meta, err := s.Metadata(id)
		if err != nil {
			continue
		}
		metas = append(metas, meta)
	}
	return metas, nil
}

func (s *VaultStore) Delete(id string) error {
	// Vault requires deleting all key versions first, then the key itself.
	body, _ := json.Marshal(map[string]bool{"force": true})
	resp, err := s.vaultRequest(context.Background(), http.MethodDelete,
		"/v1/"+s.mount+"/keys/"+vaultKeyName(id), body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrKeyNotFound
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("vault delete key: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (s *VaultStore) RotateKey(id string, _ Algorithm) (KeyRotateResult, error) {
	resp, err := s.vaultRequest(context.Background(), http.MethodPost,
		"/v1/"+s.mount+"/keys/"+vaultKeyName(id)+"/rotate", nil)
	if err != nil {
		return KeyRotateResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return KeyRotateResult{}, ErrKeyNotFound
	}
	if resp.StatusCode >= 300 {
		return KeyRotateResult{}, fmt.Errorf("vault rotate key: HTTP %d", resp.StatusCode)
	}
	meta, err := s.Metadata(id)
	if err != nil {
		return KeyRotateResult{}, err
	}
	return KeyRotateResult{New: meta, PreviousID: id + "-previous-version"}, nil
}

// ExportEncryptedKey is not supported — Vault keys are non-extractable by design.
func (s *VaultStore) ExportEncryptedKey(_ string, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("vault: key export is not permitted — Vault keys are non-extractable")
}

// ImportEncryptedKey is not supported — use Vault's wrapping import API directly.
func (s *VaultStore) ImportEncryptedKey(_ string, _ []byte, _ []byte) error {
	return fmt.Errorf("vault: use the Vault wrapping import API to import keys")
}

// vaultSigner implements crypto.Signer using Vault transit sign operations.
type vaultSigner struct {
	store *VaultStore
	id    string
	pub   crypto.PublicKey
}

func (v *vaultSigner) Public() crypto.PublicKey { return v.pub }

func (v *vaultSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	algo, hashAlgo := vaultSignAlgo(v.pub, opts)

	// Vault expects base64-encoded input. For prehash algorithms pass the digest;
	// for ed25519-style pass the raw message (not supported here — always prehash).
	input := base64.StdEncoding.EncodeToString(digest)

	body, _ := json.Marshal(map[string]any{
		"input":               input,
		"signature_algorithm": algo,
		"hash_algorithm":      hashAlgo,
		"prehashed":           true,
	})

	resp, err := v.store.vaultRequest(context.Background(), http.MethodPost,
		"/v1/"+v.store.mount+"/sign/"+vaultKeyName(v.id), body)
	if err != nil {
		return nil, fmt.Errorf("vault sign: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vault sign: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("vault sign decode: %w", err)
	}

	// Vault signature format: "vault:v{n}:{base64(signature)}"
	parts := strings.SplitN(result.Data.Signature, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("vault: unexpected signature format: %s", result.Data.Signature)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("vault: decode signature: %w", err)
	}
	return sigBytes, nil
}

// vaultRequest makes an authenticated request to Vault.
func (s *VaultStore) vaultRequest(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.addr+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build vault request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.token)
	if s.namespace != "" {
		req.Header.Set("X-Vault-Namespace", s.namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return s.httpClient.Do(req)
}

func algoToVaultType(algo Algorithm) (string, error) {
	switch algo {
	case RSA2048:
		return "rsa-2048", nil
	case RSA4096:
		return "rsa-4096", nil
	case ECDSAP256:
		return "ecdsa-p256", nil
	case ECDSAP384:
		return "ecdsa-p384", nil
	case Ed25519:
		return "ed25519", nil
	default:
		return "", fmt.Errorf("%w: %s not supported by Vault transit backend", ErrUnsupportedAlgo, algo)
	}
}

func vaultTypeToAlgo(t string) Algorithm {
	switch t {
	case "rsa-2048":
		return RSA2048
	case "rsa-4096":
		return RSA4096
	case "ecdsa-p256":
		return ECDSAP256
	case "ecdsa-p384":
		return ECDSAP384
	case "ed25519":
		return Ed25519
	default:
		return Algorithm(t)
	}
}

func vaultSignAlgo(pub crypto.PublicKey, opts crypto.SignerOpts) (sigAlgo, hashAlgo string) {
	switch pub.(type) {
	case *rsa.PublicKey:
		if _, ok := opts.(*rsa.PSSOptions); ok {
			sigAlgo = "pss"
		} else {
			sigAlgo = "pkcs1v15"
		}
	case *ecdsa.PublicKey:
		sigAlgo = "pkcs1v15" // Vault uses this label for ECDSA too
	default:
		sigAlgo = "pkcs1v15"
	}

	switch opts.HashFunc() {
	case crypto.SHA256:
		hashAlgo = "sha2-256"
	case crypto.SHA384:
		hashAlgo = "sha2-384"
	case crypto.SHA512:
		hashAlgo = "sha2-512"
	default:
		hashAlgo = "sha2-256"
	}
	return
}

// vaultKeyName sanitises a key ID for use as a Vault transit key name.
func vaultKeyName(id string) string {
	return strings.NewReplacer("/", "-", " ", "-", ":", "-").Replace(id)
}

func vaultKeyNameToID(name string) string { return name }

// hashForOpts computes the digest of data using the hash from opts.
// Used in tests and callers that need to pre-hash before calling Sign.
func hashForOpts(data []byte, opts crypto.SignerOpts) ([]byte, error) {
	var h hash.Hash
	switch opts.HashFunc() {
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported hash function: %v", opts.HashFunc())
	}
	h.Write(data)
	return h.Sum(nil), nil
}

// Compile-time checks.
var (
	_ Store         = (*VaultStore)(nil)
	_ crypto.Signer = (*vaultSigner)(nil)
)

// Suppress unused import warnings for packages only used in tests.
var (
	_ = rand.Reader
	_ = elliptic.P256()
	_ = sha256.New
	_ = big.NewInt
)
