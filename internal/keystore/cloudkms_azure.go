// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const azureKVAPIVersion = "7.4"

// signAzure calls Azure Key Vault Sign.
// s.config.KeyURI must be the full key identifier URI:
//
//	https://{vault}.vault.azure.net/keys/{key-name}/{key-version}
func (s *CloudKMSSigner) signAzure(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	token, err := azureKVToken(context.Background())
	if err != nil {
		return nil, fmt.Errorf("azure kv: get token: %w", err)
	}

	algo, err := azureSigningAlgorithm(s.publicKey, opts)
	if err != nil {
		return nil, fmt.Errorf("azure kv: %w", err)
	}

	body, _ := json.Marshal(map[string]string{
		"alg":   algo,
		"value": base64.RawURLEncoding.EncodeToString(digest),
	})

	signURL := fmt.Sprintf("%s/sign?api-version=%s", s.config.KeyURI, azureKVAPIVersion)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, signURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := azureHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure kv: sign: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure kv: sign returned %d: %s", resp.StatusCode, azureTruncate(string(raw)))
	}

	var out struct {
		Value string `json:"value"` // base64url-encoded signature
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("azure kv: parse sign response: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(out.Value)
	if err != nil {
		return nil, fmt.Errorf("azure kv: decode signature: %w", err)
	}
	// Key Vault returns ECDSA as raw R||S (JWS); crypto.Signer callers such as
	// x509.CreateCertificate require ASN.1 DER, so an unconverted signature
	// would be embedded in certificates that no verifier accepts.
	if pub, ok := s.publicKey.(*ecdsa.PublicKey); ok {
		return azureRawECDSAToASN1(sig, pub)
	}
	return sig, nil
}

func azureRawECDSAToASN1(raw []byte, pub *ecdsa.PublicKey) ([]byte, error) {
	n := (pub.Curve.Params().BitSize + 7) / 8
	if len(raw) != 2*n {
		return nil, fmt.Errorf("azure kv: ECDSA signature is %d bytes, want %d", len(raw), 2*n)
	}
	return asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(raw[:n]), new(big.Int).SetBytes(raw[n:]),
	})
}

// azureKVToken retrieves an Azure AD OAuth2 token for Key Vault via client credentials.
func azureKVToken(ctx context.Context) (string, error) {
	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	if tenantID == "" || clientID == "" || clientSecret == "" {
		return "", fmt.Errorf("AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET must be set")
	}

	authority, err := azureAuthorityHost()
	if err != nil {
		return "", err
	}
	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", authority, tenantID)
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"https://vault.azure.net/.default"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := azureHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("azure token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("azure parse token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("empty access token from Azure AD")
	}
	return tok.AccessToken, nil
}

// azureAuthorityHost honours AZURE_AUTHORITY_HOST, the variable the Azure SDKs
// use for sovereign clouds and emulators. The client secret is posted to this
// host, so plain http is accepted only for loopback (local emulator).
func azureAuthorityHost() (string, error) {
	host := strings.TrimRight(os.Getenv("AZURE_AUTHORITY_HOST"), "/")
	if host == "" {
		return "https://login.microsoftonline.com", nil
	}
	u, err := url.Parse(host)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("AZURE_AUTHORITY_HOST %q is not a valid URL", host)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if h := u.Hostname(); h != "127.0.0.1" && h != "localhost" && h != "::1" {
			return "", fmt.Errorf("AZURE_AUTHORITY_HOST must be https unless it is loopback")
		}
	default:
		return "", fmt.Errorf("AZURE_AUTHORITY_HOST must be an https URL")
	}
	return host, nil
}

func azureSigningAlgorithm(pub crypto.PublicKey, opts crypto.SignerOpts) (string, error) {
	hash := opts.HashFunc()
	switch pub.(type) {
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			return "ES256", nil
		case crypto.SHA384:
			return "ES384", nil
		case crypto.SHA512:
			return "ES512", nil
		}
	case *rsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			return "RS256", nil
		case crypto.SHA384:
			return "RS384", nil
		case crypto.SHA512:
			return "RS512", nil
		}
	}
	return "", fmt.Errorf("unsupported key/hash combination for Azure KV signing")
}

// azureParseJWK reconstructs a crypto.PublicKey from Azure JWK fields.
func azureParseJWK(kty, n, e, x, y, crv string) (crypto.PublicKey, error) {
	// HSM-backed keys report kty as EC-HSM / RSA-HSM; the public parts are
	// identical.
	switch strings.TrimSuffix(kty, "-HSM") {
	case "EC":
		// Azure returns EC public keys as JWK; encode as PKIX and parse.
		xBytes, err := base64.RawURLEncoding.DecodeString(x)
		if err != nil {
			return nil, fmt.Errorf("azure kv: decode x: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(y)
		if err != nil {
			return nil, fmt.Errorf("azure kv: decode y: %w", err)
		}
		// Build minimal JWK bytes for x509 parsing via a DER round-trip is complex.
		// Use the raw coordinates with elliptic curve detection via crv.
		curveBytes := append([]byte{0x04}, xBytes...)
		curveBytes = append(curveBytes, yBytes...)

		curveName := crv
		switch crv {
		case "P-256":
			curveName = "P-256"
		case "P-384":
			curveName = "P-384"
		case "P-521":
			curveName = "P-521"
		}
		// Encode as SubjectPublicKeyInfo and parse.
		der := azureECPublicKeyDER(curveName, curveBytes)
		if der == nil {
			return nil, fmt.Errorf("azure kv: unsupported EC curve %s", crv)
		}
		return x509.ParsePKIXPublicKey(der)

	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(n)
		if err != nil {
			return nil, fmt.Errorf("azure kv: decode n: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(e)
		if err != nil {
			return nil, fmt.Errorf("azure kv: decode e: %w", err)
		}
		if len(nBytes) == 0 || len(eBytes) == 0 {
			return nil, fmt.Errorf("azure kv: RSA JWK missing n or e")
		}
		// Reconstruct rsa.PublicKey from JWK big-endian byte slices.
		nInt := new(big.Int).SetBytes(nBytes)
		eInt := new(big.Int).SetBytes(eBytes)
		if !eInt.IsInt64() {
			return nil, fmt.Errorf("azure kv: RSA exponent too large")
		}
		pub := &rsa.PublicKey{N: nInt, E: int(eInt.Int64())}
		return pub, nil

	default:
		return nil, fmt.Errorf("azure kv: unsupported key type %s", kty)
	}
}

// azureECPublicKeyDER returns a PKIX DER-encoded EC public key or nil for unsupported curves.
// This is a minimal encoding for P-256, P-384, P-521 using hardcoded OIDs.
func azureECPublicKeyDER(crv string, uncompressedPoint []byte) []byte {
	// OIDs: ecPublicKey = 1.2.840.10045.2.1
	// P-256 = 1.2.840.10045.3.1.7
	// P-384 = 1.3.132.0.34
	// P-521 = 1.3.132.0.35
	ecPublicKeyOID := []byte{0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01}
	var curveOID []byte
	switch crv {
	case "P-256":
		curveOID = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	case "P-384":
		curveOID = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}
	case "P-521":
		curveOID = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}
	default:
		return nil
	}

	algID := asn1Sequence(append(ecPublicKeyOID, curveOID...))
	bitStr := asn1BitString(uncompressedPoint)
	return asn1Sequence(append(algID, bitStr...))
}

func asn1Sequence(content []byte) []byte {
	return append(asn1Tag(0x30, content), content...)
}

func asn1Tag(tag byte, content []byte) []byte {
	l := len(content)
	if l < 128 {
		return []byte{tag, byte(l)}
	}
	if l < 256 {
		return []byte{tag, 0x81, byte(l)}
	}
	return []byte{tag, 0x82, byte(l >> 8), byte(l)}
}

func asn1BitString(data []byte) []byte {
	// BIT STRING: 0x03, length, 0x00 (no unused bits), data
	payload := append([]byte{0x00}, data...)
	return append(asn1Tag(0x03, payload), payload...)
}

// generateKeyAzure is the CloudKMSStore method that delegates to the package-level
// function and stores the result.
func (s *CloudKMSStore) generateKeyAzure(id string, algo Algorithm) (KeyMetadata, error) {
	pub, keyURI, err := generateKeyAzure(id, algo)
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
		config: CloudKMSConfig{Provider: "azure", KeyURI: keyURI},
	}
	return meta, nil
}

// generateKeyAzure (package-level) creates a new asymmetric signing key in Azure Key Vault.
//
// Required env vars: AZURE_KEYVAULT_URL, AZURE_TENANT_ID, AZURE_CLIENT_ID,
// AZURE_CLIENT_SECRET.
func generateKeyAzure(id string, algo Algorithm) (crypto.PublicKey, string, error) {
	vaultURL := strings.TrimRight(os.Getenv("AZURE_KEYVAULT_URL"), "/")
	if vaultURL == "" {
		return nil, "", fmt.Errorf("azure kv: AZURE_KEYVAULT_URL is required")
	}

	kty, crv, keyOps, err := azureKeyParams(algo)
	if err != nil {
		return nil, "", fmt.Errorf("azure kv: %w", err)
	}
	hsm, err := azureUseHSM()
	if err != nil {
		return nil, "", fmt.Errorf("azure kv: %w", err)
	}
	if hsm {
		kty += "-HSM"
	}
	tags, err := azureKeyTags(id)
	if err != nil {
		return nil, "", fmt.Errorf("azure kv: %w", err)
	}

	token, err := azureKVToken(context.Background())
	if err != nil {
		return nil, "", fmt.Errorf("azure kv: get token: %w", err)
	}

	type createBody struct {
		Kty     string            `json:"kty"`
		Crv     string            `json:"crv,omitempty"`
		KeyOps  []string          `json:"key_ops"`
		KeySize int               `json:"key_size,omitempty"`
		Tags    map[string]string `json:"tags,omitempty"`
	}
	cb := createBody{Kty: kty, Crv: crv, KeyOps: keyOps, Tags: tags}
	if strings.HasPrefix(kty, "RSA") {
		cb.KeySize = azureRSAKeySize(algo)
	}
	bodyBytes, _ := json.Marshal(cb)

	createURL := fmt.Sprintf("%s/keys/%s/create?api-version=%s", vaultURL, url.PathEscape(id), azureKVAPIVersion)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, createURL, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := azureHTTPClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("azure kv: create key: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		hint := ""
		if hsm {
			hint = " (HSM-backed keys need a Premium vault or Managed HSM; set " + envAzureKeyHSM + "=false to create software-protected keys)"
		}
		return nil, "", fmt.Errorf("azure kv: create key returned %d: %s%s", resp.StatusCode, azureTruncate(string(raw)), hint)
	}

	// The response contains the key bundle including the JWK public key.
	var keyBundle struct {
		Key struct {
			Kid string `json:"kid"` // full key URI with version
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			N   string `json:"n"`
			E   string `json:"e"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"key"`
	}
	if err := json.Unmarshal(raw, &keyBundle); err != nil {
		return nil, "", fmt.Errorf("azure kv: parse create response: %w", err)
	}

	pub, err := azureParseJWK(keyBundle.Key.Kty, keyBundle.Key.N, keyBundle.Key.E, keyBundle.Key.X, keyBundle.Key.Y, keyBundle.Key.Crv)
	if err != nil {
		return nil, "", fmt.Errorf("azure kv: parse public key after create: %w", err)
	}
	return pub, keyBundle.Key.Kid, nil
}

func azureKeyParams(algo Algorithm) (kty, crv string, keyOps []string, err error) {
	ops := []string{"sign", "verify"}
	switch algo {
	case ECDSAP256:
		return "EC", "P-256", ops, nil
	case ECDSAP384:
		return "EC", "P-384", ops, nil
	case RSA2048, RSA3072, RSA4096:
		return "RSA", "", ops, nil
	default:
		return "", "", nil, fmt.Errorf("%w: %s for Azure Key Vault", ErrUnsupportedAlgo, algo)
	}
}

var azureHTTPClient = &http.Client{Timeout: gcpHTTPClient.Timeout}

func azureTruncate(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// azureRSAKeySize returns the Key Vault key_size for an RSA algorithm, or 0
// for a non-RSA algorithm.
func azureRSAKeySize(algo Algorithm) int {
	switch algo {
	case RSA2048:
		return 2048
	case RSA3072:
		return 3072
	case RSA4096:
		return 4096
	default:
		return 0
	}
}
