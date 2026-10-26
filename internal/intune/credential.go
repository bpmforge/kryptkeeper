// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package intune

// The Entra app's credential, read from the outbound credential store as an
// api_token payload (W20-23, D-327). Two shapes:
//
//	{"client_secret": "..."}                                   client secret
//	{"certificate_pem": "...", "private_key_pem": "..."}      certificate
//
// A certificate credential authenticates with a signed JWT client assertion,
// per https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials :
// header alg PS256, typ JWT, x5t#S256 = base64url(SHA-256(cert DER)); claims
// aud = the tenant's v2 token endpoint, iss = sub = client id, jti, nbf, exp
// (kept to 10 minutes); form fields client_assertion_type
// urn:ietf:params:oauth:client-assertion-type:jwt-bearer and client_assertion.
// Nothing here is logged, and no error text carries the payload.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"time"
)

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Credential proves the Entra app's identity to the token endpoint.
type Credential struct {
	secret string
	cert   *x509.Certificate
	key    *rsa.PrivateKey
}

// ErrCredential is wrapped by every credential-shape failure. Its text never
// carries any part of the payload.
var ErrCredential = errors.New("intune credential invalid")

// ParseCredential reads a credential payload. Exactly one of a client secret
// or a certificate with its RSA key must be present.
func ParseCredential(payload []byte) (*Credential, error) {
	var p struct {
		ClientSecret   string `json:"client_secret"`
		CertificatePEM string `json:"certificate_pem"`
		PrivateKeyPEM  string `json:"private_key_pem"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("%w: not a JSON object", ErrCredential)
	}
	hasCert := p.CertificatePEM != "" || p.PrivateKeyPEM != ""
	switch {
	case p.ClientSecret != "" && hasCert:
		return nil, fmt.Errorf("%w: give a client_secret or a certificate, not both", ErrCredential)
	case p.ClientSecret != "":
		return &Credential{secret: p.ClientSecret}, nil
	case !hasCert:
		return nil, fmt.Errorf("%w: needs client_secret, or certificate_pem and private_key_pem", ErrCredential)
	}
	cb, _ := pem.Decode([]byte(p.CertificatePEM))
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: certificate_pem is not a PEM certificate", ErrCredential)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: certificate_pem does not parse", ErrCredential)
	}
	kb, _ := pem.Decode([]byte(p.PrivateKeyPEM))
	if kb == nil {
		return nil, fmt.Errorf("%w: private_key_pem is not PEM", ErrCredential)
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(kb.Bytes); err == nil {
		key, _ = k.(*rsa.PrivateKey)
	} else if k, err := x509.ParsePKCS1PrivateKey(kb.Bytes); err == nil {
		key = k
	}
	if key == nil {
		return nil, fmt.Errorf("%w: private_key_pem must be an RSA key", ErrCredential)
	}
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("%w: the key does not match the certificate", ErrCredential)
	}
	return &Credential{cert: cert, key: key}, nil
}

// addTo puts the proof in the token request form.
func (c *Credential) addTo(form url.Values, clientID, tokenURL string, now time.Time) error {
	if c.cert == nil {
		form.Set("client_secret", c.secret)
		return nil
	}
	assertion, err := c.assertion(clientID, tokenURL, now)
	if err != nil {
		return err
	}
	form.Set("client_assertion_type", clientAssertionType)
	form.Set("client_assertion", assertion)
	return nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (c *Credential) assertion(clientID, tokenURL string, now time.Time) (string, error) {
	thumb := sha256.Sum256(c.cert.Raw)
	header, err := json.Marshal(map[string]string{"alg": "PS256", "typ": "JWT", "x5t#S256": b64(thumb[:])})
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"aud": tokenURL, "iss": clientID, "sub": clientID, "jti": b64(jti),
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		return "", err
	}
	signing := b64(header) + "." + b64(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPSS(rand.Reader, c.key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", fmt.Errorf("sign client assertion: %w", err)
	}
	return signing + "." + b64(sig), nil
}
