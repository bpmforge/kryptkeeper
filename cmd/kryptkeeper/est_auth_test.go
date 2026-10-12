// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/est"
)

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func anchorPEM(t *testing.T) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Device CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// EST enrollment is on only for credential types that can actually work:
// a valid users file, or client-CA anchors with the listener requesting
// client certificates (D-111). Everything else leaves it off.
func TestConfigureESTAuth(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	goodUsers := writeFile(t, "users.json", `[{"username":"enroller","bcrypt_hash":"`+string(hash)+`","allowed_dns_suffixes":[".devices.example.com"]}]`)
	badUsers := writeFile(t, "bad.json", `[{"username":"enroller","bcrypt_hash":"plaintext","allowed_dns_suffixes":[".x"]}]`)
	anchors := writeFile(t, "ca.pem", anchorPEM(t))

	for _, tc := range []struct {
		name               string
		users, ca, request string
		want               bool
	}{
		{"nothing", "", "", "", false},
		{"valid users", goodUsers, "", "", true},
		{"invalid users", badUsers, "", "", false},
		{"anchors without client-cert requests", "", anchors, "", false},
		{"anchors with client-cert requests", "", anchors, "true", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envESTUsersFile, tc.users)
			t.Setenv(envESTClientCAFile, tc.ca)
			t.Setenv("KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT", tc.request)
			srv := est.NewServer(nil, "")
			configureESTAuth(srv, ca.NewMemRevocationStore(), nil)
			if got := srv.EnrollmentConfigured(); got != tc.want {
				t.Fatalf("EnrollmentConfigured = %v, want %v", got, tc.want)
			}
		})
	}
}
