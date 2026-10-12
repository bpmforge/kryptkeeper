// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery_test

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

	"kryptkeeper/internal/agentdiscovery"
)

func TestFindCertPathsInConfigs_Nginx(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	_ = os.WriteFile(conf, []byte(`
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;
    ssl_certificate /etc/ssl/certs/other.pem;
}
`), 0o644)

	paths := agentdiscovery.FindCertPathsInConfigs([]string{dir})
	if len(paths) != 2 {
		t.Fatalf("expected 2 cert paths, got %d: %v", len(paths), paths)
	}
	found := map[string]bool{}
	for _, p := range paths {
		found[p] = true
	}
	if !found["/etc/ssl/certs/example.com.crt"] {
		t.Error("expected /etc/ssl/certs/example.com.crt")
	}
	if !found["/etc/ssl/certs/other.pem"] {
		t.Error("expected /etc/ssl/certs/other.pem")
	}
}

func TestFindCertPathsInConfigs_Apache(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "site.conf")
	_ = os.WriteFile(conf, []byte(`
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLCertificateFile /etc/apache2/ssl/example.com.crt
    SSLCertificateKeyFile /etc/apache2/ssl/example.com.key
    SSLCertificateFile /etc/apache2/ssl/chain.pem
</VirtualHost>
`), 0o644)

	paths := agentdiscovery.FindCertPathsInConfigs([]string{dir})
	if len(paths) != 2 {
		t.Fatalf("expected 2 cert paths, got %d: %v", len(paths), paths)
	}
}

func TestFindCertPathsInConfigs_SkipsMissingRoots(t *testing.T) {
	paths := agentdiscovery.FindCertPathsInConfigs([]string{"/nonexistent/nginx-config"})
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for missing root, got %d", len(paths))
	}
}

func TestFindCertPathsInConfigs_SkipsRelativePaths(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	// Relative paths should not be included (can't resolve without context).
	_ = os.WriteFile(conf, []byte(`ssl_certificate ./certs/local.crt;`), 0o644)

	paths := agentdiscovery.FindCertPathsInConfigs([]string{dir})
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for relative cert path, got %d", len(paths))
	}
}

func TestFindCertPathsInConfigs_DeduplicatesSamePath(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	certPath := "/etc/ssl/shared.crt"
	_ = os.WriteFile(filepath.Join(dir1, "a.conf"), []byte(`ssl_certificate `+certPath+`;`), 0o644)
	_ = os.WriteFile(filepath.Join(dir2, "b.conf"), []byte(`ssl_certificate `+certPath+`;`), 0o644)

	paths := agentdiscovery.FindCertPathsInConfigs([]string{dir1, dir2})
	if len(paths) != 1 {
		t.Errorf("expected 1 unique path, got %d: %v", len(paths), paths)
	}
}

func TestWalkConfigCerts_ParsesFoundCerts(t *testing.T) {
	// Create a temp dir with a cert file and a nginx config pointing to it.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "example.crt")
	writeCertPEMToPath(t, certPath, "CN=config-test.example.com", time.Now().Add(90*24*time.Hour))

	conf := filepath.Join(dir, "nginx.conf")
	_ = os.WriteFile(conf, []byte(`ssl_certificate `+certPath+`;`), 0o644)

	certs, err := agentdiscovery.WalkConfigCerts([]string{dir})
	if err != nil {
		t.Fatalf("WalkConfigCerts: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].Source != certPath {
		t.Errorf("expected source %q, got %q", certPath, certs[0].Source)
	}
}

func TestWalkConfigCerts_MissingCertFileSkipped(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	_ = os.WriteFile(conf, []byte(`ssl_certificate /nonexistent/cert.crt;`), 0o644)

	certs, err := agentdiscovery.WalkConfigCerts([]string{dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs when cert file missing, got %d", len(certs))
	}
}

// writeCertPEMToPath writes a self-signed cert to a specific path.
func writeCertPEMToPath(t *testing.T, path, cn string, notAfter time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	f, _ := os.Create(path)
	defer f.Close()
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestWalkEndpoints_Nginx(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "site.conf")
	_ = os.WriteFile(conf, []byte(`
server {
    listen 443 ssl;
    server_name shop.example.com www.example.com;
    ssl_certificate /etc/nginx/ssl/shop.crt;
    ssl_certificate_key /etc/nginx/ssl/shop.key;

    location / {
        proxy_pass http://backend;
    }
}

server {
    listen 8443 ssl;
    server_name api.example.com;
    ssl_certificate /etc/nginx/ssl/api.crt;
    ssl_certificate_key /etc/nginx/ssl/api.key;
}
`), 0o644)

	eps := agentdiscovery.WalkEndpoints([]string{dir})
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %d: %+v", len(eps), eps)
	}

	byCert := map[string]int{}
	for i, e := range eps {
		byCert[e.CertPath] = i
	}
	shop := eps[byCert["/etc/nginx/ssl/shop.crt"]]
	if shop.KeyPath != "/etc/nginx/ssl/shop.key" {
		t.Errorf("shop key path: got %q", shop.KeyPath)
	}
	if shop.ServerName != "shop.example.com" {
		t.Errorf("shop server_name: got %q (want first token)", shop.ServerName)
	}
	if shop.ListenPort != 443 {
		t.Errorf("shop port: got %d", shop.ListenPort)
	}
	if string(shop.ServerType) != "nginx" {
		t.Errorf("shop server type: got %q", shop.ServerType)
	}
	if shop.VerifyHostPort() != "shop.example.com:443" {
		t.Errorf("shop verify host:port: got %q", shop.VerifyHostPort())
	}

	api := eps[byCert["/etc/nginx/ssl/api.crt"]]
	if api.ListenPort != 8443 || api.KeyPath != "/etc/nginx/ssl/api.key" {
		t.Errorf("api endpoint wrong: %+v", api)
	}
}

func TestWalkEndpoints_Apache(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "vhost.conf")
	_ = os.WriteFile(conf, []byte(`
<VirtualHost *:443>
    ServerName secure.example.com
    SSLCertificateFile /etc/apache2/ssl/secure.crt
    SSLCertificateKeyFile /etc/apache2/ssl/secure.key
</VirtualHost>
`), 0o644)

	eps := agentdiscovery.WalkEndpoints([]string{dir})
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d: %+v", len(eps), eps)
	}
	e := eps[0]
	if string(e.ServerType) != "apache" {
		t.Errorf("server type: got %q", e.ServerType)
	}
	if e.CertPath != "/etc/apache2/ssl/secure.crt" || e.KeyPath != "/etc/apache2/ssl/secure.key" {
		t.Errorf("apache cert/key wrong: %+v", e)
	}
	if e.ServerName != "secure.example.com" || e.ListenPort != 443 {
		t.Errorf("apache name/port wrong: %+v", e)
	}
}

func TestWalkEndpoints_NoKeyStillEmits(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "nokey.conf")
	_ = os.WriteFile(conf, []byte(`
server {
    listen 443 ssl;
    server_name plain.example.com;
    ssl_certificate /etc/nginx/ssl/plain.crt;
}
`), 0o644)

	eps := agentdiscovery.WalkEndpoints([]string{dir})
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	if eps[0].KeyPath != "" {
		t.Errorf("expected empty key path, got %q", eps[0].KeyPath)
	}
	if eps[0].CertPath != "/etc/nginx/ssl/plain.crt" {
		t.Errorf("cert path: got %q", eps[0].CertPath)
	}
}
