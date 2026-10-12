// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keychain_test

// Live macOS acceptance for W18-05: drives agentinstall.KeychainInstaller
// over a real SSH session into a real Mac's System keychain, then proves
// placement (find-certificate) and trust (verify-cert) independently of the
// installer's own checks, and removes everything it added. Use a disposable
// Mac (e.g. a tart VM): it changes the System keychain and admin trust.
// Skipped unless KK_LIVE_KEYCHAIN=1, with:
//
//	KK_KEYCHAIN_SSH_HOST   host or host:port
//	KK_KEYCHAIN_SSH_USER   a user with passwordless sudo
//	KK_KEYCHAIN_SSH_KEY    path to the client private key (PEM/OpenSSH)
//	KK_KEYCHAIN_HOST_KEY   the host's public key, authorized_keys format

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // macOS identifies certificates by SHA-1 for delete-certificate -Z
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"kryptkeeper/internal/agentinstall"
)

func TestLive_KeychainInstallPlacesAndTrusts(t *testing.T) {
	if os.Getenv("KK_LIVE_KEYCHAIN") != "1" {
		t.Skip("set KK_LIVE_KEYCHAIN=1 and KK_KEYCHAIN_SSH_* to run against a disposable Mac")
	}
	host, user := os.Getenv("KK_KEYCHAIN_SSH_HOST"), os.Getenv("KK_KEYCHAIN_SSH_USER")
	keyBytes, err := os.ReadFile(os.Getenv("KK_KEYCHAIN_SSH_KEY"))
	if err != nil || host == "" || user == "" {
		t.Fatalf("KK_KEYCHAIN_SSH_HOST/USER/KEY must be set: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(os.Getenv("KK_KEYCHAIN_HOST_KEY")))
	if err != nil {
		t.Fatalf("KK_KEYCHAIN_HOST_KEY: %v", err)
	}
	port := 22
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if n, err := net.LookupPort("tcp", p); err == nil {
			port = n
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	exec, err := agentinstall.NewSSHExecutor(ctx, agentinstall.SSHTarget{
		Host: host, Port: port, User: user, Signer: signer,
		HostKeyCallback: ssh.FixedHostKey(hostKey), HostKeyAlgorithms: []string{hostKey.Type()},
	})
	if err != nil {
		t.Fatalf("ssh: %v", err)
	}
	// Registered before the removal cleanup so it runs after it: Cleanup is
	// LIFO, and a deferred Close would run before any Cleanup at all.
	t.Cleanup(func() { _ = exec.Close() })

	root, leaf, chainPEM, keyPEM := liveIdentity(t)
	rootSHA1 := sha1Hex(root.Raw)
	leafSHA1 := sha1Hex(leaf.Raw)
	// Deleting the certificates also drops the root's admin trust setting.
	// remove-trusted-cert is not used: on macOS 26 removing admin trust
	// headless is refused ("no user interaction was possible"), even though
	// adding it is allowed.
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), time.Minute)
		defer done()
		for _, sha := range []string{leafSHA1, rootSHA1} {
			cmd := "delete-certificate"
			if sha == leafSHA1 {
				cmd = "delete-identity"
			}
			if out, err := exec.Run(c, "sudo", "-n", "/usr/bin/security", cmd, "-Z", sha, "/Library/Keychains/System.keychain"); err != nil {
				t.Errorf("cleanup %s %s: %v %s", cmd, sha, err, out)
			}
		}
		if out, _ := exec.Run(c, "sh", "-c", "/usr/bin/security find-certificate -a -Z /Library/Keychains/System.keychain | grep -ci "+leafSHA1+"; true"); strings.TrimSpace(string(out)) != "0" {
			t.Errorf("leaf still in the System keychain after cleanup")
		}
	})

	res, err := agentinstall.NewKeychainInstaller(exec).Install(ctx, agentinstall.KeychainInstallRequest{CertPEM: chainPEM, KeyPEM: keyPEM})
	t.Logf("result: %+v", res)
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	// Independent checks, not the installer's own.
	out, err := exec.Run(ctx, "/usr/bin/security", "find-identity", "-v", "/Library/Keychains/System.keychain")
	if err != nil || !strings.Contains(strings.ToUpper(string(out)), leafSHA1) {
		t.Fatalf("identity (cert + key) not in the System keychain: %v\n%s", err, out)
	}
	if err := exec.WriteFile("/tmp/kk-live-leaf.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Run(ctx, "/usr/bin/security", "verify-cert", "-c", "/tmp/kk-live-leaf.pem"); err != nil {
		t.Fatalf("leaf does not verify against system trust: %v\n%s", err, out)
	}
	_, _ = exec.Run(ctx, "rm", "-f", "/tmp/kk-live-leaf.pem")
	// The staging directory must be gone.
	if out, _ := exec.Run(ctx, "sh", "-c", "ls -d /tmp/kk-keychain.* 2>/dev/null | wc -l"); strings.TrimSpace(string(out)) != "0" {
		t.Fatalf("staging directories left behind: %s", out)
	}
}

func liveIdentity(t *testing.T) (root, leaf *x509.Certificate, chainPEM, keyPEM []byte) {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "KK Live Keychain Test Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ = x509.ParseCertificate(rootDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano() + 1), Subject: pkix.Name{CommonName: "kk-live-keychain.example"},
		DNSNames: []string{"kk-live-keychain.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ = x509.ParseCertificate(leafDER)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	chainPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	return root, leaf, chainPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func sha1Hex(der []byte) string {
	sum := sha1.Sum(der) //nolint:gosec // lookup key, not a signature
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
