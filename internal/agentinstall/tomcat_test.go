// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"
)

const tomcatKS = "/opt/tomcat/conf/keystore.p12"
const tomcatPW = "S3cr3t-pw-xyz"

// tomcatMaterial returns a leaf+CA chain PEM, the leaf key PEM and leaf DER.
func tomcatMaterial(t *testing.T) (chainPEM, keyPEM, leafDER []byte) {
	t.Helper()
	mk := func(cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: isCA, BasicConstraintsValid: true,
		}
		signer, signerKey := tpl, k
		if parent != nil {
			signer, signerKey = parent, parentKey
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &k.PublicKey, signerKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, k, der
	}
	ca, caKey, caDER := mk("test-ca", true, nil, nil)
	_, leafKey, lDER := mk("tomcat.example.com", false, ca, caKey)
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: lDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	return chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), lDER
}

func tomcatReq(t *testing.T) (InstallRequest, []byte) {
	chain, key, leaf := tomcatMaterial(t)
	return InstallRequest{
		ServerType: "tomcat", CertPath: tomcatKS, CertPEM: chain, KeyPEM: key,
		KeystorePassword: tomcatPW,
	}, leaf
}

func TestTomcatInstallPKCS12HappyPath(t *testing.T) {
	exec := newFakeExecutor()
	req, leaf := tomcatReq(t)
	res, err := New(exec).Install(context.Background(), req)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Outcome != OutcomeInstalled || !res.Installed || !res.Reloaded {
		t.Fatalf("unexpected result: %+v", res)
	}
	_, got, ca, err := pkcs12.DecodeChain(exec.files[tomcatKS], tomcatPW)
	if err != nil {
		t.Fatalf("decode keystore: %v", err)
	}
	if !bytes.Equal(got.Raw, leaf) || len(ca) != 1 {
		t.Fatalf("keystore must hold leaf + 1 CA, got ca=%d", len(ca))
	}
	want := []string{"/opt/tomcat/bin/catalina.sh configtest", "systemctl restart tomcat"}
	if strings.Join(exec.ran, "|") != strings.Join(want, "|") {
		t.Fatalf("ran %v, want %v", exec.ran, want)
	}
}

func TestTomcatInstallJKSAndLegacyFormats(t *testing.T) {
	req, leaf := tomcatReq(t)
	req.KeystoreFormat = "jks"
	req.KeystoreAlias = "srv"
	exec := newFakeExecutor()
	if _, err := New(exec).Install(context.Background(), req); err != nil {
		t.Fatalf("jks install: %v", err)
	}
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(exec.files[tomcatKS]), []byte(tomcatPW)); err != nil {
		t.Fatalf("load jks: %v", err)
	}
	chain, err := ks.GetPrivateKeyEntryCertificateChain("srv")
	if err != nil || len(chain) != 2 || !bytes.Equal(chain[0].Content, leaf) {
		t.Fatalf("jks chain wrong: %v len=%d", err, len(chain))
	}
	if _, err := ks.GetPrivateKeyEntry("srv", []byte(tomcatPW)); err != nil {
		t.Fatalf("jks key entry: %v", err)
	}

	req.KeystoreFormat = "pkcs12-legacy"
	exec = newFakeExecutor()
	if _, err := New(exec).Install(context.Background(), req); err != nil {
		t.Fatalf("legacy install: %v", err)
	}
	if _, _, _, err := pkcs12.DecodeChain(exec.files[tomcatKS], tomcatPW); err != nil {
		t.Fatalf("legacy decode: %v", err)
	}
}

func TestTomcatConfigTestFailureRollsBack(t *testing.T) {
	exec := newFakeExecutor()
	old := []byte("OLD-KEYSTORE")
	exec.files[tomcatKS] = old
	exec.failCmd = "/opt/tomcat/bin/catalina.sh"
	req, _ := tomcatReq(t)
	res, err := New(exec).Install(context.Background(), req)
	if err == nil || !res.RolledBack || res.Outcome != OutcomeConfigTestFailed {
		t.Fatalf("want config_test_failed rollback, got %+v err=%v", res, err)
	}
	if !bytes.Equal(exec.files[tomcatKS], old) {
		t.Fatal("old keystore must be restored byte-for-byte")
	}
	for _, c := range exec.ran {
		if strings.Contains(c, "restart") {
			t.Fatalf("no restart after failed config test: %v", exec.ran)
		}
	}
}

func TestTomcatReloadFailureRollsBackAndRestarts(t *testing.T) {
	exec := newFakeExecutor()
	old := []byte("OLD-KEYSTORE")
	exec.files[tomcatKS] = old
	exec.failCmd = "systemctl restart"
	req, _ := tomcatReq(t)
	res, err := New(exec).Install(context.Background(), req)
	if err == nil || !res.RolledBack || res.Outcome != OutcomeReloadFailed {
		t.Fatalf("want reload_failed rollback, got %+v err=%v", res, err)
	}
	if !bytes.Equal(exec.files[tomcatKS], old) {
		t.Fatal("old keystore must be restored")
	}
	restarts := 0
	for _, c := range exec.ran {
		if c == "systemctl restart tomcat" {
			restarts++
		}
	}
	if restarts != 2 {
		t.Fatalf("expected restart + best-effort restart, ran %v", exec.ran)
	}
}

func TestTomcatVerifyMismatchRollsBack(t *testing.T) {
	exec := newFakeExecutor()
	old := []byte("OLD-KEYSTORE")
	exec.files[tomcatKS] = old
	req, _ := tomcatReq(t)
	req.VerifyHostPort, req.ExpectedFingerprint = "tomcat.example.com:8443", "aa11"
	in := New(exec).WithVerifier(func(context.Context, string) (string, error) { return "bb22", nil })
	res, err := in.Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeVerifyFailed || !res.RolledBack {
		t.Fatalf("want verify_failed rollback, got %+v err=%v", res, err)
	}
	if !bytes.Equal(exec.files[tomcatKS], old) {
		t.Fatal("old keystore must be restored")
	}
}

func TestTomcatVerifySuccess(t *testing.T) {
	exec := newFakeExecutor()
	req, _ := tomcatReq(t)
	req.VerifyHostPort, req.ExpectedFingerprint = "tomcat.example.com:8443", "aa11"
	in := New(exec).WithVerifier(func(context.Context, string) (string, error) { return "AA:11", nil })
	res, err := in.Install(context.Background(), req)
	if err != nil || res.Outcome != OutcomeInstalledVerified || !res.Verified {
		t.Fatalf("got %+v err=%v", res, err)
	}
}

func TestTomcatPasswordNeverLeaks(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	var seen []string
	collect := func(res InstallResult, err error) {
		seen = append(seen, res.Detail, res.Outcome, res.ServedFingerprint)
		if err != nil {
			seen = append(seen, err.Error())
		}
	}
	type scenario struct {
		name string
		fail string
		mut  func(*InstallRequest)
	}
	scenarios := []scenario{
		{"happy", "", nil},
		{"configtest", "/opt/tomcat/bin/catalina.sh", nil},
		{"restart", "systemctl restart", nil},
		{"jks", "", func(r *InstallRequest) { r.KeystoreFormat = "jks" }},
		{"badkey", "", func(r *InstallRequest) { r.KeyPEM = []byte("garbage") }},
		{"badformat", "", func(r *InstallRequest) { r.KeystoreFormat = "pfx" }},
		{"binary", "", func(r *InstallRequest) { r.ReloadMethod = "binary" }},
		{"verify", "", func(r *InstallRequest) { r.VerifyHostPort, r.ExpectedFingerprint = "h:1", "aa" }},
	}
	var ran []string
	for _, sc := range scenarios {
		exec := newFakeExecutor()
		exec.failCmd = sc.fail
		req, _ := tomcatReq(t)
		if sc.mut != nil {
			sc.mut(&req)
		}
		in := New(exec).WithVerifier(func(context.Context, string) (string, error) { return "zz", errors.New("dial failed") })
		res, err := in.Install(context.Background(), req)
		collect(res, err)
		ran = append(ran, exec.ran...)
	}
	// Short-password refusal path too.
	short, _ := tomcatReq(t)
	short.KeystorePassword = "abc"
	res, err := New(newFakeExecutor()).Install(context.Background(), short)
	collect(res, err)

	blob := strings.Join(append(seen, ran...), "\n") + logs.String()
	if strings.Contains(blob, tomcatPW) || strings.Contains(blob, "abc\n") {
		t.Fatal("keystore password leaked into commands, results, errors or logs")
	}
}

func TestTomcatRefusals(t *testing.T) {
	cases := map[string]func(*InstallRequest){
		"empty cert path": func(r *InstallRequest) { r.CertPath = "" },
		"empty cert pem":  func(r *InstallRequest) { r.CertPEM = nil },
		"empty key pem":   func(r *InstallRequest) { r.KeyPEM = nil },
		"empty password":  func(r *InstallRequest) { r.KeystorePassword = "" },
		"bad format":      func(r *InstallRequest) { r.KeystoreFormat = "p12x" },
		"binary reload":   func(r *InstallRequest) { r.ReloadMethod = "binary" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			exec := newFakeExecutor()
			req, _ := tomcatReq(t)
			mut(&req)
			if _, err := New(exec).Install(context.Background(), req); err == nil {
				t.Fatal("expected refusal")
			}
			if len(exec.files) != 0 || len(exec.ran) != 0 {
				t.Fatalf("refusal must not touch the target: files=%d ran=%v", len(exec.files), exec.ran)
			}
		})
	}
}

func TestTomcatBuildFailureWritesNothing(t *testing.T) {
	exec := newFakeExecutor()
	req, _ := tomcatReq(t)
	req.KeyPEM = []byte("not pem")
	res, err := New(exec).Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeWriteFailed || len(exec.files) != 0 {
		t.Fatalf("got %+v err=%v files=%d", res, err, len(exec.files))
	}
}
