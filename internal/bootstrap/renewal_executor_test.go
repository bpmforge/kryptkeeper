// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"software.sslmate.com/src/go-pkcs12"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"encoding/base64"
	"io"
	"kryptkeeper/internal/agentinstall"
	"net/http"
	"net/http/httptest"
)

// --- fakes -----------------------------------------------------------------

// renewalFakeExecutor is an in-memory agentinstall.Executor: a virtual
// filesystem plus scripted command results (same shape as the one in
// internal/agentinstall/installer_test.go).
type renewalFakeExecutor struct {
	files       map[string][]byte
	failCommand string // command name that should fail, e.g. "nginx"
}

func (f *renewalFakeExecutor) Exists(path string) bool { _, ok := f.files[path]; return ok }
func (f *renewalFakeExecutor) ReadFile(path string) ([]byte, error) {
	b, ok := f.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}
func (f *renewalFakeExecutor) WriteFile(path string, content []byte, _ os.FileMode) error {
	f.files[path] = append([]byte(nil), content...)
	return nil
}
func (f *renewalFakeExecutor) Run(_ context.Context, name string, _ ...string) ([]byte, error) {
	if f.failCommand != "" && name == f.failCommand {
		return []byte("scripted failure"), errors.New("scripted failure")
	}
	return []byte("ok"), nil
}

type renewalFakeCredStore struct {
	meta    OutboundCredentialMeta
	payload []byte
	getErr  error
}

func (s *renewalFakeCredStore) EnsureSchema(context.Context) error { return nil }
func (s *renewalFakeCredStore) Create(context.Context, string, string, string, string, []byte) (OutboundCredentialMeta, error) {
	return OutboundCredentialMeta{}, errors.New("not implemented")
}
func (s *renewalFakeCredStore) Get(_ context.Context, id string) (OutboundCredentialMeta, error) {
	if s.getErr != nil {
		return OutboundCredentialMeta{}, s.getErr
	}
	return s.meta, nil
}
func (s *renewalFakeCredStore) List(context.Context) ([]OutboundCredentialMeta, error) {
	return nil, nil
}
func (s *renewalFakeCredStore) Delete(context.Context, string) error { return nil }
func (s *renewalFakeCredStore) Resolve(_ context.Context, id string) ([]byte, error) {
	return append([]byte(nil), s.payload...), nil
}

// testSSHCredentialJSON builds a valid ssh_key payload: a parseable client
// key (PKCS#8 PEM, which x/crypto/ssh accepts) and a pinned host key.
func testSSHCredentialJSON(t *testing.T) []byte {
	t.Helper()
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	hostPub, err := ssh.NewPublicKey(&hostKey.PublicKey)
	if err != nil {
		t.Fatalf("host pub: %v", err)
	}
	payload, err := json.Marshal(sshCredentialPayload{
		PrivateKeyPEM: string(keyPEM),
		HostPublicKey: string(ssh.MarshalAuthorizedKey(hostPub)),
		User:          "deploy",
		Port:          2222,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return payload
}

func newRenewalTestEngine(t *testing.T, certs CertificateProvider, fake *renewalFakeExecutor, credPayload []byte) *RenewalExecutor {
	t.Helper()
	e := NewRenewalExecutor(certs, &renewalFakeCredStore{
		meta:    OutboundCredentialMeta{ID: "cred-1", CredentialType: CredentialTypeSSHKey},
		payload: credPayload,
	})
	e.dial = func(_ context.Context, cfg agentinstall.SSHTarget) (agentinstall.Executor, func() error, error) {
		if cfg.HostKeyCallback == nil {
			t.Fatal("dial must carry a pinned host key callback")
		}
		if cfg.User != "deploy" || cfg.Port != 2222 {
			t.Fatalf("dial config not taken from credential payload: %+v", cfg)
		}
		return fake, func() error { return nil }, nil
	}
	// The fake "server" serves whatever the installer wrote to the cert path,
	// which is exactly what a reloaded nginx would do.
	e.verifier = func(_ context.Context, _ string) (string, error) {
		certPEM, ok := fake.files["/etc/nginx/tls/renewed.crt"]
		if !ok {
			return "", errors.New("nothing installed")
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return "", errors.New("installed cert unparseable")
		}
		return agentinstall.FingerprintSHA256(block.Bytes), nil
	}
	return e
}

func sshTestTarget() ManagedTarget {
	return ManagedTarget{
		ID: "tgt-1", Name: "web-1", Host: "renew-exec.example.com",
		DiscoveryMode: "none", InstallMode: "ssh", RenewalMethod: "manual",
		CredentialRef: "cred-1",
	}
}

func sshTestProfile() RenewalInstallProfile {
	return RenewalInstallProfile{
		ServerType: "nginx",
		CertPath:   "/etc/nginx/tls/renewed.crt",
		KeyPath:    "/etc/nginx/tls/renewed.key",
	}
}

// --- tests -----------------------------------------------------------------

// The full hub-side loop against the PRODUCTION issuance path (S-66 lesson:
// never a hand-built predecessor): issue → execute-renewal → the successor
// exists with the same CN, and the fake target holds the new cert + a fresh
// key, verified.
func TestRenewalExecutorEndToEnd(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	caID := getFirstCAID(t, engine)
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		CSRPEM:     generateTestCSRPEM(t, "renew-exec.example.com", "renew-exec.example.com", "alt.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-renew-exec",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}
	predecessorFP := issued.CertificateItem.FingerprintSHA256

	fake := &renewalFakeExecutor{files: map[string][]byte{}}
	exec := newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t))

	result, err := exec.ExecuteRenewal(ctx, predecessorFP, sshTestTarget(), sshTestProfile())
	if err != nil {
		t.Fatalf("ExecuteRenewal: %v", err)
	}
	if !result.Renewed || result.NewFingerprint == "" || result.NewFingerprint == predecessorFP {
		t.Fatalf("expected a renewed successor, got %+v", result)
	}
	if result.InstallOutcome != agentinstall.OutcomeInstalledVerified || !result.Verified {
		t.Fatalf("expected installed_verified, got %+v", result)
	}

	// The successor is a real inventory record with the CN preserved.
	successor, ok, err := provider.GetCertificate(ctx, result.NewFingerprint)
	if err != nil || !ok {
		t.Fatalf("successor not in inventory: ok=%v err=%v", ok, err)
	}
	if successor.CommonName != "renew-exec.example.com" {
		t.Fatalf("successor CN = %q", successor.CommonName)
	}

	// The target received the new cert and a parseable fresh private key.
	certPEM := fake.files["/etc/nginx/tls/renewed.crt"]
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no cert installed on target")
	}
	if got := agentinstall.FingerprintSHA256(block.Bytes); got != result.NewFingerprint {
		t.Fatalf("installed cert fp %s != new fp %s", got, result.NewFingerprint)
	}
	keyBlock, _ := pem.Decode(fake.files["/etc/nginx/tls/renewed.key"])
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatal("no PKCS#8 key installed on target")
	}
	if _, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err != nil {
		t.Fatalf("installed key unparseable: %v", err)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse installed leaf: %v", err)
	}
	if len(leaf.DNSNames) == 0 || leaf.DNSNames[0] != "renew-exec.example.com" {
		t.Fatalf("successor lost its SANs: %v", leaf.DNSNames)
	}
}

// A failed install must not hide a successful renewal: the successor exists,
// so the result reports both facts instead of returning one opaque error.
func TestRenewalExecutorInstallFailureIsVisiblePartialState(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "partial.example.com", "partial.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-partial",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}

	fake := &renewalFakeExecutor{files: map[string][]byte{}, failCommand: "nginx"} // config test fails
	exec := newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t))

	result, err := exec.ExecuteRenewal(ctx, issued.CertificateItem.FingerprintSHA256, sshTestTarget(), sshTestProfile())
	if err != nil {
		t.Fatalf("partial state must not be an error: %v", err)
	}
	if !result.Renewed || result.NewFingerprint == "" {
		t.Fatalf("renewal should have succeeded before the install failed: %+v", result)
	}
	if result.InstallOutcome != agentinstall.OutcomeConfigTestFailed {
		t.Fatalf("expected config_test_failed, got %+v", result)
	}
}

func TestRenewalExecutorRejectsNonSSHTargetBeforeRenewing(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, _ := newIntegrationCAProvider(t, db)
	exec := newRenewalTestEngine(t, provider, &renewalFakeExecutor{files: map[string][]byte{}}, testSSHCredentialJSON(t))

	target := sshTestTarget()
	target.InstallMode = "agent"
	_, err := exec.ExecuteRenewal(context.Background(), "irrelevant", target, sshTestProfile())
	if !errors.Is(err, errRenewalTargetNotSSH) {
		t.Fatalf("expected errRenewalTargetNotSSH, got %v", err)
	}
}

// An unreachable/unresolvable credential must fail BEFORE the renewal burns
// a serial and leaves a successor nothing can install.
func TestRenewalExecutorBadCredentialFailsBeforeRenewal(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "cred-fail.example.com", "cred-fail.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-cred-fail",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}
	fp := issued.CertificateItem.FingerprintSHA256

	exec := newRenewalTestEngine(t, provider, &renewalFakeExecutor{files: map[string][]byte{}}, []byte("not-json: a raw key blob"))
	_, err = exec.ExecuteRenewal(ctx, fp, sshTestTarget(), sshTestProfile())
	if !errors.Is(err, errRenewalBadCredential) {
		t.Fatalf("expected errRenewalBadCredential, got %v", err)
	}

	// The predecessor must be untouched — no successor was minted.
	after, _, err := provider.GetCertificate(ctx, fp)
	if err != nil {
		t.Fatalf("get predecessor: %v", err)
	}
	if after.SuccessorFP != nil {
		t.Fatalf("credential failure must precede renewal, but a successor exists: %v", *after.SuccessorFP)
	}
}

func TestRenewalExecutorRequiresInstallProfile(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, _ := newIntegrationCAProvider(t, db)
	exec := newRenewalTestEngine(t, provider, &renewalFakeExecutor{files: map[string][]byte{}}, testSSHCredentialJSON(t))

	_, err := exec.ExecuteRenewal(context.Background(), "irrelevant", sshTestTarget(), RenewalInstallProfile{ServerType: "nginx"})
	if !errors.Is(err, errRenewalInstallProfile) {
		t.Fatalf("expected errRenewalInstallProfile, got %v", err)
	}
}

func TestGenerateRenewalKeyAndCSRSplitsSANs(t *testing.T) {
	_, keyPEM, csrPEM, err := generateRenewalKeyAndCSR(CertificateItem{
		CommonName:      "mixed.example.com",
		SubjectAltNames: []string{"mixed.example.com", "10.0.0.5", "alt.example.com"},
	}, renewalKeyECDSAP256)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.Contains(string(keyPEM), "PRIVATE KEY") {
		t.Fatal("key not PEM-encoded")
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	if csr.Subject.CommonName != "mixed.example.com" {
		t.Fatalf("CN = %q", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 2 || len(csr.IPAddresses) != 1 || csr.IPAddresses[0].String() != "10.0.0.5" {
		t.Fatalf("SAN split wrong: dns=%v ips=%v", csr.DNSNames, csr.IPAddresses)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("csr self-signature invalid: %v", err)
	}
}

// TestGenerateRenewalKeyAndCSRKeepsIISHostIPSAN is W18-14: the record
// stored for the live IIS host at 192.0.2.10 carries both its DNS and
// IP SAN once ca.SubjectAltNameStrings (called from
// certificate_ca_provider.go) stops dropping the IP -- this proves the
// renewal CSR built from that record carries both forward too, closing the
// loop that produced the 2026-09-10 live defect (renewed cert missing the
// IP SAN IIS was addressed by).
func TestGenerateRenewalKeyAndCSRKeepsIISHostIPSAN(t *testing.T) {
	_, _, csrPEM, err := generateRenewalKeyAndCSR(CertificateItem{
		CommonName:      "iis-lab.kk.local",
		SubjectAltNames: []string{"iis-lab.kk.local", "192.0.2.10"},
	}, renewalKeyECDSAP256)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "iis-lab.kk.local" {
		t.Fatalf("DNSNames = %v, want [iis-lab.kk.local]", csr.DNSNames)
	}
	if len(csr.IPAddresses) != 1 || csr.IPAddresses[0].String() != "192.0.2.10" {
		t.Fatalf("IPAddresses = %v, want [192.0.2.10]", csr.IPAddresses)
	}
}

// TestSplitSubjectAltNames is the table test for the classifier that puts
// each stored SAN string back into the x509.CertificateRequest field it
// came from. An invalid IP-looking string (too many octets) must fall
// through to DNS -- net.ParseIP correctly rejects it, and nothing else about
// it looks like a URI or an email address.
func TestSplitSubjectAltNames(t *testing.T) {
	tests := []struct {
		name       string
		sans       []string
		wantDNS    []string
		wantIPs    []string // net.IP.String() form
		wantURIs   []string
		wantEmails []string
	}{
		{
			name:    "dns only",
			sans:    []string{"iis-lab.kk.local"},
			wantDNS: []string{"iis-lab.kk.local"},
		},
		{
			name:    "ip only",
			sans:    []string{"192.0.2.10"},
			wantIPs: []string{"192.0.2.10"},
		},
		{
			name:     "uri only",
			sans:     []string{"spiffe://kk.local/ns/default/sa/iis-lab"},
			wantURIs: []string{"spiffe://kk.local/ns/default/sa/iis-lab"},
		},
		{
			name:       "email only",
			sans:       []string{"ops@kk.local"},
			wantEmails: []string{"ops@kk.local"},
		},
		{
			name:    "invalid ip-looking string falls to dns",
			sans:    []string{"999.999.999.999"},
			wantDNS: []string{"999.999.999.999"},
		},
		{
			name:       "all four kinds together",
			sans:       []string{"iis-lab.kk.local", "192.0.2.10", "spiffe://kk.local/ns/default/sa/iis-lab", "ops@kk.local"},
			wantDNS:    []string{"iis-lab.kk.local"},
			wantIPs:    []string{"192.0.2.10"},
			wantURIs:   []string{"spiffe://kk.local/ns/default/sa/iis-lab"},
			wantEmails: []string{"ops@kk.local"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dns, ips, uris, emails := splitSubjectAltNames(tc.sans)
			if !equalStrings(dns, tc.wantDNS) {
				t.Errorf("dns = %v, want %v", dns, tc.wantDNS)
			}
			gotIPs := make([]string, len(ips))
			for i, ip := range ips {
				gotIPs[i] = ip.String()
			}
			if !equalStrings(gotIPs, tc.wantIPs) {
				t.Errorf("ips = %v, want %v", gotIPs, tc.wantIPs)
			}
			gotURIs := make([]string, len(uris))
			for i, u := range uris {
				gotURIs[i] = u.String()
			}
			if !equalStrings(gotURIs, tc.wantURIs) {
				t.Errorf("uris = %v, want %v", gotURIs, tc.wantURIs)
			}
			if !equalStrings(emails, tc.wantEmails) {
				t.Errorf("emails = %v, want %v", emails, tc.wantEmails)
			}
		})
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestGenerateRenewalKeyAndCSRKeepsURIAndEmailSANs proves a SPIFFE URI and
// an email SAN round-trip into the renewal CSR's URIs/EmailAddresses -- not
// DNSNames, which would silently change the renewed certificate's identity.
func TestGenerateRenewalKeyAndCSRKeepsURIAndEmailSANs(t *testing.T) {
	const spiffeURI = "spiffe://kk.local/ns/default/sa/iis-lab"
	const email = "ops@kk.local"
	_, _, csrPEM, err := generateRenewalKeyAndCSR(CertificateItem{
		CommonName:      "iis-lab.kk.local",
		SubjectAltNames: []string{"iis-lab.kk.local", spiffeURI, email},
	}, renewalKeyECDSAP256)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "iis-lab.kk.local" {
		t.Fatalf("DNSNames = %v, want only [iis-lab.kk.local] (no URI/email leaked in)", csr.DNSNames)
	}
	if len(csr.URIs) != 1 || csr.URIs[0].String() != spiffeURI {
		t.Fatalf("URIs = %v, want [%s]", csr.URIs, spiffeURI)
	}
	if len(csr.EmailAddresses) != 1 || csr.EmailAddresses[0] != email {
		t.Fatalf("EmailAddresses = %v, want [%s]", csr.EmailAddresses, email)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("csr self-signature invalid: %v", err)
	}
}

func TestLeafFingerprintTakesFirstCertificateBlock(t *testing.T) {
	if _, err := leafFingerprint([]byte("garbage")); err == nil {
		t.Fatal("expected error on non-PEM input")
	}
	// Build a two-cert bundle and confirm the FIRST block's fingerprint wins.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mk := func(cn string, serial int64) []byte {
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if err != nil {
			t.Fatalf("mk cert: %v", err)
		}
		return der
	}
	leafDER, issuerDER := mk("leaf", 1), mk("issuer", 2)
	bundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})...)
	got, err := leafFingerprint(bundle)
	if err != nil {
		t.Fatalf("leafFingerprint: %v", err)
	}
	if want := agentinstall.FingerprintSHA256(leafDER); got != want {
		t.Fatalf("got %s want %s (leaf must be the first block)", got, want)
	}
}

// --- W12-05: push-mode targets (f5 | citrix | k8s) -------------------------

func pushCredentialJSON(t *testing.T, baseURL string) []byte {
	t.Helper()
	payload, err := json.Marshal(pushCredentialPayload{
		BaseURL: baseURL, BearerToken: "sekrit-token",
		Namespace: "edge", SecretName: "shop-tls",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return payload
}

// The full push loop against the PRODUCTION issuance path: issue →
// execute-renewal on a k8s-mode target → the successor's cert lands in the
// fixture cluster's secret and verify-after-push reports installed_verified.
func TestPushRenewalK8sEndToEnd(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "push.example.com", "push.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-push",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}
	fp := issued.CertificateItem.FingerprintSHA256

	// Fixture cluster: stores the secret manifest it receives.
	var stored []byte
	var requests []string
	k8s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer sekrit-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusNotFound) // first install
		case http.MethodPost:
			stored, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(k8s.Close)

	exec := NewRenewalExecutor(provider, &renewalFakeCredStore{
		meta:    OutboundCredentialMeta{ID: "cred-push", CredentialType: CredentialTypeAPIToken},
		payload: pushCredentialJSON(t, k8s.URL),
	})
	exec.pushClient = k8s.Client()
	// The fixture "endpoint" serves whatever landed in the secret.
	exec.verifier = func(context.Context, string) (string, error) {
		var manifest struct {
			Data map[string]string `json:"data"`
		}
		if err := json.Unmarshal(stored, &manifest); err != nil {
			return "", err
		}
		raw, err := base64.StdEncoding.DecodeString(manifest.Data["tls.crt"])
		if err != nil {
			return "", err
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			return "", errors.New("stored cert unparseable")
		}
		return agentinstall.FingerprintSHA256(block.Bytes), nil
	}

	target := ManagedTarget{ID: "tgt-k8s", Name: "Edge Cluster", Host: "gw.example.com",
		InstallMode: "k8s", CredentialRef: "cred-push"}
	res, err := exec.ExecuteRenewal(ctx, fp, target, RenewalInstallProfile{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !res.Renewed || res.NewFingerprint == "" {
		t.Fatalf("expected renewal: %+v", res)
	}
	if res.InstallOutcome != "installed_verified" || !res.Verified {
		t.Fatalf("expected installed_verified via push, got %+v", res)
	}
	if len(requests) < 2 || stored == nil {
		t.Fatalf("secret never landed on the cluster: %v", requests)
	}
}

// A wrong-type credential refuses BEFORE renewal burns a serial.
func TestPushRenewalWrongCredentialTypeFailsBeforeRenewal(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "push-badcred.example.com", "push-badcred.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-push",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}
	fp := issued.CertificateItem.FingerprintSHA256

	exec := NewRenewalExecutor(provider, &renewalFakeCredStore{
		meta:    OutboundCredentialMeta{ID: "cred-ssh", CredentialType: CredentialTypeSSHKey},
		payload: []byte("{}"),
	})
	target := ManagedTarget{ID: "t", Name: "n", Host: "h", InstallMode: "f5", CredentialRef: "cred-ssh"}
	if _, err := exec.ExecuteRenewal(ctx, fp, target, RenewalInstallProfile{}); !errors.Is(err, errRenewalBadCredential) {
		t.Fatalf("expected errRenewalBadCredential, got %v", err)
	}
	after, _, err := provider.GetCertificate(ctx, fp)
	if err != nil {
		t.Fatalf("get predecessor: %v", err)
	}
	if after.SuccessorFP != nil {
		t.Fatal("credential refusal must precede renewal")
	}
}

func TestPushObjectNameSanitizes(t *testing.T) {
	if got := pushObjectName("Edge Cluster v1.2"); got != "edge-cluster-v1-2" {
		t.Fatalf("sanitize: %q", got)
	}
	if got := pushObjectName("!!!"); got != "kryptkeeper" {
		t.Fatalf("fallback: %q", got)
	}
}

// W18 bug: resolvePushCredential hardcoded api_token, so the
// windows_password credential the whole Windows wave added was rejected —
// no IIS target could ever be pushed to. The type is now install-mode
// specific: iis needs windows_password, the HTTP pushers need api_token.
func TestResolvePushCredentialTypePerInstallMode(t *testing.T) {
	winPayload := []byte(`{"base_url":"http://host:5985/wsman","username":"u","password":"p","ipport":"0.0.0.0:443"}`)
	apiPayload := []byte(`{"base_url":"https://dev:443","bearer_token":"t"}`)

	exec := func(ct string, payload []byte) *RenewalExecutor {
		return NewRenewalExecutor(nil, &renewalFakeCredStore{
			meta:    OutboundCredentialMeta{ID: "c", CredentialType: ct},
			payload: payload,
		})
	}

	// windows_password is accepted for iis...
	if _, err := exec(CredentialTypeWindowsPassword, winPayload).resolvePushCredential(context.Background(), "c", "iis"); err != nil {
		t.Fatalf("windows_password must be accepted for iis, got: %v", err)
	}
	// ...and rejected for a non-iis push mode.
	if _, err := exec(CredentialTypeWindowsPassword, winPayload).resolvePushCredential(context.Background(), "c", "k8s"); err == nil {
		t.Fatal("windows_password must be rejected for k8s")
	}
	// api_token is accepted for k8s but rejected for iis.
	if _, err := exec(CredentialTypeAPIToken, apiPayload).resolvePushCredential(context.Background(), "c", "k8s"); err != nil {
		t.Fatalf("api_token must be accepted for k8s, got: %v", err)
	}
	if _, err := exec(CredentialTypeAPIToken, apiPayload).resolvePushCredential(context.Background(), "c", "iis"); err == nil {
		t.Fatal("api_token must be rejected for iis")
	}
}

// TestHostKeyAlgorithmsFor_RSAUsesSHA2Names guards against the fix
// regressing to []string{pub.Type()}: an RSA ssh.PublicKey's Type() is
// "ssh-rsa" (KeyAlgoRSA), the legacy SHA-1 scheme that
// golang.org/x/crypto/ssh's client refuses to negotiate at all (excluded
// from its own supportedHostKeyAlgos). Passing that straight through as
// ClientConfig.HostKeyAlgorithms would make every RSA-pinned host --
// the common case for a stock sshd -- fail to connect, the exact class of
// bug this helper exists to prevent (W19-02).
func TestHostKeyAlgorithmsFor_RSAUsesSHA2Names(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa key: %v", err)
	}
	rsaPub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("rsa pubkey: %v", err)
	}

	got := hostKeyAlgorithmsFor(rsaPub)
	want := []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	if len(got) != len(want) {
		t.Fatalf("hostKeyAlgorithmsFor(rsa) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("hostKeyAlgorithmsFor(rsa) = %v, want %v", got, want)
		}
	}
	for _, algo := range got {
		if algo == ssh.KeyAlgoRSA {
			t.Fatalf("hostKeyAlgorithmsFor(rsa) must not return the raw key type %q -- x/crypto/ssh's client won't negotiate it", ssh.KeyAlgoRSA)
		}
	}
}

// TestHostKeyAlgorithmsFor_NonRSAPassesTypeThrough covers the other key
// types (Ed25519 here, representative of ECDSA too): for these, Type() IS
// already a valid, negotiable ClientConfig.HostKeyAlgorithms entry.
func TestHostKeyAlgorithmsFor_NonRSAPassesTypeThrough(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen ed25519 key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(edPub)
	if err != nil {
		t.Fatalf("ed25519 pubkey: %v", err)
	}

	got := hostKeyAlgorithmsFor(sshPub)
	if len(got) != 1 || got[0] != ssh.KeyAlgoED25519 {
		t.Fatalf("hostKeyAlgorithmsFor(ed25519) = %v, want [%s]", got, ssh.KeyAlgoED25519)
	}
}

// keychainFakeMac answers like a Mac: mktemp prints a private directory,
// `security import` decodes the bundle it was handed, and find-certificate
// lists whatever leaf that bundle really held.
type keychainFakeMac struct {
	files    map[string][]byte
	ran      []string
	imported []byte // DER of the leaf from the last import
}

func (m *keychainFakeMac) Exists(p string) bool { _, ok := m.files[p]; return ok }
func (m *keychainFakeMac) ReadFile(p string) ([]byte, error) {
	return m.files[p], nil
}
func (m *keychainFakeMac) WriteFile(p string, c []byte, _ os.FileMode) error {
	m.files[p] = append([]byte(nil), c...)
	return nil
}
func (m *keychainFakeMac) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	m.ran = append(m.ran, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	switch {
	case name == "mktemp":
		return []byte("/tmp/kk-keychain.Zz99Yy88\n"), nil
	case len(args) > 3 && args[2] == "import": // sudo -n /usr/bin/security import <bundle> ...
		pw := ""
		for i, a := range args {
			if a == "-P" && i+1 < len(args) {
				pw = args[i+1]
			}
		}
		_, leaf, _, err := pkcs12.DecodeChain(m.files[args[3]], pw)
		if err != nil {
			return nil, err
		}
		m.imported = leaf.Raw
	case len(args) > 2 && args[2] == "find-certificate":
		sum := sha256.Sum256(m.imported)
		return []byte("SHA-256 hash: " + strings.ToUpper(hex.EncodeToString(sum[:])) + "\n"), nil
	}
	return nil, nil
}

// W18-05: a keychain target renews through the same SSH credential and
// pinned dial as an ssh target, but needs no server type or paths, and the
// renewed identity lands in the System keychain with its root trusted.
func TestRenewalExecutorKeychainTarget(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "mac01.example.com", "mac01.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-keychain",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}

	mac := &keychainFakeMac{files: map[string][]byte{}}
	e := newRenewalTestEngine(t, provider, &renewalFakeExecutor{files: map[string][]byte{}}, testSSHCredentialJSON(t))
	e.dial = func(_ context.Context, cfg agentinstall.SSHTarget) (agentinstall.Executor, func() error, error) {
		if cfg.HostKeyCallback == nil || cfg.User != "deploy" {
			t.Fatalf("keychain must use the pinned SSH credential: %+v", cfg)
		}
		return mac, func() error { return nil }, nil
	}
	target := sshTestTarget()
	target.InstallMode = "keychain"

	result, err := e.ExecuteRenewal(ctx, issued.CertificateItem.FingerprintSHA256, target, RenewalInstallProfile{})
	if err != nil {
		t.Fatalf("ExecuteRenewal: %v", err)
	}
	if !result.Renewed || result.InstallOutcome != agentinstall.OutcomeInstalled {
		t.Fatalf("result %+v", result)
	}
	if got := agentinstall.FingerprintSHA256(mac.imported); got != result.NewFingerprint {
		t.Fatalf("keychain received %s, want the successor %s", got, result.NewFingerprint)
	}
	var trusted bool
	for _, c := range mac.ran {
		trusted = trusted || strings.Contains(c, "add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain")
	}
	if !trusted {
		t.Fatalf("root never trusted: %v", mac.ran)
	}
}

// The sweep may execute an ssh target only with its full install profile,
// and a keychain or push target (iis here; f5/citrix/k8s are covered in
// renewal_push_sweep_test.go) with just a credential; nothing else.
func TestAutoRenewTargetsByHostEligibility(t *testing.T) {
	full := ManagedTarget{Host: "web", InstallMode: "ssh", AutoRenew: true, AutoRenewSetBy: "admin-1", CredentialRef: "c",
		InstallServerType: "nginx", InstallCertPath: "/c", InstallKeyPath: "/k"}
	pathless := ManagedTarget{Host: "web2", InstallMode: "ssh", AutoRenew: true, AutoRenewSetBy: "admin-1", CredentialRef: "c"}
	mac := ManagedTarget{Host: "mac", InstallMode: "keychain", AutoRenew: true, AutoRenewSetBy: "admin-1", CredentialRef: "c"}
	macNoCred := ManagedTarget{Host: "mac2", InstallMode: "keychain", AutoRenew: true, AutoRenewSetBy: "admin-1"}
	macOptOut := ManagedTarget{Host: "mac3", InstallMode: "keychain", CredentialRef: "c"}
	iis := ManagedTarget{Host: "win", InstallMode: "iis", AutoRenew: true, AutoRenewSetBy: "admin-1", CredentialRef: "c"}
	agent := ManagedTarget{Host: "agenthost", InstallMode: "agent", AutoRenew: true, AutoRenewSetBy: "admin-1", CredentialRef: "c"}

	got := autoRenewTargetsByHost([]ManagedTarget{full, pathless, mac, macNoCred, macOptOut, iis, agent})
	if len(got) != 3 || got["web"].InstallMode != "ssh" || got["mac"].InstallMode != "keychain" || got["win"].InstallMode != "iis" {
		t.Fatalf("eligible %v", got)
	}
}

// W20-21: the sweep auto-renews plugin targets that opted in, have a
// credential and name their plugin.
func TestAutoRenewTargetsIncludePluginTargets(t *testing.T) {
	plugin := ManagedTarget{Host: "vip.example.com", InstallMode: "plugin", AutoRenew: true, AutoRenewSetBy: "admin-1", CredentialRef: "c", PluginID: "kryptkeeper.example-device"}
	noPlugin := ManagedTarget{Host: "vip2.example.com", InstallMode: "plugin", AutoRenew: true, AutoRenewSetBy: "admin-1", CredentialRef: "c"}
	optOut := ManagedTarget{Host: "vip3.example.com", InstallMode: "plugin", CredentialRef: "c", PluginID: "kryptkeeper.example-device"}
	got := autoRenewTargetsByHost([]ManagedTarget{plugin, noPlugin, optOut})
	if len(got) != 1 {
		t.Fatalf("eligible %v, want only vip.example.com", got)
	}
	if _, ok := got["vip.example.com"]; !ok {
		t.Fatalf("an opted-in plugin target is not auto-renewed: %v", got)
	}
}
