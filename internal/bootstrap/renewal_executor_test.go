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
	"kryptkeeper/internal/discovery/scanner"
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

	// W32-26: a verified renewal tells the ITSM hook which certificate was replaced.
	var hooked []string
	SetRenewalVerifiedHook(func(_ context.Context, pred, succ string) { hooked = append(hooked, pred+">"+succ) })
	t.Cleanup(func() { SetRenewalVerifiedHook(nil) })

	result, err := exec.ExecuteRenewal(ctx, predecessorFP, sshTestTarget(), sshTestProfile())
	if err != nil {
		t.Fatalf("ExecuteRenewal: %v", err)
	}
	if !result.Renewed || result.NewFingerprint == "" || result.NewFingerprint == predecessorFP {
		t.Fatalf("expected a renewed successor, got %+v", result)
	}
	if len(hooked) != 1 || hooked[0] != predecessorFP+">"+result.NewFingerprint {
		t.Fatalf("renewal-verified hook calls = %v", hooked)
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

// W35-02: a sqlserver target authenticates over WinRM like iis, takes its
// instance and port from the credential, and the port may arrive as a number
// (API) or as text (the wizard's form).
func TestResolvePushCredentialSQLServer(t *testing.T) {
	exec := func(ct string, payload string) *RenewalExecutor {
		return NewRenewalExecutor(nil, &renewalFakeCredStore{
			meta:    OutboundCredentialMeta{ID: "c", CredentialType: ct},
			payload: []byte(payload),
		})
	}
	for name, payload := range map[string]string{
		"number": `{"base_url":"https://h:5986/wsman","username":"u","password":"p","sql_instance":"SALES","sql_port":14330}`,
		"text":   `{"base_url":"https://h:5986/wsman","username":"u","password":"p","sql_instance":"SALES","sql_port":"14330"}`,
	} {
		got, err := exec(CredentialTypeWindowsPassword, payload).resolvePushCredential(context.Background(), "c", "sqlserver")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.SQLInstance != "SALES" || got.SQLPort != 14330 {
			t.Errorf("%s: instance/port = %q/%d", name, got.SQLInstance, got.SQLPort)
		}
		if p := defaultVerifyPort("sqlserver", got); p != "14330" {
			t.Errorf("%s: verify port = %s", name, p)
		}
	}
	if _, err := exec(CredentialTypeAPIToken, `{"base_url":"https://h"}`).resolvePushCredential(context.Background(), "c", "sqlserver"); err == nil {
		t.Fatal("api_token must be rejected for sqlserver")
	}
	if _, err := exec(CredentialTypeWindowsPassword, `{"base_url":"https://h","sql_port":"99999"}`).resolvePushCredential(context.Background(), "c", "sqlserver"); err == nil {
		t.Fatal("an out-of-range port must be rejected")
	}
	if p := defaultVerifyPort("sqlserver", pushCredentialPayload{}); p != "1433" {
		t.Errorf("default sqlserver verify port = %s, want 1433", p)
	}
	if p := defaultVerifyPort("iis", pushCredentialPayload{}); p != "443" {
		t.Errorf("default iis verify port = %s, want 443", p)
	}
	if p := defaultVerifyPort("rdp", pushCredentialPayload{}); p != "3389" {
		t.Errorf("default rdp verify port = %s, want 3389", p)
	}
	if _, err := exec(CredentialTypeWindowsPassword, `{"base_url":"https://h:5986/wsman","username":"u","password":"p"}`).resolvePushCredential(context.Background(), "c", "rdp"); err != nil {
		t.Fatalf("windows_password must be accepted for rdp: %v", err)
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

// W27-07: a tomcat target builds the keystore hub-side from the credential's
// keystore_password. The scheduler audits result.InstallOutcome verbatim as
// "install=<outcome>", so asserting the outcome here pins the audit field; the
// password must appear in neither the outcome nor the detail.
func TestRenewalExecutorTomcatKeystore(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "renew-exec.example.com", "renew-exec.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-renew-exec",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}

	const ksPassword = "Tomcat-ks-pw-123"
	var cred sshCredentialPayload
	if err := json.Unmarshal(testSSHCredentialJSON(t), &cred); err != nil {
		t.Fatal(err)
	}
	cred.KeystorePassword = ksPassword
	credJSON, _ := json.Marshal(cred)

	const ksPath = "/opt/tomcat/conf/keystore.p12"
	fake := &renewalFakeExecutor{files: map[string][]byte{}}
	exec := newRenewalTestEngine(t, provider, fake, credJSON)
	exec.verifier = func(context.Context, string) (string, error) {
		_, leaf, _, err := pkcs12.DecodeChain(fake.files[ksPath], ksPassword)
		if err != nil {
			return "", err
		}
		return agentinstall.FingerprintSHA256(leaf.Raw), nil
	}
	profile := RenewalInstallProfile{ServerType: "tomcat", CertPath: ksPath, KeyPath: ksPath}

	result, err := exec.ExecuteRenewal(ctx, issued.CertificateItem.FingerprintSHA256, sshTestTarget(), profile)
	if err != nil {
		t.Fatalf("ExecuteRenewal: %v", err)
	}
	if result.InstallOutcome != agentinstall.OutcomeInstalledVerified || !result.Verified {
		t.Fatalf("want installed_verified, got %+v", result)
	}
	if strings.Contains(result.InstallOutcome+result.InstallDetail, ksPassword) {
		t.Fatal("keystore password leaked into the result")
	}
	if _, ok := fake.files[ksPath]; !ok {
		t.Fatal("keystore not installed")
	}

	// Without a keystore_password the install is refused, reported in the
	// result (not an opaque error), and the first-install keystore is cleaned.
	noPW := &renewalFakeExecutor{files: map[string][]byte{}}
	cred.KeystorePassword = ""
	credJSON, _ = json.Marshal(cred)
	exec2 := newRenewalTestEngine(t, provider, noPW, credJSON)
	issued2, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "renew-exec2.example.com", "renew-exec2.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-renew-exec",
	})
	if err != nil {
		t.Fatalf("issue second predecessor: %v", err)
	}
	res2, err := exec2.ExecuteRenewal(ctx, issued2.CertificateItem.FingerprintSHA256, sshTestTarget(), profile)
	if err != nil {
		t.Fatalf("ExecuteRenewal (no password): %v", err)
	}
	if res2.InstallOutcome == agentinstall.OutcomeInstalledVerified || len(noPW.files) != 0 {
		t.Fatalf("missing keystore password must not install: %+v", res2)
	}
}

// ---- W34-14: sudo_mode on the ssh_key credential ----

// privFakeExec emulates a host where one cert is root-only: plain ReadFile
// cannot see it, `sudo ... cat` can. It records every command line so tests
// can assert the sudo password never appears in argv.
type privFakeExec struct {
	sshDiscFakeExec
	rootOnly map[string][]byte
	password string
	argv     []string
}

func (f *privFakeExec) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f.RunStdin(ctx, nil, name, args...)
}

func (f *privFakeExec) RunStdin(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	f.argv = append(f.argv, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	if name != "sudo" {
		return f.sshDiscFakeExec.Run(ctx, name, args...)
	}
	if len(args) > 0 && args[0] == "-S" && string(stdin) != f.password+"\n" {
		return []byte("Sorry, try again."), errors.New("exit status 1")
	}
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 || sep+1 >= len(args) {
		return nil, errors.New("sudo: no command")
	}
	cmd, cargs := args[sep+1], args[sep+2:]
	if cmd == "cat" && len(cargs) == 1 {
		if b, ok := f.rootOnly[cargs[0]]; ok {
			return b, nil
		}
		if b, ok := f.files[cargs[0]]; ok {
			return b, nil
		}
		return nil, errors.New("no such file")
	}
	return f.sshDiscFakeExec.Run(ctx, cmd, cargs...)
}

func sshPayloadWithPrivilege(t *testing.T, extra map[string]string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(sshCredentialJSONWithMarker(t, "PRIV-MARK"), &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range extra {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func runPrivScan(t *testing.T, extra map[string]string, exec *privFakeExec) scanner.ScanResult {
	t.Helper()
	targets, creds := winrmTestStores(t)
	if _, err := creds.Create(context.Background(), "cred-priv", "kkscan", CredentialTypeSSHKey, "", sshPayloadWithPrivilege(t, extra)); err != nil {
		t.Fatal(err)
	}
	tgt, err := targets.Create(context.Background(), ManagedTarget{ID: "t-priv", Name: "linux", Host: "192.0.2.30",
		DiscoveryMode: "network", InstallMode: "ssh", RenewalMethod: "manual", CredentialRef: "cred-priv"})
	if err != nil {
		t.Fatal(err)
	}
	run := newSSHTargetScanner(targets, creds, &sshRecordingAudit{}, func(context.Context, agentinstall.SSHTarget) (agentinstall.Executor, func() error, error) {
		return exec, func() error { return nil }, nil
	})
	return run(context.Background(), tgt.ID)
}

func newPrivFake(t *testing.T, password string) *privFakeExec {
	return &privFakeExec{
		sshDiscFakeExec: sshDiscFakeExec{
			files:   map[string][]byte{"/etc/ssl/certs/a.crt": certFilePEM(t, "a.example.com")},
			findOut: map[string]string{"/etc/ssl/certs": "/etc/ssl/certs/a.crt\n/etc/ssl/certs/root.crt"},
		},
		rootOnly: map[string][]byte{"/etc/ssl/certs/root.crt": certFilePEM(t, "root.example.com")},
		password: password,
	}
}

func TestSSHDiscoveryHonoursSudoMode(t *testing.T) {
	const pw = "Disc-Sudo-Pw-4412"
	cases := []struct {
		name      string
		extra     map[string]string
		wantCerts int
		wantSudo  string
	}{
		{"unset is none", nil, 1, ""},
		{"none", map[string]string{"sudo_mode": "none"}, 1, ""},
		{"nopasswd", map[string]string{"sudo_mode": "nopasswd"}, 2, "sudo -n -- cat /etc/ssl/certs/root.crt"},
		{"password", map[string]string{"sudo_mode": "password", "sudo_password": pw}, 2, "sudo -S -p  -k -- cat /etc/ssl/certs/root.crt"},
	}
	for _, c := range cases {
		exec := newPrivFake(t, pw)
		res := runPrivScan(t, c.extra, exec)
		if res.CertsFound != c.wantCerts {
			t.Errorf("%s: CertsFound %d, want %d (%+v)", c.name, res.CertsFound, c.wantCerts, res)
		}
		joined := strings.Join(exec.argv, "\n")
		if c.wantSudo == "" && strings.Contains(joined, "sudo") {
			t.Errorf("%s: sudo must not run:\n%s", c.name, joined)
		}
		if c.wantSudo != "" && !strings.Contains(joined, c.wantSudo) {
			t.Errorf("%s: missing %q in:\n%s", c.name, c.wantSudo, joined)
		}
		if strings.Contains(joined, pw) {
			t.Errorf("%s: sudo password in argv:\n%s", c.name, joined)
		}
		if b, _ := json.Marshal(res); strings.Contains(string(b), pw) {
			t.Errorf("%s: sudo password in scan result", c.name)
		}
	}
}

func TestSSHDiscoveryWrongSudoPasswordDoesNotLeak(t *testing.T) {
	const pw = "Stored-Wrong-Pw-9921"
	exec := newPrivFake(t, "the-real-one")
	res := runPrivScan(t, map[string]string{"sudo_mode": "password", "sudo_password": pw}, exec)
	if b, _ := json.Marshal(res); strings.Contains(string(b), pw) {
		t.Fatalf("scan result leaked the sudo password: %s", b)
	}
	if res.CertsFound != 0 || res.Status != "failed" {
		t.Fatalf("a rejected password must surface as unreadable paths, not as certs: %+v", res)
	}
}

func TestSSHDiscoveryInvalidPrivilegeFailsBeforeScan(t *testing.T) {
	exec := newPrivFake(t, "x")
	res := runPrivScan(t, map[string]string{"sudo_mode": "password"}, exec)
	if res.Status != "failed" || len(exec.argv) != 0 {
		t.Fatalf("invalid combination must fail the scan without running commands: %+v argv=%v", res, exec.argv)
	}
}

func TestSSHCredentialElevate(t *testing.T) {
	plain := &privFakeExec{}
	got, done, err := sshCredentialPayload{}.elevate(plain)
	if err != nil || got != agentinstall.Executor(plain) {
		t.Fatalf("none must return the executor unchanged: %v", err)
	}
	done()
	if _, _, err := (sshCredentialPayload{SudoMode: "password", SudoPassword: "x"}).elevate(&renewalFakeExecutor{}); err == nil {
		t.Fatal("password mode over a transport without stdin (renewalFakeExecutor has no RunStdin, like WinRM) must be refused")
	}
	if _, _, err := (sshCredentialPayload{SudoMode: "helper"}).elevate(plain); err == nil {
		t.Fatal("helper mode without a pinned sha must be refused")
	}
	if _, done, err := (sshCredentialPayload{SudoMode: "helper", HelperSHA256: strings.Repeat("0", 64)}).elevate(plain); err != nil {
		t.Fatalf("helper: %v", err)
	} else {
		done()
	}
}

// sudoInstallFake serves the privilege-elevated half of the installer: it
// strips `sudo -n --` or `sudo -S -p ” -k --` and honours `install -m M src dst`
// against its virtual filesystem, recording argv and refusing a wrong password.
type sudoInstallFake struct {
	renewalFakeExecutor
	password string
	argv     []string
	// owners maps a path to "owner group mode" for the `stat -c` probe.
	owners map[string]string
	// failInstallsAfter, when > 0, makes every sudo install after that many fail.
	failInstallsAfter int
	installs          int
}

func (f *sudoInstallFake) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f.RunStdin(ctx, nil, name, args...)
}

func (f *sudoInstallFake) RunStdin(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	f.argv = append(f.argv, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	if name != "sudo" {
		return f.renewalFakeExecutor.Run(ctx, name, args...)
	}
	if len(args) > 0 && args[0] == "-S" && string(stdin) != f.password+"\n" {
		return []byte("Sorry, try again."), errors.New("exit status 1")
	}
	for i, a := range args {
		if a != "--" {
			continue
		}
		cmd, rest := args[i+1], args[i+2:]
		if cmd == "cat" && len(rest) == 1 {
			if b, ok := f.files[rest[0]]; ok {
				return b, nil
			}
			return nil, errors.New("cat: no such file")
		}
		if cmd == "stat" && len(rest) == 3 && rest[0] == "-c" {
			if o, ok := f.owners[rest[2]]; ok && rest[1] == "%U %G %a" {
				return []byte(o + "\n"), nil
			}
			return nil, errors.New("stat: no such file")
		}
		if cmd == "install" && len(rest) >= 4 {
			f.installs++
			if f.failInstallsAfter > 0 && f.installs > f.failInstallsAfter {
				return []byte("install: Permission denied"), errors.New("exit status 1")
			}
			b, ok := f.files[rest[len(rest)-2]]
			if !ok {
				return nil, errors.New("install: no such staged file")
			}
			f.files[rest[len(rest)-1]] = b
			return nil, nil
		}
		return f.renewalFakeExecutor.Run(ctx, cmd, rest...)
	}
	return nil, errors.New("sudo: no command")
}

func TestRenewalExecutorInstallsThroughSudo(t *testing.T) {
	const pw = "Renew-Sudo-Pw-3308"
	for _, mode := range []string{"nopasswd", "password"} {
		t.Run(mode, func(t *testing.T) {
			db := setupIntegrationDB(t)
			provider, engine := newIntegrationCAProvider(t, db)
			ctx := context.Background()
			issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
				CAID:       getFirstCAID(t, engine),
				CSRPEM:     generateTestCSRPEM(t, "renew-exec.example.com", "renew-exec.example.com"),
				TemplateID: "file-backed-default",
				TeamID:     "team-renew-exec",
			})
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(testSSHCredentialJSON(t), &m); err != nil {
				t.Fatal(err)
			}
			m["sudo_mode"] = mode
			if mode == "password" {
				m["sudo_password"] = pw
			}
			payload, _ := json.Marshal(m)

			fake := &sudoInstallFake{renewalFakeExecutor: renewalFakeExecutor{files: map[string][]byte{}}, password: pw}
			e := NewRenewalExecutor(provider, &renewalFakeCredStore{
				meta: OutboundCredentialMeta{ID: "cred-1", CredentialType: CredentialTypeSSHKey}, payload: payload,
			})
			e.dial = func(context.Context, agentinstall.SSHTarget) (agentinstall.Executor, func() error, error) {
				return fake, func() error { return nil }, nil
			}
			e.verifier = func(context.Context, string) (string, error) {
				block, _ := pem.Decode(fake.files["/etc/nginx/tls/renewed.crt"])
				if block == nil {
					return "", errors.New("nothing installed")
				}
				return agentinstall.FingerprintSHA256(block.Bytes), nil
			}
			res, err := e.ExecuteRenewal(ctx, issued.CertificateItem.FingerprintSHA256, sshTestTarget(), sshTestProfile())
			if err != nil {
				t.Fatal(err)
			}
			if res.InstallOutcome != agentinstall.OutcomeInstalledVerified {
				t.Fatalf("install through sudo failed: %+v", res)
			}
			joined := strings.Join(fake.argv, "\n")
			if !strings.Contains(joined, "install -m ") || !strings.Contains(joined, "sudo ") {
				t.Fatalf("install must run under sudo:\n%s", joined)
			}
			if strings.Contains(joined, pw) || strings.Contains(res.InstallDetail, pw) {
				t.Fatal("sudo password leaked into argv or the install detail")
			}
		})
	}
}

type fakeBlocker struct{ blocked []string }

func (b *fakeBlocker) BlockTarget(_ context.Context, id, reason string) error {
	b.blocked = append(b.blocked, id+"|"+reason)
	return nil
}

// privRenewal runs one nginx renewal through nopasswd sudo against fake, with
// both certificate files already on the host.
func privRenewal(t *testing.T, fake *sudoInstallFake) (RenewalExecuteResult, *sshRecordingAudit, *fakeBlocker) {
	return privRenewalWith(t, fake, "nopasswd", context.Background())
}

func privRenewalWith(t *testing.T, fake *sudoInstallFake, sudoMode string, ctx context.Context) (RenewalExecuteResult, *sshRecordingAudit, *fakeBlocker) {
	t.Helper()
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "renew-exec.example.com", "renew-exec.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-renew-exec",
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(testSSHCredentialJSON(t), &m); err != nil {
		t.Fatal(err)
	}
	if sudoMode != "" {
		m["sudo_mode"] = sudoMode
	}
	payload, _ := json.Marshal(m)
	audit := &sshRecordingAudit{}
	blocker := &fakeBlocker{}
	e := NewRenewalExecutor(provider, &renewalFakeCredStore{
		meta: OutboundCredentialMeta{ID: "cred-1", CredentialType: CredentialTypeSSHKey}, payload: payload,
	}).WithTargetBlocker(blocker)
	e.pluginAudit = audit
	e.dial = func(context.Context, agentinstall.SSHTarget) (agentinstall.Executor, func() error, error) {
		return fake, func() error { return nil }, nil
	}
	e.verifier = func(context.Context, string) (string, error) {
		block, _ := pem.Decode(fake.files["/etc/nginx/tls/renewed.crt"])
		if block == nil {
			return "", errors.New("nothing installed")
		}
		return agentinstall.FingerprintSHA256(block.Bytes), nil
	}
	res, err := e.ExecuteRenewal(ctx, issued.CertificateItem.FingerprintSHA256, sshTestTarget(), sshTestProfile())
	if err != nil {
		t.Fatal(err)
	}
	return res, audit, blocker
}

func newOwnedFake() *sudoInstallFake {
	return &sudoInstallFake{
		renewalFakeExecutor: renewalFakeExecutor{files: map[string][]byte{
			"/etc/nginx/tls/renewed.crt": []byte("OLD-CERT"),
			"/etc/nginx/tls/renewed.key": []byte("OLD-KEY"),
		}},
		owners: map[string]string{
			"/etc/nginx/tls/renewed.crt": "www-data www-data 644",
			"/etc/nginx/tls/renewed.key": "root ssl-cert 640",
		},
	}
}

// W34-18: a privileged push keeps owner, group and mode, and is audited with
// the mode but never the password.
func TestRenewalExecutorPrivilegedPushPreservesOwnershipAndAudits(t *testing.T) {
	fake := newOwnedFake()
	res, audit, blocker := privRenewal(t, fake)
	if res.InstallOutcome != agentinstall.OutcomeInstalledVerified {
		t.Fatalf("%+v", res)
	}
	joined := strings.Join(fake.argv, "\n")
	for _, want := range []string{
		"sudo -n -- install -m 0644 -o www-data -g www-data",
		"sudo -n -- install -m 0640 -o root -g ssl-cert",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	var found bool
	for _, e := range audit.entries {
		if e.Action == "target.renewal.privileged" && e.Outcome == AuditOutcomeSuccess && strings.Contains(e.ChangeSummary, "mode=nopasswd") && e.ResourceID == "tgt-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no target.renewal.privileged audit row: %+v", audit.entries)
	}
	if len(blocker.blocked) != 0 {
		t.Fatalf("a good push must not block: %v", blocker.blocked)
	}
}

// A failed config test rolls back through the same privileged path (sudo
// install again, with the original owner), and the old files come back.
func TestRenewalExecutorPrivilegedRollbackUsesPrivilegedPath(t *testing.T) {
	fake := newOwnedFake()
	fake.failCommand = "nginx"
	res, _, blocker := privRenewal(t, fake)
	if res.InstallOutcome != agentinstall.OutcomeConfigTestFailed {
		t.Fatalf("%+v", res)
	}
	if string(fake.files["/etc/nginx/tls/renewed.crt"]) != "OLD-CERT" || string(fake.files["/etc/nginx/tls/renewed.key"]) != "OLD-KEY" {
		t.Fatal("old files must be back")
	}
	if fake.installs != 4 {
		t.Fatalf("2 installs to push + 2 to roll back, got %d", fake.installs)
	}
	if len(blocker.blocked) != 0 {
		t.Fatalf("a clean rollback must not block: %v", blocker.blocked)
	}
}

func TestRenewalExecutorRollbackFailureBlocksTarget(t *testing.T) {
	fake := newOwnedFake()
	fake.failCommand = "nginx"
	fake.failInstallsAfter = 2 // the push works, the rollback does not
	res, audit, blocker := privRenewal(t, fake)
	if res.InstallOutcome != agentinstall.OutcomeRollbackFailed {
		t.Fatalf("want rollback_failed, got %+v", res)
	}
	if len(blocker.blocked) != 1 || !strings.HasPrefix(blocker.blocked[0], "tgt-1|") {
		t.Fatalf("target must be blocked: %v", blocker.blocked)
	}
	assertAudit(t, audit, "target.renewal.rollback_failed", AuditOutcomeFailure)
}

// W34-17: a credential without sudo renews through a one-off password carried
// on the context, and the secret is wiped afterwards by its owner.
func TestRenewalExecutorUsesJITSudoPassword(t *testing.T) {
	const pw = "Jit-Renew-Pw-2290"
	fake := newOwnedFake()
	fake.password = pw
	res, _, _ := privRenewalWith(t, fake, "", withJITSudo(context.Background(), newJITSudo(pw)))
	if res.InstallOutcome != agentinstall.OutcomeInstalledVerified {
		t.Fatalf("%+v", res)
	}
	joined := strings.Join(fake.argv, "\n")
	if !strings.Contains(joined, "sudo -S -p  -k -- install -m 0644 -o www-data") {
		t.Fatalf("install must run under the one-off password:\n%s", joined)
	}
	if strings.Contains(joined, pw) || strings.Contains(res.InstallDetail, pw) {
		t.Fatal("password leaked")
	}
}
