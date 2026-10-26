// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// W36-06: AWS Private CA over an httptest server speaking the AWS JSON 1.1
// protocol (X-Amz-Target: ACMPrivateCA.<Op>), pinning our request fields.

const (
	pcaTestARN    = "arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/12345678-1234-1234-1234-123456789012"
	pcaTestSecret = "pca-test-secret-key-do-not-leak"
)

func pcaCSR(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "svc.example.test"}, DNSNames: []string{"svc.example.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

type pcaFixture struct {
	srv *httptest.Server

	mu       sync.Mutex
	targets  []string
	bodies   map[string]map[string]any
	auth     string
	leaf     string
	chain    string
	caStatus string
	// getInProgress: GetCertificate answers RequestInProgressException this many times first.
	getInProgress int
	gets          int
	// errFor maps a target to an AWS error type returned with HTTP 400.
	errFor map[string]string
}

func newPCAFixture(t *testing.T) *pcaFixture {
	t.Helper()
	f := &pcaFixture{
		bodies:   map[string]map[string]any{},
		caStatus: "ACTIVE",
		leaf:     string(digicertLeafPEM(t, "svc.example.test")),
		chain:    string(digicertLeafPEM(t, "Issuing CA")) + string(digicertLeafPEM(t, "Root CA")),
		errFor:   map[string]string{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		target := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "ACMPrivateCA.")
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.targets = append(f.targets, target)
		f.bodies[target] = body
		f.auth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		fail := func(typ string) {
			w.Header().Set("X-Amzn-ErrorType", typ)
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"__type": typ, "message": "boom " + typ})
		}
		if typ := f.errFor[target]; typ != "" {
			fail(typ)
			return
		}
		switch target {
		case "DescribeCertificateAuthority":
			_ = json.NewEncoder(w).Encode(map[string]any{"CertificateAuthority": map[string]any{
				"Status":                            f.caStatus,
				"CertificateAuthorityConfiguration": map[string]any{"SigningAlgorithm": "SHA384WITHECDSA"},
			}})
		case "IssueCertificate":
			_ = json.NewEncoder(w).Encode(map[string]string{"CertificateArn": pcaTestARN + "/certificate/abc123"})
		case "GetCertificate":
			f.gets++
			if f.gets <= f.getInProgress {
				fail("RequestInProgressException")
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"Certificate": f.leaf, "CertificateChain": f.chain})
		case "RevokeCertificate":
			_, _ = w.Write([]byte("{}"))
		default:
			fail("UnknownOperationException")
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *pcaFixture) connector(mut func(*AWSPCAConfig)) *AWSPCAConnector {
	cfg := AWSPCAConfig{
		CertificateAuthorityARN: pcaTestARN, Region: "us-east-1", EndpointURL: f.srv.URL,
		AccessKeyID: "AKIATESTFAKE", SecretAccessKey: pcaTestSecret,
		PollAttempts: 5, PollInterval: 10 * time.Millisecond,
	}
	if mut != nil {
		mut(&cfg)
	}
	return NewAWSPCAConnector("pca1", cfg, testClient("", "", ""))
}

func TestAWSPCAIssueSuccess(t *testing.T) {
	f := newPCAFixture(t)
	c := f.connector(func(cfg *AWSPCAConfig) { cfg.TemplateARN = "arn:aws:acm-pca:::template/EndEntityCertificate/V1" })
	csr := pcaCSR(t)
	res, err := c.Issue(context.Background(), IssueRequest{CSRPEM: csr})
	if err != nil {
		t.Fatal(err)
	}
	// Leaf first, then both chain certs.
	if n := strings.Count(res.CertificatePEM, "BEGIN CERTIFICATE"); n != 3 {
		t.Fatalf("want leaf+2 chain, got %d certs", n)
	}
	leaf, _ := pem.Decode([]byte(res.CertificatePEM))
	cert, err := x509.ParseCertificate(leaf.Bytes)
	if err != nil || cert.Subject.CommonName != "svc.example.test" {
		t.Fatalf("leaf not first: %v %v", err, cert)
	}
	fp := sha256.Sum256(cert.Raw)
	if res.FingerprintSHA256 != hex.EncodeToString(fp[:]) {
		t.Fatal("fingerprint is not sha256 of leaf DER")
	}
	if c.Type() != "aws_pca" || c.Origin() != "synced" {
		t.Fatal("type/origin")
	}

	issue := f.bodies["IssueCertificate"]
	if issue["CertificateAuthorityArn"] != pcaTestARN {
		t.Fatalf("arn: %v", issue["CertificateAuthorityArn"])
	}
	// Signing algorithm came from the CA because none was configured.
	if issue["SigningAlgorithm"] != "SHA384WITHECDSA" {
		t.Fatalf("alg: %v", issue["SigningAlgorithm"])
	}
	v, _ := issue["Validity"].(map[string]any)
	if v["Type"] != "DAYS" || v["Value"] != float64(90) {
		t.Fatalf("validity: %v", v)
	}
	sum := sha256.Sum256([]byte(csr))
	if issue["IdempotencyToken"] != hex.EncodeToString(sum[:])[:36] {
		t.Fatalf("idempotency token: %v", issue["IdempotencyToken"])
	}
	if issue["TemplateArn"] != "arn:aws:acm-pca:::template/EndEntityCertificate/V1" {
		t.Fatalf("template: %v", issue["TemplateArn"])
	}
	if got, _ := issue["Csr"].(string); got == "" {
		t.Fatal("csr missing")
	}
	get := f.bodies["GetCertificate"]
	if get["CertificateAuthorityArn"] != pcaTestARN || !strings.HasSuffix(get["CertificateArn"].(string), "/certificate/abc123") {
		t.Fatalf("get body: %v", get)
	}
	if !strings.Contains(f.auth, "AKIATESTFAKE") || strings.Contains(f.auth, pcaTestSecret) {
		t.Fatalf("auth header should be signed with the static key id only: %s", f.auth)
	}
}

func TestAWSPCAConfiguredAlgorithmSkipsDescribe(t *testing.T) {
	f := newPCAFixture(t)
	c := f.connector(func(cfg *AWSPCAConfig) { cfg.SigningAlgorithm = "SHA256WITHRSA"; cfg.ValidityDays = 30 })
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: pcaCSR(t)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.bodies["DescribeCertificateAuthority"]; ok {
		t.Fatal("describe should not be called when algorithm is configured")
	}
	issue := f.bodies["IssueCertificate"]
	if issue["SigningAlgorithm"] != "SHA256WITHRSA" || issue["Validity"].(map[string]any)["Value"] != float64(30) {
		t.Fatalf("issue body: %v", issue)
	}
}

func TestAWSPCAPendingThenIssued(t *testing.T) {
	f := newPCAFixture(t)
	f.getInProgress = 2
	c := f.connector(nil)
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: pcaCSR(t)}); err != nil {
		t.Fatal(err)
	}
	if f.gets != 3 {
		t.Fatalf("want 3 GetCertificate calls, got %d", f.gets)
	}
}

func TestAWSPCAPendingBudgetExhausted(t *testing.T) {
	f := newPCAFixture(t)
	f.getInProgress = 1000
	c := f.connector(func(cfg *AWSPCAConfig) { cfg.PollAttempts = 3 })
	_, err := c.Issue(context.Background(), IssueRequest{CSRPEM: pcaCSR(t)})
	if err == nil {
		t.Fatal("expected wait-budget error")
	}
	if h := c.Health(context.Background()); h.Status != "degraded" || !strings.Contains(h.Detail, "last issue error") {
		t.Fatalf("health should carry the issue error: %+v", h)
	}
}

func TestAWSPCAIssueContextCancel(t *testing.T) {
	f := newPCAFixture(t)
	f.getInProgress = 1000
	c := f.connector(func(cfg *AWSPCAConfig) { cfg.PollAttempts = 1000; cfg.PollInterval = 50 * time.Millisecond })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := c.Issue(ctx, IssueRequest{CSRPEM: pcaCSR(t)}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
}

func TestAWSPCAIssue4xxHidesSecret(t *testing.T) {
	f := newPCAFixture(t)
	f.errFor["IssueCertificate"] = "MalformedCSRException"
	c := f.connector(nil)
	_, err := c.Issue(context.Background(), IssueRequest{CSRPEM: pcaCSR(t)})
	if err == nil || !strings.Contains(err.Error(), "MalformedCSRException") {
		t.Fatalf("want mapped vendor error, got %v", err)
	}
	var rl *RateLimitError
	if errors.As(err, &rl) {
		t.Fatal("malformed CSR is not a rate limit")
	}
	for _, s := range []string{pcaTestSecret, "AKIATESTFAKE"} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("error leaks credential: %v", err)
		}
	}
}

func TestAWSPCAThrottleMapsToRateLimitError(t *testing.T) {
	for _, code := range []string{"ThrottlingException", "TooManyRequestsException", "LimitExceededException"} {
		f := newPCAFixture(t)
		f.errFor["IssueCertificate"] = code
		c := f.connector(nil)
		_, err := c.Issue(context.Background(), IssueRequest{CSRPEM: pcaCSR(t)})
		var rl *RateLimitError
		if !errors.As(err, &rl) || rl.Reason != "upstream_429" || rl.ConnectorID != "pca1" || rl.RetryAfter != 0 {
			t.Fatalf("%s: want RateLimitError, got %v", code, err)
		}
		if _, limited := RetryAfterOf(err); !limited {
			t.Fatalf("%s: throttle gate should see it", code)
		}
	}
}

func TestAWSPCARevoke(t *testing.T) {
	cases := []struct {
		reason int
		serial string
		want   string
	}{
		{1, "E8:CB:D2:BE", "KEY_COMPROMISE"},
		{2, "0a1b", "CERTIFICATE_AUTHORITY_COMPROMISE"},
		{3, "0a1b", "AFFILIATION_CHANGED"},
		{4, "0a1b", "SUPERSEDED"},
		{5, "0a1b", "CESSATION_OF_OPERATION"},
		{9, "0a1b", "PRIVILEGE_WITHDRAWN"},
		{10, "0a1b", "A_A_COMPROMISE"},
		{0, "0a1b", "UNSPECIFIED"},
		{6, "0a1b", "UNSPECIFIED"},
		{99, "0a1b", "UNSPECIFIED"},
	}
	for _, tc := range cases {
		f := newPCAFixture(t)
		c := f.connector(nil)
		if err := c.Revoke(context.Background(), RevokeRequest{SerialHex: tc.serial, Reason: tc.reason}); err != nil {
			t.Fatal(err)
		}
		b := f.bodies["RevokeCertificate"]
		if b["RevocationReason"] != tc.want || b["CertificateAuthorityArn"] != pcaTestARN {
			t.Fatalf("reason %d: %v", tc.reason, b)
		}
		if got := b["CertificateSerial"]; got != strings.ToLower(strings.ReplaceAll(tc.serial, ":", "")) {
			t.Fatalf("serial: %v", got)
		}
	}
}

func TestAWSPCARevokeErrors(t *testing.T) {
	f := newPCAFixture(t)
	f.errFor["RevokeCertificate"] = "InvalidStateException"
	c := f.connector(nil)
	err := c.Revoke(context.Background(), RevokeRequest{SerialHex: "ab", Reason: 1})
	if err == nil || !strings.Contains(err.Error(), "InvalidStateException") || strings.Contains(err.Error(), pcaTestSecret) {
		t.Fatalf("got %v", err)
	}
	f.errFor["RevokeCertificate"] = "ThrottlingException"
	var rl *RateLimitError
	if err := c.Revoke(context.Background(), RevokeRequest{SerialHex: "ab"}); !errors.As(err, &rl) {
		t.Fatalf("want RateLimitError, got %v", err)
	}
	for _, bad := range []string{"", "xyz"} {
		if err := c.Revoke(context.Background(), RevokeRequest{SerialHex: bad}); err == nil {
			t.Fatalf("serial %q should be refused", bad)
		}
	}
}

func TestAWSPCAHealth(t *testing.T) {
	f := newPCAFixture(t)
	c := f.connector(nil)
	if h := c.Health(context.Background()); h.Status != "healthy" {
		t.Fatalf("want healthy, got %+v", h)
	}
	f.caStatus = "DISABLED"
	if h := c.Health(context.Background()); h.Status != "degraded" || !strings.Contains(h.Detail, "DISABLED") {
		t.Fatalf("want degraded DISABLED, got %+v", h)
	}
	f.errFor["DescribeCertificateAuthority"] = "ResourceNotFoundException"
	if h := c.Health(context.Background()); h.Status != "degraded" || strings.Contains(h.Detail, pcaTestSecret) {
		t.Fatalf("got %+v", h)
	}
}

func TestAWSPCAConfigValidation(t *testing.T) {
	f := newPCAFixture(t)
	for name, cfg := range map[string]AWSPCAConfig{
		"no arn":      {Region: "us-east-1", AccessKeyID: "a", SecretAccessKey: "b"},
		"no creds":    {CertificateAuthorityARN: pcaTestARN, Region: "us-east-1"},
		"half creds":  {CertificateAuthorityARN: pcaTestARN, Region: "us-east-1", AccessKeyID: "a"},
		"bad csr arg": {CertificateAuthorityARN: pcaTestARN, Region: "us-east-1", AccessKeyID: "a", SecretAccessKey: "b"},
	} {
		cfg.EndpointURL = f.srv.URL
		c := NewAWSPCAConnector("x", cfg, testClient("", "", ""))
		req := IssueRequest{CSRPEM: pcaCSR(t)}
		if name == "bad csr arg" {
			req.CSRPEM = "not a csr"
		}
		if _, err := c.Issue(context.Background(), req); err == nil {
			t.Fatalf("%s: expected error", name)
		}
		if name != "bad csr arg" {
			if h := c.Health(context.Background()); h.Status != "degraded" {
				t.Fatalf("%s: health %+v", name, h)
			}
		}
	}
	if len(f.targets) != 0 {
		t.Fatalf("invalid config must not reach AWS: %v", f.targets)
	}
}

func TestAWSPCARefusesUnparseableCertificate(t *testing.T) {
	f := newPCAFixture(t)
	f.leaf = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	c := f.connector(func(cfg *AWSPCAConfig) { cfg.SigningAlgorithm = "SHA256WITHECDSA" })
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: pcaCSR(t)}); err == nil {
		t.Fatal("garbage certificate must be refused")
	}
}
