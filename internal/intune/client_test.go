// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package intune

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/egress"
)

const fakeSecret = "s3cret-value-for-tests"

// fakeIntune stands in for Entra, Graph and the Intune validation service on
// one TLS listener. Its paths mirror the real contract.
type fakeIntune struct {
	srv *httptest.Server

	mu          sync.Mutex
	tokenCalls  map[string]int // by scope
	discoveries int
	posts       []map[string]any
	paths       []string
	headers     http.Header
	lastForm    map[string]string

	code         string // validate answer; "" = Success
	desc         string
	tokenStatus  int
	validateHTTP int
	graphMissing bool
	expiresIn    int
}

func newFake(t *testing.T) *fakeIntune {
	t.Helper()
	f := &fakeIntune{tokenCalls: map[string]int{}, expiresIn: 3600}
	mux := http.NewServeMux()
	mux.HandleFunc("/tenant-1/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.tokenCalls[r.Form.Get("scope")]++
		f.lastForm = map[string]string{}
		for k := range r.Form {
			f.lastForm[k] = r.Form.Get(k)
		}
		st, exp := f.tokenStatus, f.expiresIn
		f.mu.Unlock()
		if st != 0 {
			w.WriteHeader(st)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS7000215 secret ` + r.Form.Get("client_secret") + `"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-" + r.Form.Get("scope"), "expires_in": exp})
	})
	mux.HandleFunc("/v1.0/servicePrincipals/appId=0000000a-0000-0000-c000-000000000000/endpoints", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.discoveries++
		missing := f.graphMissing
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer tok-"+graphScope {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		list := []map[string]string{{"providerName": "Other", "uri": "https://other.invalid"}}
		if !missing {
			list = append(list, map[string]string{"providerName": "ScepRequestValidationFEService", "uri": f.srv.URL + "/svc/"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": list})
	})
	mux.HandleFunc("/svc/ScepActions/", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.posts = append(f.posts, body)
		f.paths = append(f.paths, r.URL.Path)
		f.headers = r.Header.Clone()
		code, desc, st := f.code, f.desc, f.validateHTTP
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer tok-"+intuneScope {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if st != 0 {
			w.WriteHeader(st)
			return
		}
		if code == "" || strings.HasSuffix(r.URL.Path, "Notification") {
			code = "Success"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "errorDescription": desc})
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIntune) manager(t *testing.T, payload string, now func() time.Time) *Manager {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	m, err := NewManager(Options{
		Authority: f.srv.URL, GraphURL: f.srv.URL, UserAgent: "Kryptkeeper/test", Now: now,
		HTTP: egress.NewClient(egress.Policy{AllowLoopback: true, RequireHTTPS: true, RootCAs: pool}),
		Resolve: func(_ context.Context, ref string) ([]byte, error) {
			if ref != "cred-1" {
				return nil, errors.New("no such credential")
			}
			return []byte(payload), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

var conn = Connection{TenantID: "tenant-1", ClientID: "client-1", CredentialRef: "cred-1", IssuingAuthority: "Kryptkeeper Test CA"}

const secretPayload = `{"client_secret":"` + fakeSecret + `"}`

func testCert(t *testing.T) *x509.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(0xABCDEF), Subject: pkix.Name{CommonName: "dev"}, NotBefore: time.Now(), NotAfter: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestValidateSuccessSendsContract(t *testing.T) {
	f := newFake(t)
	m := f.manager(t, secretPayload, nil)
	csr := []byte{1, 2, 3}
	if err := m.Validate(context.Background(), conn, "tx-1", csr); err != nil {
		t.Fatal(err)
	}
	if f.paths[0] != "/svc/ScepActions/validateRequest" {
		t.Fatalf("path %q", f.paths[0])
	}
	req := f.posts[0]["request"].(map[string]any)
	if req["transactionId"] != "tx-1" || req["certificateRequest"] != base64.StdEncoding.EncodeToString(csr) || req["callerInfo"] != "Kryptkeeper/test" {
		t.Fatalf("body %v", req)
	}
	if f.headers.Get("api-version") != "2018-02-20" || f.headers.Get("client-request-id") == "" || f.headers.Get("UserAgent") != "Kryptkeeper/test" {
		t.Fatalf("headers %v", f.headers)
	}
	if f.lastForm["grant_type"] != "client_credentials" || f.lastForm["client_secret"] != fakeSecret || f.lastForm["scope"] != intuneScope {
		t.Fatalf("token form %v", f.lastForm)
	}
}

func TestValidateRefusalCarriesCode(t *testing.T) {
	f := newFake(t)
	f.code, f.desc = "SubjectNameMismatch", "CN\x00 differs"
	err := f.manager(t, secretPayload, nil).Validate(context.Background(), conn, "tx", []byte{1})
	var se *ServiceError
	if !errors.As(err, &se) || se.Code != "SubjectNameMismatch" || strings.ContainsRune(se.Description, 0) {
		t.Fatalf("err %v", err)
	}
	if errors.Is(err, ErrUnavailable) {
		t.Fatal("a refusal is not an outage")
	}
}

func TestOutagesFailClosed(t *testing.T) {
	cases := map[string]func(*fakeIntune){
		"token refused":   func(f *fakeIntune) { f.tokenStatus = http.StatusUnauthorized },
		"service 500":     func(f *fakeIntune) { f.validateHTTP = http.StatusInternalServerError },
		"service missing": func(f *fakeIntune) { f.graphMissing = true },
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			set(f)
			err := f.manager(t, secretPayload, nil).Validate(context.Background(), conn, "tx", []byte{1})
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("err %v", err)
			}
			if strings.Contains(err.Error(), fakeSecret) {
				t.Fatal("secret leaked into the error")
			}
		})
	}
}

func TestUnreachableServerFailsClosed(t *testing.T) {
	f := newFake(t)
	m := f.manager(t, secretPayload, nil)
	f.srv.Close()
	if err := m.Validate(context.Background(), conn, "tx", []byte{1}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err %v", err)
	}
}

func TestEgressGuardBlocksLoopbackByDefault(t *testing.T) {
	f := newFake(t)
	m, _ := NewManager(Options{
		Authority: f.srv.URL, GraphURL: f.srv.URL,
		HTTP:    egress.NewClient(egress.Policy{RequireHTTPS: true}),
		Resolve: func(context.Context, string) ([]byte, error) { return []byte(secretPayload), nil },
	})
	err := m.Validate(context.Background(), conn, "tx", []byte{1})
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("err %v", err)
	}
}

func TestTokenAndLocationAreReused(t *testing.T) {
	f := newFake(t)
	m := f.manager(t, secretPayload, nil)
	for i := 0; i < 3; i++ {
		if err := m.Validate(context.Background(), conn, "tx", []byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	if f.tokenCalls[intuneScope] != 1 || f.tokenCalls[graphScope] != 1 || f.discoveries != 1 {
		t.Fatalf("tokens %v discoveries %d", f.tokenCalls, f.discoveries)
	}
}

func TestTokenRefreshedAfterExpiry(t *testing.T) {
	f := newFake(t)
	f.expiresIn = 3600
	now := time.Now()
	m := f.manager(t, secretPayload, func() time.Time { return now })
	_ = m.Validate(context.Background(), conn, "tx", []byte{1})
	now = now.Add(3600*time.Second - time.Minute) // inside the skew
	_ = m.Validate(context.Background(), conn, "tx", []byte{1})
	if f.tokenCalls[intuneScope] != 2 {
		t.Fatalf("want a refresh inside the skew, got %v", f.tokenCalls)
	}
}

func TestUnauthorizedDropsTokenAndRetriesOnce(t *testing.T) {
	f := newFake(t)
	m := f.manager(t, secretPayload, nil)
	if err := m.Validate(context.Background(), conn, "tx", []byte{1}); err != nil {
		t.Fatal(err)
	}
	// Revoke the cached token server-side by changing what the service accepts.
	f.mu.Lock()
	f.validateHTTP = http.StatusUnauthorized
	f.mu.Unlock()
	if err := m.Validate(context.Background(), conn, "tx", []byte{1}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err %v", err)
	}
	if f.tokenCalls[intuneScope] != 2 {
		t.Fatalf("expected one forced token refresh, got %v", f.tokenCalls)
	}
}

func TestSuccessNotificationFields(t *testing.T) {
	f := newFake(t)
	cert := testCert(t)
	csr := []byte{9, 9}
	if err := f.manager(t, secretPayload, nil).NotifySuccess(context.Background(), conn, "tx-9", csr, cert); err != nil {
		t.Fatal(err)
	}
	if f.paths[0] != "/svc/ScepActions/successNotification" {
		t.Fatalf("path %q", f.paths[0])
	}
	n := f.posts[0]["notification"].(map[string]any)
	if n["certificateSerialNumber"] != "ABCDEF" || n["issuingCertificateAuthority"] != "Kryptkeeper Test CA" ||
		n["certificateExpirationDateUtc"] != "2030-01-02T03:04:05.000Z" || len(n["certificateThumbprint"].(string)) != 40 ||
		n["transactionId"] != "tx-9" || n["certificateRequest"] != base64.StdEncoding.EncodeToString(csr) {
		t.Fatalf("notification %v", n)
	}
}

func TestFailureNotificationFields(t *testing.T) {
	f := newFake(t)
	if err := f.manager(t, secretPayload, nil).NotifyFailure(context.Background(), conn, "tx-2", []byte{1}, HResultFail, "issuance failed"); err != nil {
		t.Fatal(err)
	}
	n := f.posts[0]["notification"].(map[string]any)
	if f.paths[0] != "/svc/ScepActions/failureNotification" || n["hResult"] != float64(HResultFail) || n["errorDescription"] != "issuance failed" {
		t.Fatalf("%q %v", f.paths[0], n)
	}
}

func TestCertificateCredentialSendsSignedAssertion(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kk-intune"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	payload, _ := json.Marshal(map[string]string{
		"certificate_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"private_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
	})
	f := newFake(t)
	if err := f.manager(t, string(payload), nil).Validate(context.Background(), conn, "tx", []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, has := f.lastForm["client_secret"]; has || f.lastForm["client_assertion_type"] != clientAssertionType {
		t.Fatalf("form %v", f.lastForm)
	}
	parts := strings.Split(f.lastForm["client_assertion"], ".")
	if len(parts) != 3 {
		t.Fatal("not a JWT")
	}
	var h map[string]string
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(hb, &h)
	thumb := sha256.Sum256(der)
	if h["alg"] != "PS256" || h["x5t#S256"] != base64.RawURLEncoding.EncodeToString(thumb[:]) {
		t.Fatalf("header %v", h)
	}
	var c map[string]any
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(cb, &c)
	if c["iss"] != "client-1" || c["sub"] != "client-1" || c["aud"] != f.srv.URL+"/tenant-1/oauth2/v2.0/token" {
		t.Fatalf("claims %v", c)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		t.Fatalf("assertion signature: %v", err)
	}
}

func TestParseCredentialRejects(t *testing.T) {
	for name, p := range map[string]string{
		"empty":       `{}`,
		"not json":    `x`,
		"both":        `{"client_secret":"a","certificate_pem":"b","private_key_pem":"c"}`,
		"half cert":   `{"certificate_pem":"b"}`,
		"junk cert":   `{"certificate_pem":"b","private_key_pem":"c"}`,
		"no key part": `{"private_key_pem":"c"}`,
	} {
		_, err := ParseCredential([]byte(p))
		if !errors.Is(err, ErrCredential) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestBadConnectionRefused(t *testing.T) {
	f := newFake(t)
	m := f.manager(t, secretPayload, nil)
	bad := conn
	bad.TenantID = "../evil"
	if err := m.Validate(context.Background(), bad, "tx", []byte{1}); !errors.Is(err, ErrCredential) {
		t.Fatalf("err %v", err)
	}
	missing := conn
	missing.CredentialRef = "nope"
	if err := m.Validate(context.Background(), missing, "tx", []byte{1}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err %v", err)
	}
}
