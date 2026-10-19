package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
)

func ariCertID(cert *x509.Certificate) string {
	return base64.RawURLEncoding.EncodeToString(cert.AuthorityKeyId) + "." +
		base64.RawURLEncoding.EncodeToString(cert.SerialNumber.Bytes())
}

func ariGet(t *testing.T, baseURL, certID string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(baseURL + "/acme/renewalInfo/" + certID)
	if err != nil {
		t.Fatalf("GET renewalInfo: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func ariWindowOf(t *testing.T, baseURL, certID string) (start, end time.Time) {
	t.Helper()
	resp, body := ariGet(t, baseURL, certID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	var r RenewalInfoResponse
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	start, err := time.Parse(time.RFC3339, r.SuggestedWindow.Start)
	if err != nil {
		t.Fatal(err)
	}
	end, err = time.Parse(time.RFC3339, r.SuggestedWindow.End)
	if err != nil {
		t.Fatal(err)
	}
	return start, end
}

// seedARICert issues a certificate through the CA engine and records it (and
// its order) in the server's store, bypassing the ACME protocol.
func seedARICert(t *testing.T, srv *Server, engine ca.Service, account string, names []string, validity time.Duration) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := engine.IssueCertificate(srv.caID, ca.IssuanceRequest{
		CSR: csr, Validity: validity, DNSNames: names,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	id := generateID("cert")
	if err := srv.store.SaveCert(id, issued.CertPEM); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.SaveOrder(&Order{
		ID: generateID("order"), AccountID: account, Status: "valid",
		Certificate: srv.baseURL + "/acme/cert/" + id,
	}); err != nil {
		t.Fatal(err)
	}
	return issued.Certificate
}

func TestARIWindow90DayCertStartsDay60EndsBeforeNotAfter(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := &x509.Certificate{NotBefore: nb, NotAfter: nb.Add(90 * 24 * time.Hour)}
	w := ariWindow(cert, nb.Add(time.Hour), false)
	start, _ := time.Parse(time.RFC3339, w.SuggestedWindow.Start)
	end, _ := time.Parse(time.RFC3339, w.SuggestedWindow.End)
	if !start.Equal(nb.Add(60 * 24 * time.Hour)) {
		t.Errorf("start = %v, want notBefore+60d", start)
	}
	if end.After(cert.NotAfter.Add(-7*24*time.Hour)) || !end.Before(cert.NotAfter) || !end.After(start) {
		t.Errorf("end = %v out of range", end)
	}
}

func TestARIWindowShortLivedCert(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := &x509.Certificate{NotBefore: nb, NotAfter: nb.Add(47 * 24 * time.Hour)}
	w := ariWindow(cert, nb, false)
	start, _ := time.Parse(time.RFC3339, w.SuggestedWindow.Start)
	end, _ := time.Parse(time.RFC3339, w.SuggestedWindow.End)
	if !start.Before(end) || !end.Before(cert.NotAfter) {
		t.Errorf("window %v..%v not ordered before notAfter %v", start, end, cert.NotAfter)
	}
}

func TestARICertIDParse(t *testing.T) {
	ok := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})
	big21 := base64.RawURLEncoding.EncodeToString(make([]byte, 21))
	cases := []struct {
		name, id string
		want     bool
	}{
		{"valid", ok + "." + ok, true},
		{"extra dot", ok + "." + ok + ".x", false},
		{"bad base64", "!!!." + ok, false},
		{"empty", "", false},
		{"empty serial", ok + ".", false},
		{"empty aki", "." + ok, false},
		{"no dot", ok, false},
		{"oversize serial", ok + "." + big21, false},
	}
	for _, c := range cases {
		if _, _, got := parseARICertID(c.id); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestARIHighBitSerialMatches(t *testing.T) {
	leaf := &x509.Certificate{SerialNumber: new(big.Int).SetBytes([]byte{0x80, 0x01, 0x02}), AuthorityKeyId: []byte{9, 9}}
	entries := []ariEntry{{order: &Order{}, leaf: leaf}}
	// DER INTEGER content carries a leading 0x00 for a high-bit serial.
	if findCertByARI(entries, []byte{9, 9}, []byte{0x00, 0x80, 0x01, 0x02}) == nil {
		t.Fatal("high-bit serial with DER leading zero not found")
	}
	if findCertByARI(entries, []byte{9, 9}, []byte{0x80, 0x01, 0x02}) == nil {
		t.Fatal("high-bit serial without leading zero not found")
	}
	if findCertByARI(entries, []byte{1, 1}, []byte{0x80, 0x01, 0x02}) != nil {
		t.Fatal("wrong AKI must not match")
	}
	leaf.AuthorityKeyId = nil
	if findCertByARI(entries, nil, []byte{0x80, 0x01, 0x02}) != nil {
		t.Fatal("cert without AKI must never match")
	}
}

func TestARIRevokedViaACMEReturnsRenewNow(t *testing.T) {
	srv, ts, engine, _ := newTestACMEServerWithRevStore(t)
	cert := seedARICert(t, srv, engine, "acct1", []string{"a.example.test"}, 90*24*time.Hour)
	_, end := ariWindowOf(t, ts.URL, ariCertID(cert))
	if end.Before(time.Now().Add(24 * time.Hour)) {
		t.Fatalf("unrevoked cert should not renew now, end=%v", end)
	}
	srv.mu.Lock()
	srv.revoked[certFingerprint(cert)] = revocationRecord{RevokedAt: time.Now()}
	srv.mu.Unlock()
	_, end = ariWindowOf(t, ts.URL, ariCertID(cert))
	if end.After(time.Now().Add(time.Second)) {
		t.Fatalf("revoked cert end = %v, want <= now", end)
	}
}

func TestARIRevokedViaRevStoreReturnsRenewNow(t *testing.T) {
	srv, ts, engine, revStore := newTestACMEServerWithRevStore(t)
	cert := seedARICert(t, srv, engine, "acct1", []string{"b.example.test"}, 90*24*time.Hour)
	if err := revStore.Revoke(cert.SerialNumber, srv.caID, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, end := ariWindowOf(t, ts.URL, ariCertID(cert))
	if end.After(time.Now().Add(time.Second)) {
		t.Fatalf("end = %v, want <= now", end)
	}
}

func TestARISupersededReturnsRenewNow(t *testing.T) {
	srv, ts, engine, _ := newTestACMEServerWithRevStore(t)
	names := []string{"s2.example.test", "s1.example.test"}
	old := seedARICert(t, srv, engine, "acct1", names, 90*24*time.Hour)
	other := seedARICert(t, srv, engine, "acct2", names, 90*24*time.Hour)
	time.Sleep(1100 * time.Millisecond) // NotBefore has 1s granularity
	newer := seedARICert(t, srv, engine, "acct1", []string{"s1.example.test", "s2.example.test"}, 90*24*time.Hour)

	_, end := ariWindowOf(t, ts.URL, ariCertID(old))
	if end.After(time.Now().Add(time.Second)) {
		t.Fatalf("superseded end = %v, want <= now", end)
	}
	// A different account's cert, and the newest cert, are not superseded.
	for name, c := range map[string]*x509.Certificate{"other account": other, "newest": newer} {
		if _, e := ariWindowOf(t, ts.URL, ariCertID(c)); e.Before(time.Now().Add(24 * time.Hour)) {
			t.Errorf("%s must not be renew-now, end=%v", name, e)
		}
	}
	// Revoking the replacement un-supersedes the old cert.
	srv.mu.Lock()
	srv.revoked[certFingerprint(newer)] = revocationRecord{RevokedAt: time.Now()}
	srv.mu.Unlock()
	if _, e := ariWindowOf(t, ts.URL, ariCertID(old)); e.Before(time.Now().Add(24 * time.Hour)) {
		t.Errorf("old cert with revoked replacement must not be renew-now, end=%v", e)
	}
}

func TestARIUnknownSerialWrongAKIMalformedAreIdentical404(t *testing.T) {
	srv, ts, engine, _ := newTestACMEServerWithRevStore(t)
	cert := seedARICert(t, srv, engine, "acct1", []string{"c.example.test"}, 90*24*time.Hour)
	b64 := base64.RawURLEncoding.EncodeToString
	ids := map[string]string{
		"unknown serial": b64(cert.AuthorityKeyId) + "." + b64([]byte{0x7f, 0x01}),
		"wrong aki":      b64([]byte("not-the-issuer")) + "." + b64(cert.SerialNumber.Bytes()),
		"malformed":      "garbage",
	}
	var refStatus int
	var refType string
	var refBody []byte
	for name, id := range ids {
		resp, body := ariGet(t, ts.URL, id)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: status %d", name, resp.StatusCode)
		}
		if resp.Header.Get("Retry-After") != "" {
			t.Errorf("%s: unexpected Retry-After", name)
		}
		if refBody == nil {
			refStatus, refType, refBody = resp.StatusCode, resp.Header.Get("Content-Type"), body
			if refType != "application/problem+json" {
				t.Errorf("content-type = %q", refType)
			}
			continue
		}
		if resp.StatusCode != refStatus || resp.Header.Get("Content-Type") != refType || string(body) != string(refBody) {
			t.Errorf("%s: response differs: %q vs %q", name, body, refBody)
		}
	}
}

func TestARIMassRevocationAllRenewNow(t *testing.T) {
	srv, ts, engine, revStore := newTestACMEServerWithRevStore(t)
	const n = 20
	certs := make([]*x509.Certificate, n)
	for i := range certs {
		certs[i] = seedARICert(t, srv, engine, "acct1", []string{fmt.Sprintf("m%d.example.test", i)}, 90*24*time.Hour)
	}
	for i, c := range certs {
		if err := revStore.Revoke(c.SerialNumber, srv.caID, 1, time.Now()); err != nil {
			t.Fatalf("revoke %d: %v", i, err)
		}
	}
	for i, c := range certs {
		if _, end := ariWindowOf(t, ts.URL, ariCertID(c)); end.After(time.Now().Add(time.Second)) {
			t.Errorf("cert %d end = %v, want <= now", i, end)
		}
	}
}

func TestARIRetryAfterIsDeltaSeconds(t *testing.T) {
	srv, ts, engine, _ := newTestACMEServerWithRevStore(t)
	cert := seedARICert(t, srv, engine, "acct1", []string{"d.example.test"}, 90*24*time.Hour)
	resp, _ := ariGet(t, ts.URL, ariCertID(cert))
	ra := resp.Header.Get("Retry-After")
	if n, err := strconv.Atoi(ra); err != nil || n <= 0 {
		t.Fatalf("Retry-After = %q, want positive delta-seconds", ra)
	}
	if resp.Header.Get("Replay-Nonce") == "" {
		t.Error("missing Replay-Nonce")
	}
}
