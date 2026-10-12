// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
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
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/egress"
)

// FG-1 (OWASP-A04-001, A10-001, A04-002, A03-2, A04-004): ACME issues only
// for validated DNS names, validation cannot be aimed at internal services,
// and weak keys are refused.

const (
	problemUnsupportedIdentifier = "urn:ietf:params:acme:error:unsupportedIdentifier"
	problemRejectedIdentifier    = "urn:ietf:params:acme:error:rejectedIdentifier"
	problemBadCSR                = "urn:ietf:params:acme:error:badCSR"
)

// keyAuthHandler serves the correct KeyAuthorization for any token.
func keyAuthHandler(t *testing.T, client *acmeTestClient) http.Handler {
	thumb := client.thumbprint(t)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		_, _ = w.Write([]byte(parts[len(parts)-1] + "." + thumb))
	})
}

func postNewOrder(t *testing.T, ts *httptest.Server, client *acmeTestClient, idents []Identifier) (*http.Response, Order, Problem) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"identifiers": idents})
	resp := client.postJWS(t, ts, ts.URL+"/acme/new-order", payload)
	defer resp.Body.Close()
	var order Order
	var prob Problem
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)
	if resp.StatusCode == http.StatusCreated {
		_ = json.Unmarshal(body.Bytes(), &order)
	} else {
		_ = json.Unmarshal(body.Bytes(), &prob)
	}
	return resp, order, prob
}

func dnsIdents(names ...string) []Identifier {
	out := make([]Identifier, len(names))
	for i, n := range names {
		out[i] = Identifier{Type: "dns", Value: n}
	}
	return out
}

func getAuthz(t *testing.T, url string) Authorization {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get authz: %v", err)
	}
	defer resp.Body.Close()
	var a Authorization
	_ = json.NewDecoder(resp.Body).Decode(&a)
	return a
}

func getOrder(t *testing.T, url string) Order {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get order: %v", err)
	}
	defer resp.Body.Close()
	var o Order
	_ = json.NewDecoder(resp.Body).Decode(&o)
	return o
}

func challengeOf(a Authorization, typ string) (Challenge, bool) {
	for _, c := range a.Challenges {
		if c.Type == typ {
			return c, true
		}
	}
	return Challenge{}, false
}

// readyOrderFor creates an order for names (each already routed to a
// key-authorization host) and solves http-01 for all of them.
func readyOrderFor(t *testing.T, ts *httptest.Server, client *acmeTestClient, names ...string) Order {
	t.Helper()
	resp, order, prob := postNewOrder(t, ts, client, dnsIdents(names...))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("new-order: %d %+v", resp.StatusCode, prob)
	}
	orderURL := resp.Header.Get("Location")
	for _, au := range order.Authorizations {
		ch, ok := challengeOf(getAuthz(t, au), "http-01")
		if !ok {
			t.Fatal("no http-01 challenge")
		}
		r := client.postJWS(t, ts, ch.URL, []byte("{}"))
		r.Body.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if o := getOrder(t, orderURL); o.Status == "ready" {
			o.Finalize = order.Finalize
			return o
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("order never became ready")
	return Order{}
}

type csrSpec struct {
	key    crypto.Signer
	cn     string
	dns    []string
	ips    []net.IP
	uris   []*url.URL
	emails []string
}

func (c csrSpec) der(t *testing.T) []byte {
	t.Helper()
	key := c.key
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: c.cn},
		DNSNames:       c.dns,
		IPAddresses:    c.ips,
		URIs:           c.uris,
		EmailAddresses: c.emails,
	}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return der
}

func finalizeWith(t *testing.T, ts *httptest.Server, client *acmeTestClient, o Order, csrDER []byte) (int, Problem, Order) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"csr": base64.RawURLEncoding.EncodeToString(csrDER)})
	resp := client.postJWS(t, ts, o.Finalize, payload)
	defer resp.Body.Close()
	var prob Problem
	var final Order
	if resp.StatusCode == http.StatusOK {
		_ = json.NewDecoder(resp.Body).Decode(&final)
	} else {
		_ = json.NewDecoder(resp.Body).Decode(&prob)
	}
	return resp.StatusCode, prob, final
}

func fetchCert(t *testing.T, o Order) *x509.Certificate {
	t.Helper()
	resp, err := http.Get(o.Certificate)
	if err != nil {
		t.Fatalf("get cert: %v", err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	der, _ := decodePEM(buf.Bytes())
	if der == nil {
		t.Fatal("no PEM certificate")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func TestACMENewOrderRejectsNonDNSIdentifier(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()
	client := newACMEAccount(t, ts)

	for _, ident := range []Identifier{
		{Type: "ip", Value: "127.0.0.1"},
		{Type: "ip", Value: "10.0.0.5"},
		{Type: "email", Value: "a@example.com"},
		{Type: "", Value: "shop.example.test"},
	} {
		resp, _, prob := postNewOrder(t, ts, client, []Identifier{ident})
		if resp.StatusCode != http.StatusBadRequest || prob.Type != problemUnsupportedIdentifier {
			t.Errorf("%+v: status=%d problem=%q, want 400 %s", ident, resp.StatusCode, prob.Type, problemUnsupportedIdentifier)
		}
	}
}

func TestACMENewOrderRejectsInvalidDNSValues(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()
	client := newACMEAccount(t, ts)

	long := strings.Repeat("a", 64) + ".example.test"
	tooLong := strings.Repeat("abcdefghi.", 26) + "test" // > 253
	for name, v := range map[string]string{
		"ipv4 literal":      "127.0.0.1",
		"ipv4 non-canon":    "127.1",
		"ipv6 literal":      "::1",
		"host:port":         "shop.example.test:8080",
		"underscore":        "_dmarc.example.test",
		"localhost":         "localhost",
		"localhost suffix":  "app.localhost",
		"single-label wild": "*.corp",
		"too long":          tooLong,
		"label over 63":     long,
		"nested wildcard":   "*.*.example.test",
		"wildcard one lbl":  "*.test",
		"mid wildcard":      "a.*.example.test",
		"trailing dot":      "shop.example.test.",
		"leading hyphen":    "-a.example.test",
		"trailing hyphen":   "a-.example.test",
		"empty label":       "a..example.test",
		"empty":             "",
		"space":             "a b.example.test",
		"unicode":           "bücher.example.test",
		"path":              "shop.example.test/x",
		"userinfo":          "u@shop.example.test",
		"bare wildcard dot": "*.",
	} {
		resp, _, prob := postNewOrder(t, ts, client, dnsIdents(v))
		if resp.StatusCode != http.StatusBadRequest || prob.Type != problemRejectedIdentifier {
			t.Errorf("%s (%q): status=%d problem=%q, want 400 %s", name, v, resp.StatusCode, prob.Type, problemRejectedIdentifier)
		}
	}
}

func TestACMENewOrderNormalisesAndDeduplicates(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()
	client := newACMEAccount(t, ts)

	resp, order, prob := postNewOrder(t, ts, client, dnsIdents("Shop.Example.TEST", "shop.example.test", "api.example.test"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d %+v", resp.StatusCode, prob)
	}
	if len(order.Identifiers) != 2 || order.Identifiers[0].Value != "shop.example.test" || len(order.Authorizations) != 2 {
		t.Fatalf("identifiers not normalised/deduplicated: %+v authz=%d", order.Identifiers, len(order.Authorizations))
	}
}

func TestACMEWildcardOffersOnlyDNS01(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()
	client := newACMEAccount(t, ts)

	resp, order, prob := postNewOrder(t, ts, client, dnsIdents("*.zone.example.test", "plain.example.test"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d %+v", resp.StatusCode, prob)
	}
	var sawWildcard, sawPlain bool
	for _, au := range order.Authorizations {
		a := getAuthz(t, au)
		_, hasHTTP := challengeOf(a, "http-01")
		_, hasDNS := challengeOf(a, "dns-01")
		if a.Wildcard {
			sawWildcard = true
			if a.Identifier.Value != "zone.example.test" {
				t.Errorf("wildcard authz identifier = %q, want the base domain", a.Identifier.Value)
			}
			if hasHTTP || !hasDNS || len(a.Challenges) != 1 {
				t.Errorf("wildcard authz challenges = %+v, want dns-01 only (RFC 8555 §8.3)", a.Challenges)
			}
		} else {
			sawPlain = true
			if !hasHTTP || !hasDNS {
				t.Errorf("plain authz challenges = %+v, want http-01 and dns-01", a.Challenges)
			}
		}
	}
	if !sawWildcard || !sawPlain {
		t.Fatalf("wildcard=%v plain=%v", sawWildcard, sawPlain)
	}
}

func TestACMEWildcardDNS01ChecksBaseName(t *testing.T) {
	srv, ts := newTestACMEServer(t)
	defer ts.Close()
	client := newACMEAccount(t, ts)

	var mu sync.Mutex
	var looked []string
	var digest string
	srv.SetTXTResolver(func(name string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		looked = append(looked, name)
		return []string{digest}, nil
	})

	_, order, _ := postNewOrder(t, ts, client, dnsIdents("*.zone.example.test"))
	a := getAuthz(t, order.Authorizations[0])
	ch, ok := challengeOf(a, "dns-01")
	if !ok {
		t.Fatal("no dns-01 challenge")
	}
	sum := sha256.Sum256([]byte(ch.Token + "." + client.thumbprint(t)))
	mu.Lock()
	digest = base64.RawURLEncoding.EncodeToString(sum[:])
	mu.Unlock()
	r := client.postJWS(t, ts, ch.URL, []byte("{}"))
	r.Body.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && getAuthz(t, order.Authorizations[0]).Status != "valid" {
		time.Sleep(25 * time.Millisecond)
	}
	if getAuthz(t, order.Authorizations[0]).Status != "valid" {
		t.Fatal("wildcard dns-01 did not validate")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(looked) != 1 || looked[0] != "_acme-challenge.zone.example.test" {
		t.Fatalf("TXT lookups = %v, want [_acme-challenge.zone.example.test]", looked)
	}
}

func TestACMEFinalizeIssuesExactlyOrderIdentifiers(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()
	client := newACMEAccount(t, ts)

	a := startChallengeHost(t, keyAuthHandler(t, client))
	b := startChallengeHost(t, keyAuthHandler(t, client))
	want := []string{a, b}
	sort.Strings(want)

	o := readyOrderFor(t, ts, client, b, a)
	// Mixed-case CN equal to one identifier: RFC 8555 §7.4 compares case-insensitively.
	status, prob, final := finalizeWith(t, ts, client, o, csrSpec{cn: strings.ToUpper(b), dns: []string{a, b}}.der(t))
	if status != http.StatusOK || final.Status != "valid" {
		t.Fatalf("finalize: %d %+v order=%q", status, prob, final.Status)
	}
	cert := fetchCert(t, final)
	got := append([]string(nil), cert.DNSNames...)
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("cert DNS SANs = %v, want exactly %v", got, want)
	}
	if len(cert.IPAddresses) != 0 || len(cert.URIs) != 0 || len(cert.EmailAddresses) != 0 {
		t.Errorf("cert carries non-DNS SANs: ips=%v uris=%v emails=%v", cert.IPAddresses, cert.URIs, cert.EmailAddresses)
	}
	if cert.Subject.CommonName != want[0] {
		t.Errorf("CN = %q, want first sorted identifier %q", cert.Subject.CommonName, want[0])
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("EKU = %v, want serverAuth only", cert.ExtKeyUsage)
	}
}

// A CSR with no CN and just the SANs, or just a CN, is equally valid: the
// union of SANs and CN must equal the identifier set.
func TestACMEFinalizeAcceptsCNOnlyAndSANOnlyCSR(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()
	client := newACMEAccount(t, ts)

	for name, spec := range map[string]func(h string) csrSpec{
		"cn only":  func(h string) csrSpec { return csrSpec{cn: h} },
		"san only": func(h string) csrSpec { return csrSpec{dns: []string{h}} },
	} {
		h := startChallengeHost(t, keyAuthHandler(t, client))
		o := readyOrderFor(t, ts, client, h)
		status, prob, final := finalizeWith(t, ts, client, o, spec(h).der(t))
		if status != http.StatusOK {
			t.Errorf("%s: %d %+v", name, status, prob)
			continue
		}
		if c := fetchCert(t, final); len(c.DNSNames) != 1 || c.DNSNames[0] != h || c.Subject.CommonName != h {
			t.Errorf("%s: cert names = %v / %q", name, c.DNSNames, c.Subject.CommonName)
		}
	}
}

func TestACMEFinalizeRejectsCSRBeyondOrderIdentifiers(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()
	client := newACMEAccount(t, ts)

	spiffe, _ := url.Parse("spiffe://corp.example.test/ns/prod/sa/admin")
	cases := map[string]func(h string) csrSpec{
		"extra dns san": func(h string) csrSpec { return csrSpec{cn: h, dns: []string{h, "victim.example.test"}} },
		"wildcard san":  func(h string) csrSpec { return csrSpec{cn: h, dns: []string{h, "*.example.test"}} },
		"ip san": func(h string) csrSpec {
			return csrSpec{cn: h, dns: []string{h}, ips: []net.IP{net.ParseIP("10.1.2.3")}}
		},
		"uri san":      func(h string) csrSpec { return csrSpec{cn: h, dns: []string{h}, uris: []*url.URL{spiffe}} },
		"email san":    func(h string) csrSpec { return csrSpec{cn: h, dns: []string{h}, emails: []string{"a@example.test"}} },
		"different cn": func(h string) csrSpec { return csrSpec{cn: "admin.example.test", dns: []string{h}} },
		"unrelated name": func(h string) csrSpec {
			return csrSpec{cn: "victim.example.test", dns: []string{"victim.example.test"}}
		},
		"no names": func(h string) csrSpec { return csrSpec{} },
	}
	for name, mk := range cases {
		h := startChallengeHost(t, keyAuthHandler(t, client))
		o := readyOrderFor(t, ts, client, h)
		status, prob, _ := finalizeWith(t, ts, client, o, mk(h).der(t))
		if status != http.StatusBadRequest || prob.Type != problemBadCSR {
			t.Errorf("%s: status=%d problem=%q, want 400 badCSR", name, status, prob.Type)
		}
		if st := getOrder(t, ts.URL+"/acme/order/"+o.ID).Status; st != "invalid" {
			t.Errorf("%s: order status = %q, want invalid", name, st)
		}
	}
}

func TestACMEFinalizeRejectsMissingIdentifierInCSR(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()
	client := newACMEAccount(t, ts)

	a := startChallengeHost(t, keyAuthHandler(t, client))
	b := startChallengeHost(t, keyAuthHandler(t, client))
	o := readyOrderFor(t, ts, client, a, b)
	status, prob, _ := finalizeWith(t, ts, client, o, csrSpec{cn: a, dns: []string{a}}.der(t))
	if status != http.StatusBadRequest || prob.Type != problemBadCSR {
		t.Fatalf("status=%d problem=%q, want 400 badCSR (RFC 8555 §7.4: CSR must cover every identifier)", status, prob.Type)
	}
}

func TestACMEFinalizeRejectsAccountKeyReuse(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()
	client := newACMEAccount(t, ts)

	h := startChallengeHost(t, keyAuthHandler(t, client))
	o := readyOrderFor(t, ts, client, h)
	status, prob, _ := finalizeWith(t, ts, client, o, csrSpec{key: client.priv, cn: h, dns: []string{h}}.der(t))
	if status != http.StatusBadRequest || prob.Type != problemBadCSR {
		t.Fatalf("status=%d problem=%q, want 400 badCSR for a CSR on the account key", status, prob.Type)
	}
}

func TestACMEFinalizeKeyStrength(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()
	client := newACMEAccount(t, ts)

	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // deliberately weak: must be refused
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for name, c := range map[string]struct {
		key crypto.Signer
		ok  bool
	}{
		"rsa-1024": {rsa1024, false},
		"p-224":    {p224, false},
		"rsa-2048": {rsa2048, true},
		"p-384":    {p384, true},
	} {
		h := startChallengeHost(t, keyAuthHandler(t, client))
		o := readyOrderFor(t, ts, client, h)
		status, prob, _ := finalizeWith(t, ts, client, o, csrSpec{key: c.key, cn: h, dns: []string{h}}.der(t))
		if c.ok && status != http.StatusOK {
			t.Errorf("%s: want issued, got %d %+v", name, status, prob)
		}
		if !c.ok && (status != http.StatusBadRequest || prob.Type != problemBadCSR || !strings.Contains(prob.Detail, "key too weak")) {
			t.Errorf("%s: status=%d problem=%+v, want 400 badCSR key too weak", name, status, prob)
		}
	}
}

// solveHTTP01 orders name, answers its http-01 challenge and returns the
// authorization's final status.
func solveHTTP01(t *testing.T, ts *httptest.Server, client *acmeTestClient, name string) string {
	t.Helper()
	resp, order, prob := postNewOrder(t, ts, client, dnsIdents(name))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("new-order %q: %d %+v", name, resp.StatusCode, prob)
	}
	ch, _ := challengeOf(getAuthz(t, order.Authorizations[0]), "http-01")
	r := client.postJWS(t, ts, ch.URL, []byte("{}"))
	r.Body.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st := getAuthz(t, order.Authorizations[0]).Status; st != "pending" && st != "processing" {
			return st
		}
		time.Sleep(25 * time.Millisecond)
	}
	return "timeout"
}

func TestACMEHTTP01RedirectPolicy(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()
	client := newACMEAccount(t, ts)

	good := startChallengeHost(t, keyAuthHandler(t, client))
	// A loopback server that would satisfy validation if the CA ever reached it.
	loopback := httptest.NewServer(keyAuthHandler(t, client))
	defer loopback.Close()

	redirectTo := func(target func(path string) string) string {
		return startChallengeHost(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target(r.URL.Path), http.StatusFound)
		}))
	}

	// Positive control: a redirect to another host on the default port is
	// followed, so the refusals below are the guard's doing.
	if st := solveHTTP01(t, ts, client, redirectTo(func(p string) string { return "http://" + good + p })); st != "valid" {
		t.Fatalf("redirect to an ordinary host on port 80: authz = %q, want valid", st)
	}
	for name, target := range map[string]func(string) string{
		"loopback ip":    func(p string) string { return loopback.URL + p },
		"cloud metadata": func(p string) string { return "http://169.254.169.254" + p },
		"other port":     func(p string) string { return "http://" + good + ":8080" + p },
		"other scheme":   func(p string) string { return "ftp://" + good + p },
	} {
		if st := solveHTTP01(t, ts, client, redirectTo(target)); st != "invalid" {
			t.Errorf("redirect to %s: authz = %q, want invalid", name, st)
		}
	}
}

func TestHTTP01GuardRefusesInternalAddresses(t *testing.T) {
	for addr, refused := range map[string]bool{
		"127.0.0.1:80":          true,
		"127.9.9.9:80":          true,
		"[::1]:80":              true,
		"169.254.169.254:80":    true,
		"[fe80::1]:80":          true,
		"0.0.0.0:80":            true,
		"[::]:80":               true,
		"224.0.0.1:80":          true,
		"[ff02::1]:80":          true,
		"[::ffff:127.0.0.1]:80": true,
		// FB-11: forms the old local copy let through.
		"[64:ff9b::7f00:1]:80":    true,  // NAT64-embedded 127.0.0.1
		"[64:ff9b::a9fe:a9fe]:80": true,  // NAT64-embedded metadata
		"0.0.0.1:80":              true,  // 0.0.0.0/8
		"[64:ff9b:1::7f00:1]:80":  true,  // RFC 8215 local-use NAT64
		"[64:ff9b::a00:5]:80":     false, // NAT64-embedded 10.0.0.5: RFC1918 stays reachable
		"10.0.0.5:80":             false,
		"172.16.0.9:80":           false,
		"192.168.1.20:80":         false,
		"[fd00::5]:80":            false,
		"93.184.216.34:80":        false,
		"[2606:2800:220:1::1]:80": false,
	} {
		err := http01DialControl()("tcp", addr, nil)
		if refused && err == nil {
			t.Errorf("%s: want refused", addr)
		}
		if !refused && err != nil {
			t.Errorf("%s: want allowed, got %v", addr, err)
		}
	}
}

func TestHTTP01DefaultClientRefusesLoopbackAndMetadata(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("reached"))
	}))
	defer local.Close()

	client := newHTTP01Client(nil)
	for _, target := range []string{local.URL + "/x", "http://169.254.169.254/latest/meta-data/", "http://[::1]/x"} {
		resp, err := client.Get(target)
		if err == nil {
			resp.Body.Close()
			t.Errorf("GET %s succeeded; the default client must refuse it", target)
			continue
		}
		if !errors.Is(err, egress.ErrBlockedDestination) {
			t.Errorf("GET %s failed for the wrong reason: %v", target, err)
		}
	}
}

func TestHTTP01CheckRedirect(t *testing.T) {
	hop := func(rawurl string, via int) error {
		u, _ := url.Parse(rawurl)
		return http01CheckRedirect(&http.Request{URL: u}, make([]*http.Request, via))
	}
	for _, ok := range []string{"http://a.example.test/x", "https://a.example.test:443/x", "http://a.example.test:80/x"} {
		if err := hop(ok, 1); err != nil {
			t.Errorf("redirect to %s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://a.example.test:8080/x", "https://a.example.test:8443/x", "ftp://a.example.test/x", "file:///tmp/x", "gopher://a.example.test/"} {
		if err := hop(bad, 1); err == nil {
			t.Errorf("redirect to %s allowed", bad)
		}
	}
	if err := hop("http://a.example.test/x", 9); err != nil {
		t.Errorf("10th redirect refused: %v", err)
	}
	if err := hop("http://a.example.test/x", 10); err == nil {
		t.Error("11th redirect allowed")
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// The validation body is attacker-controlled and the fetch unauthenticated:
// it must not be echoed to the log (OWASP-A10-001).
func TestACMEHTTP01DoesNotLogResponseBody(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()
	client := newACMEAccount(t, ts)

	var buf bytes.Buffer
	var mu sync.Mutex
	prev := log.Writer()
	log.SetOutput(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return buf.Write(p) }))
	t.Cleanup(func() { log.SetOutput(prev) })

	h := startChallengeHost(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("INTERNAL-SECRET-BODY-12345"))
	}))
	if st := solveHTTP01(t, ts, client, h); st != "invalid" {
		t.Fatalf("authz = %q, want invalid", st)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(buf.String(), "INTERNAL-SECRET-BODY") {
		t.Errorf("response body leaked into the log: %s", buf.String())
	}
	if !strings.Contains(buf.String(), fmt.Sprintf("%q", h)) {
		t.Errorf("identifier not logged with %%q: %s", buf.String())
	}
}

// An internal CA serves intranet hosts with single-label names; the live
// certbot/lego harness found the first FG-1 cut refusing them.
func TestACMENewOrderAcceptsSingleLabelIntranetName(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()
	client := newACMEAccount(t, ts)
	resp, _, prob := postNewOrder(t, ts, client, dnsIdents("fileserver"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("single-label name: status=%d problem=%q, want 201", resp.StatusCode, prob.Type)
	}
	resp, _, prob = postNewOrder(t, ts, client, dnsIdents("2130706433"))
	if resp.StatusCode != http.StatusBadRequest || prob.Type != problemRejectedIdentifier {
		t.Errorf("all-numeric single label (an IPv4 integer form): status=%d problem=%q, want rejected", resp.StatusCode, prob.Type)
	}
}
