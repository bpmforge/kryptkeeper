// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"kryptkeeper/internal/connectors"
)

// ---- RFC 2136 test server ---------------------------------------------------

type testRFC2136Server struct {
	addr string
	zone *memZone

	mu        sync.Mutex
	zoneName  string // the one zone this server is authoritative for
	forceRC   dnsmessage.RCode
	lastTime  time.Time
	requests  int
	macChecks int
}

// newTestRFC2136Server serves UPDATE over TCP for example.test. It verifies
// the TSIG MAC with its own implementation of RFC 8945 (not signTSIG).
func newTestRFC2136Server(t *testing.T, zone *memZone, keyName string, secret []byte) *testRFC2136Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testRFC2136Server{addr: ln.Addr().String(), zone: zone, zoneName: "example.test."}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				raw := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, raw); err != nil {
					return
				}
				id, rc := s.handle(raw, keyName, secret)
				b := dnsmessage.NewBuilder(make([]byte, 2, 64), dnsmessage.Header{ID: id, Response: true, OpCode: 5, RCode: rc})
				out, _ := b.Finish()
				binary.BigEndian.PutUint16(out[:2], uint16(len(out)-2))
				_, _ = c.Write(out)
			}()
		}
	}()
	return s
}

func wireLower(name string) []byte {
	var out []byte
	for _, l := range strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".") {
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	return append(out, 0)
}

func (s *testRFC2136Server) handle(raw []byte, keyName string, secret []byte) (uint16, dnsmessage.RCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	var p dnsmessage.Parser
	h, err := p.Start(raw)
	if err != nil || h.OpCode != 5 {
		return h.ID, 1
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 || qs[0].Type != dnsmessage.TypeSOA {
		return h.ID, 1
	}
	if err := p.SkipAllAnswers(); err != nil {
		return h.ID, 1
	}
	auths, err := p.AllAuthorities()
	if err != nil {
		return h.ID, 1
	}
	adds, err := p.AllAdditionals()
	if err != nil {
		return h.ID, 1
	}
	var tsig *dnsmessage.UnknownResource
	for _, a := range adds {
		if u, ok := a.Body.(*dnsmessage.UnknownResource); ok && u.Type == 250 {
			tsig = u
		}
	}
	if tsig == nil {
		return h.ID, 5 // REFUSED: unsigned
	}
	// rdata: alg(wire) time48 fudge2 maclen2 mac origid2 err2 other2
	rd := tsig.Data
	i := 0
	for rd[i] != 0 {
		i += int(rd[i]) + 1
	}
	i++
	algWire, t48, fudge := rd[:i], rd[i:i+6], rd[i+6:i+8]
	macLen := int(binary.BigEndian.Uint16(rd[i+8 : i+10]))
	gotMAC := rd[i+10 : i+10+macLen]
	secs := int64(binary.BigEndian.Uint64(append([]byte{0, 0}, t48...)))
	s.lastTime = time.Unix(secs, 0).UTC()

	tailLen := len(wireLower(keyName)) + 10 + len(rd)
	signed := append([]byte(nil), raw[:len(raw)-tailLen]...)
	binary.BigEndian.PutUint16(signed[10:12], binary.BigEndian.Uint16(signed[10:12])-1) // ARCOUNT without TSIG
	mac := hmac.New(sha256.New, secret)
	mac.Write(signed)
	mac.Write(wireLower(keyName))
	mac.Write([]byte{0, 255, 0, 0, 0, 0})
	mac.Write(algWire)
	mac.Write(t48)
	mac.Write(fudge)
	mac.Write([]byte{0, 0, 0, 0})
	s.macChecks++
	if !hmac.Equal(mac.Sum(nil), gotMAC) {
		return h.ID, 9 // NOTAUTH: bad signature
	}
	if s.forceRC != 0 {
		return h.ID, s.forceRC
	}
	if !strings.EqualFold(qs[0].Name.String(), s.zoneName) {
		return h.ID, 8 // NOTZONE
	}
	s.zone.mu.Lock()
	defer s.zone.mu.Unlock()
	for _, a := range auths {
		txt, ok := a.Body.(*dnsmessage.TXTResource)
		if !ok {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(a.Header.Name.String()), ".")
		v := strings.Join(txt.TXT, "")
		switch a.Header.Class {
		case dnsmessage.ClassINET:
			s.zone.txt[name] = append(s.zone.txt[name], v)
		case 254:
			var keep []string
			for _, e := range s.zone.txt[name] {
				if e != v {
					keep = append(keep, e)
				}
			}
			if len(keep) == 0 {
				delete(s.zone.txt, name)
			} else {
				s.zone.txt[name] = keep
			}
		}
	}
	return h.ID, 0
}

var (
	testTSIGSecret = []byte("tsig-secret-bytes-not-real-0123456789")
	testTSIGTime   = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
)

func rfc2136Adapter(t *testing.T, addr, zone string, secret []byte) *rfc2136DNS {
	t.Helper()
	d, _ := json.Marshal(map[string]string{
		"nameserver": addr, "zone": zone, "tsig_key_name": "KK-Key.", "tsig_secret": base64.StdEncoding.EncodeToString(secret),
	})
	p, err := newRFC2136DNSFromConfig(acmeConnectorConfig{}, acmeCredentialPayload{DNS: d})
	if err != nil {
		t.Fatal(err)
	}
	a := p.(*rfc2136DNS)
	a.now = func() time.Time { return testTSIGTime }
	return a
}

func TestRFC2136PresentAndCleanupWithTSIG(t *testing.T) {
	zone := &memZone{txt: map[string][]string{}}
	srv := newTestRFC2136Server(t, zone, "kk-key.", testTSIGSecret)
	a := rfc2136Adapter(t, srv.addr, "example.test", testTSIGSecret)
	const fqdn = "_acme-challenge.shop.example.test"

	z, cleanup, err := a.Present(context.Background(), fqdn, "digest-value")
	if err != nil {
		t.Fatal(err)
	}
	if z != "example.test" {
		t.Errorf("zone %q", z)
	}
	if got := zone.txt[fqdn]; len(got) != 1 || got[0] != "digest-value" {
		t.Fatalf("server state %v", zone.txt)
	}
	if !srv.lastTime.Equal(testTSIGTime) || srv.macChecks != 1 {
		t.Errorf("TSIG time %v, checks %d", srv.lastTime, srv.macChecks)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(zone.txt) != 0 {
		t.Errorf("TXT left after cleanup: %v", zone.txt)
	}
}

func TestRFC2136SharedNameKeepsOtherValue(t *testing.T) {
	const fqdn = "_acme-challenge.shop.example.test"
	zone := &memZone{txt: map[string][]string{fqdn: {"foreign"}}}
	srv := newTestRFC2136Server(t, zone, "kk-key.", testTSIGSecret)
	a := rfc2136Adapter(t, srv.addr, "example.test", testTSIGSecret)
	_, cleanup, err := a.Present(context.Background(), fqdn, "ours")
	if err != nil {
		t.Fatal(err)
	}
	if len(zone.txt[fqdn]) != 2 {
		t.Fatalf("both values must coexist: %v", zone.txt[fqdn])
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := zone.txt[fqdn]; len(got) != 1 || got[0] != "foreign" {
		t.Errorf("cleanup must remove only ours: %v", got)
	}
}

func TestRFC2136WrongSecretIsRefusedWithClearError(t *testing.T) {
	zone := &memZone{txt: map[string][]string{}}
	srv := newTestRFC2136Server(t, zone, "kk-key.", testTSIGSecret)
	a := rfc2136Adapter(t, srv.addr, "example.test", []byte("a-different-secret-entirely-xyz"))
	_, _, err := a.Present(context.Background(), "_acme-challenge.shop.example.test", "v")
	if err == nil || !strings.Contains(err.Error(), "rejected the TSIG signature") {
		t.Fatalf("want a TSIG rejection, got %v", err)
	}
	if len(zone.txt) != 0 {
		t.Errorf("a rejected update changed the zone: %v", zone.txt)
	}
	srv.mu.Lock()
	srv.forceRC = 5
	srv.mu.Unlock()
	good := rfc2136Adapter(t, srv.addr, "example.test", testTSIGSecret)
	if _, _, err := good.Present(context.Background(), "_acme-challenge.shop.example.test", "v"); err == nil || !strings.Contains(err.Error(), "update refused by") {
		t.Errorf("rcode 5: %v", err)
	}
}

func TestRFC2136NoSuchZone(t *testing.T) {
	zone := &memZone{txt: map[string][]string{}}
	srv := newTestRFC2136Server(t, zone, "kk-key.", testTSIGSecret)
	a := rfc2136Adapter(t, srv.addr, "other.test", testTSIGSecret)
	if _, _, err := a.Present(context.Background(), "_acme-challenge.shop.other.test", "v"); err == nil || !strings.Contains(err.Error(), "other.test is not a zone on") {
		t.Errorf("rcode 8: %v", err)
	}
	if _, _, err := a.Present(context.Background(), "_acme-challenge.shop.example.test", "v"); err == nil || !strings.Contains(err.Error(), "not inside the configured rfc2136 zone") {
		t.Errorf("name outside the configured zone: %v", err)
	}
	if srv.requests != 1 {
		t.Errorf("the outside-zone name must not reach the server (requests=%d)", srv.requests)
	}
}

func TestRFC2136ConfigValidation(t *testing.T) {
	good := map[string]string{"nameserver": "127.0.0.1", "zone": "example.test", "tsig_key_name": "k.", "tsig_secret": "c2VjcmV0"}
	with := func(k, v string) json.RawMessage {
		m := map[string]string{}
		for a, b := range good {
			m[a] = b
		}
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
		raw, _ := json.Marshal(m)
		return raw
	}
	for name, c := range map[string]struct {
		dns  json.RawMessage
		want string
	}{
		"no dns object": {nil, `needs a "dns" object`},
		"no nameserver": {with("nameserver", ""), `needs a "dns" object`},
		"no zone":       {with("zone", ""), `needs a "dns" object`},
		"no key name":   {with("tsig_key_name", ""), `needs a "dns" object`},
		"no secret":     {with("tsig_secret", ""), `needs a "dns" object`},
		"sha1":          {with("tsig_algorithm", "hmac-sha1"), "is not supported"},
		"md5":           {with("tsig_algorithm", "hmac-md5.sig-alg.reg.int"), "is not supported"},
		"bad base64":    {with("tsig_secret", "not base64!!"), "must be base64"},
	} {
		if _, err := newRFC2136DNSFromConfig(acmeConnectorConfig{}, acmeCredentialPayload{DNS: c.dns}); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	p, err := newRFC2136DNSFromConfig(acmeConnectorConfig{}, acmeCredentialPayload{DNS: with("tsig_algorithm", "HMAC-SHA512")})
	if err != nil {
		t.Fatal(err)
	}
	if a := p.(*rfc2136DNS); a.nameserver != "127.0.0.1:53" || a.algorithm != "hmac-sha512" {
		t.Errorf("defaults: %s %s", a.nameserver, a.algorithm)
	}
}

func TestRFC2136EndToEndWithACMEConnector(t *testing.T) {
	zone := &memZone{txt: map[string][]string{}}
	srv := newTestRFC2136Server(t, zone, "kk-key.", testTSIGSecret)
	adapter := rfc2136Adapter(t, srv.addr, "example.test", testTSIGSecret)
	conn := newDNS01Connector(newDNS01Upstream(t, zone), zone)
	conn.cfg.DNSProvider = "rfc2136"
	conn.newDNS = func(acmeCredentialPayload) (dnsProvider, error) { return adapter, nil }

	res, err := conn.Issue(context.Background(), connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, "shop.example.test")})
	if err != nil {
		t.Fatalf("dns-01 issue through rfc2136: %v", err)
	}
	if !strings.Contains(res.CertificatePEM, "BEGIN CERTIFICATE") {
		t.Fatal("no certificate")
	}
	zone.mu.Lock()
	defer zone.mu.Unlock()
	if len(zone.txt) != 0 {
		t.Errorf("TXT not removed after validation: %v", zone.txt)
	}
	if srv.requests != 2 {
		t.Errorf("want one add and one delete, got %d updates", srv.requests)
	}
}

// ---- delegated (acme-dns) ---------------------------------------------------

type fakeAcmeDNS struct {
	mu     sync.Mutex
	srv    *httptest.Server
	calls  int
	status int
	user   string
	key    string
	body   map[string]string
}

func newFakeAcmeDNS(t *testing.T) *fakeAcmeDNS {
	f := &fakeAcmeDNS{status: 200}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		f.user, f.key = r.Header.Get("X-Api-User"), r.Header.Get("X-Api-Key")
		_ = json.NewDecoder(r.Body).Decode(&f.body)
		if r.URL.Path != "/update" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(f.status)
		io.WriteString(w, `{"echo":"`+f.key+`"}`) // a careless server: must never reach our errors
	}))
	t.Cleanup(f.srv.Close)
	return f
}

const (
	delegatedPassword = "acme-dns-password-not-real"
	delegatedFull     = "d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.org"
)

func delegatedAdapter(t *testing.T, base string, cname string) *delegatedDNS {
	t.Helper()
	d, _ := json.Marshal(map[string]any{"base_url": base, "accounts": map[string]any{
		"example.com":      map[string]string{"username": "user-ex", "password": delegatedPassword, "subdomain": "sub-ex", "fulldomain": delegatedFull},
		"shop.example.com": map[string]string{"username": "user-shop", "password": delegatedPassword, "subdomain": "sub-shop", "fulldomain": "shop-id.auth.example.org"},
	}})
	p, err := newDelegatedDNSFromConfig(acmeConnectorConfig{}, acmeCredentialPayload{DNS: d})
	if err != nil {
		t.Fatal(err)
	}
	a := p.(*delegatedDNS)
	a.lookupCNAME = func(_ context.Context, name string) (string, error) {
		if cname == "=queried" {
			return name, nil // what Go returns when there is no CNAME
		}
		return cname, nil
	}
	return a
}

func TestDelegatedWritesTXTViaAPI(t *testing.T) {
	f := newFakeAcmeDNS(t)
	a := delegatedAdapter(t, f.srv.URL, delegatedFull+".")
	zone, cleanup, err := a.Present(context.Background(), "_acme-challenge.www.example.com", "digest43")
	if err != nil {
		t.Fatal(err)
	}
	if f.user != "user-ex" || f.key != delegatedPassword || f.body["subdomain"] != "sub-ex" || f.body["txt"] != "digest43" {
		t.Errorf("request: user=%q body=%v", f.user, f.body)
	}
	if zone != "auth.example.org" {
		t.Errorf("zone %q", zone)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Errorf("cleanup: %v", err)
	}
}

func TestDelegatedMissingCNAMEIsRejectedWithClearError(t *testing.T) {
	for name, cname := range map[string]string{"no CNAME": "=queried", "wrong target": "someone-else.example.net."} {
		f := newFakeAcmeDNS(t)
		a := delegatedAdapter(t, f.srv.URL, cname)
		_, _, err := a.Present(context.Background(), "_acme-challenge.www.example.com", "v")
		if err == nil || !strings.Contains(err.Error(), "has no CNAME to") || !strings.Contains(err.Error(), delegatedFull) {
			t.Errorf("%s: %v", name, err)
		}
		if f.calls != 0 {
			t.Errorf("%s: acme-dns saw %d requests, want 0", name, f.calls)
		}
	}
	f := newFakeAcmeDNS(t)
	a := delegatedAdapter(t, f.srv.URL, "x")
	a.lookupCNAME = func(context.Context, string) (string, error) { return "", errors.New("lookup failed") }
	if _, _, err := a.Present(context.Background(), "_acme-challenge.www.example.com", "v"); err == nil || !strings.Contains(err.Error(), "has no CNAME to") {
		t.Errorf("resolver error: %v", err)
	}
}

func TestDelegatedLongestSuffixAccount(t *testing.T) {
	f := newFakeAcmeDNS(t)
	a := delegatedAdapter(t, f.srv.URL, "shop-id.auth.example.org")
	if _, _, err := a.Present(context.Background(), "_acme-challenge.shop.example.com", "v"); err != nil {
		t.Fatal(err)
	}
	if f.user != "user-shop" {
		t.Errorf("used account %q, want the longest-suffix one", f.user)
	}
	if _, _, err := a.Present(context.Background(), "_acme-challenge.other.org", "v"); err == nil || !strings.Contains(err.Error(), "no acme-dns account is configured for other.org") {
		t.Errorf("unconfigured name: %v", err)
	}
}

func TestDelegatedAPIErrorsMapped(t *testing.T) {
	for status, want := range map[int]string{401: "rejected the account credentials", 403: "rejected the account credentials", 400: "refused the TXT value", 500: "returned HTTP 500"} {
		f := newFakeAcmeDNS(t)
		f.status = status
		a := delegatedAdapter(t, f.srv.URL, delegatedFull)
		_, _, err := a.Present(context.Background(), "_acme-challenge.www.example.com", "v")
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), delegatedPassword) {
			t.Errorf("%d: %v", status, err)
		}
	}
	if _, err := newDelegatedDNSFromConfig(acmeConnectorConfig{}, acmeCredentialPayload{}); err == nil || !strings.Contains(err.Error(), `needs a "dns" object`) {
		t.Errorf("missing config: %v", err)
	}
}

// ---- secrets and registry ---------------------------------------------------

func TestRFC2136AndDelegatedNeverLogSecrets(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	secrets := []string{string(testTSIGSecret), base64.StdEncoding.EncodeToString(testTSIGSecret), delegatedPassword, "WRONG-secret-for-tsig"}

	var texts []string
	record := func(err error) {
		if err != nil {
			texts = append(texts, err.Error())
		}
	}
	zone := &memZone{txt: map[string][]string{}}
	srv := newTestRFC2136Server(t, zone, "kk-key.", testTSIGSecret)
	good := rfc2136Adapter(t, srv.addr, "example.test", testTSIGSecret)
	_, cleanup, err := good.Present(context.Background(), "_acme-challenge.a.example.test", "v")
	record(err)
	record(cleanup(context.Background()))
	bad := rfc2136Adapter(t, srv.addr, "example.test", []byte("WRONG-secret-for-tsig"))
	_, _, err = bad.Present(context.Background(), "_acme-challenge.a.example.test", "v")
	record(err)
	dead := rfc2136Adapter(t, "127.0.0.1:1", "example.test", testTSIGSecret)
	_, _, err = dead.Present(context.Background(), "_acme-challenge.a.example.test", "v")
	record(err)

	for _, status := range []int{200, 400, 401, 500} {
		f := newFakeAcmeDNS(t)
		f.status = status
		_, _, err := delegatedAdapter(t, f.srv.URL, delegatedFull).Present(context.Background(), "_acme-challenge.www.example.com", "v")
		record(err)
	}
	f := newFakeAcmeDNS(t)
	f.srv.Close() // transport failure
	_, _, err = delegatedAdapter(t, f.srv.URL, delegatedFull).Present(context.Background(), "_acme-challenge.www.example.com", "v")
	record(err)

	// Connector create: config_json carries no credentials, and an attempt to
	// put one there is refused without echoing it.
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	audit := &recordingAuditProvider{}
	mux := http.NewServeMux()
	provider, _ := newIntegrationCAProvider(t, setupIntegrationDB(t))
	RegisterConnectorHandlers(mux, NewAuthenticatorFromEnv(), newConnectorTestStore(t), provider, nil, audit)
	rec := doJSON(t, mux, http.MethodPost, "/api/v1/connectors", map[string]any{"name": "a", "type": "acme", "config_json": `{"challenge":"dns-01","dns_provider":"rfc2136"}`})
	if rec.Code != http.StatusCreated {
		t.Fatalf("rfc2136 connector create: %d %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, mux, http.MethodPost, "/api/v1/connectors", map[string]any{"name": "b", "type": "acme", "config_json": `{"dns_provider":"delegated","password":"` + delegatedPassword + `"}`})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("secret in config accepted: %d", rec.Code)
	}
	texts = append(texts, rec.Body.String(), buf.String())
	audit.mu.Lock()
	for _, e := range audit.entries {
		raw, _ := json.Marshal(e)
		texts = append(texts, string(raw))
	}
	audit.mu.Unlock()

	for _, text := range texts {
		for _, s := range secrets {
			if strings.Contains(text, s) {
				t.Errorf("secret %q leaked in: %s", s, text)
			}
		}
	}
}

func TestRegistryHasRFC2136AndDelegated(t *testing.T) {
	for _, name := range []string{"rfc2136", "delegated"} {
		if _, ok := dnsProviderRegistry[name]; !ok {
			t.Errorf("%s not registered: %v", name, supportedDNSProviders())
		}
	}
	if err := validateACMEConnectorConfig(`{"dns_provider":"rfc2136"}`); err != nil {
		t.Error(err)
	}
}
