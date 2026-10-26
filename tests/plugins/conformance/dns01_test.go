// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

// Mock DNS providers for the first-party dns01 plugins (W38-08): DigitalOcean
// DNS API v2, GoDaddy Domains v1, NS1 and Akamai Edge DNS v2. Each answers as
// the vendor documents (status codes, auth scheme, body shape) and refuses a
// request that is shaped wrongly, so DNS01Suite grades the plugin's real
// requests. Vendor docs are cited in each plugin's main.go.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/plugins/delivery"
)

// dnsBase is what every mock provider shares: a TLS server, the zone it
// serves, and the armed failure.
type dnsBase struct {
	ts   *httptest.Server
	mu   sync.Mutex
	zone string
	fail string
}

func (b *dnsBase) Zone() string { return b.zone }
func (b *dnsBase) FailNext(mode string) {
	b.mu.Lock()
	b.fail = mode
	b.mu.Unlock()
}

// takeFailure answers the armed failure, once, and reports whether it did.
func (b *dnsBase) takeFailure(w http.ResponseWriter) bool {
	b.mu.Lock()
	mode := b.fail
	b.fail = ""
	b.mu.Unlock()
	switch mode {
	case "server_error":
		w.WriteHeader(http.StatusInternalServerError)
	case "rate_limit":
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
	case "unauthorized":
		w.WriteHeader(http.StatusUnauthorized)
		// A provider can reflect what it was sent; the plugin must not pass that on.
		_, _ = io.WriteString(w, "rejected credential")
	default:
		return false
	}
	return true
}

// relName is fqdn relative to the zone, as zone-relative providers take it.
func (b *dnsBase) relName(fqdn string) string {
	if fqdn == b.zone {
		return "@"
	}
	return strings.TrimSuffix(fqdn, "."+b.zone)
}

// absName is the inverse of relName.
func (b *dnsBase) absName(name string) string {
	if name == "@" || name == "" {
		return b.zone
	}
	return name + "." + b.zone
}

func newDNSBase(t *testing.T, h http.Handler) *dnsBase {
	b := &dnsBase{zone: "example.com"}
	b.ts = httptest.NewTLSServer(h)
	t.Cleanup(b.ts.Close)
	return b
}

// pathParts splits a request path after prefix.
func pathParts(r *http.Request, prefix string) []string {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if rest == "" {
		return nil
	}
	return strings.Split(rest, "/")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// --- DigitalOcean ---

type doRecord struct {
	id    int
	fqdn  string
	value string
}

type digitalOceanMock struct {
	*dnsBase
	recs   []doRecord
	nextID int
}

const doToken = "dop_v1_0123456789abcdef0123456789abcdef"

func newDigitalOceanMock(t *testing.T) *digitalOceanMock {
	m := &digitalOceanMock{nextID: 1000}
	m.dnsBase = newDNSBase(t, http.HandlerFunc(m.serve))
	return m
}

func (m *digitalOceanMock) Env() delivery.Env {
	return anyHostEnv(m.ts, map[string]string{"api_token": doToken}, []string{"api_token"}, nil)
}

func (m *digitalOceanMock) Reset() { m.mu.Lock(); m.recs, m.fail = nil, ""; m.mu.Unlock() }
func (m *digitalOceanMock) Seed(fqdn, value string) {
	m.mu.Lock()
	m.nextID++
	m.recs = append(m.recs, doRecord{m.nextID, fqdn, value})
	m.mu.Unlock()
}
func (m *digitalOceanMock) Records(fqdn string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, r := range m.recs {
		if r.fqdn == fqdn {
			out = append(out, r.value)
		}
	}
	return out
}

func (m *digitalOceanMock) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+doToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if m.takeFailure(w) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	parts := pathParts(r, "/v2/domains")
	if len(parts) == 0 || parts[0] != m.zone {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"domain": map[string]any{"name": m.zone}})
	case len(parts) == 2 && parts[1] == "records" && r.Method == http.MethodPost:
		var b struct {
			Type, Name, Data string
			TTL              int
		}
		raw, _ := io.ReadAll(r.Body)
		if json.Unmarshal(raw, &b) != nil || b.Type != "TXT" || b.Name == "" || b.Data == "" || b.TTL < 30 || strings.HasSuffix(b.Name, m.zone) {
			writeJSON(w, 422, map[string]any{"id": "unprocessable_entity", "message": "bad record"})
			return
		}
		m.nextID++
		m.recs = append(m.recs, doRecord{m.nextID, m.absName(b.Name), b.Data})
		writeJSON(w, 201, map[string]any{"domain_record": map[string]any{"id": m.nextID, "type": "TXT", "name": b.Name, "data": b.Data}})
	case len(parts) == 2 && parts[1] == "records" && r.Method == http.MethodGet:
		name, typ := r.URL.Query().Get("name"), r.URL.Query().Get("type")
		out := []map[string]any{}
		for _, rec := range m.recs {
			if typ == "TXT" && rec.fqdn == name {
				out = append(out, map[string]any{"id": rec.id, "type": "TXT", "name": m.relName(rec.fqdn), "data": rec.value})
			}
		}
		writeJSON(w, 200, map[string]any{"domain_records": out, "links": map[string]any{}, "meta": map[string]any{"total": len(out)}})
	case len(parts) == 3 && parts[1] == "records" && r.Method == http.MethodDelete:
		id, _ := strconv.Atoi(parts[2])
		for i, rec := range m.recs {
			if rec.id == id {
				m.recs = append(m.recs[:i], m.recs[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		writeJSON(w, 404, map[string]any{"id": "not_found", "message": "not found"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestDigitalOceanDNSPluginConforms(t *testing.T) {
	rt := newRuntime(t)
	DNS01Suite(t, Load(t, rt, repoPath(t, "plugins/digitalocean-dns")), newDigitalOceanMock(t))
}

// --- GoDaddy ---

type txtSets struct {
	sets map[string][]string // fqdn -> values
}

func (s *txtSets) records(fqdn string) []string { return append([]string(nil), s.sets[fqdn]...) }
func (s *txtSets) seed(fqdn, v string) {
	if s.sets == nil {
		s.sets = map[string][]string{}
	}
	s.sets[fqdn] = append(s.sets[fqdn], v)
}

type goDaddyMock struct {
	*dnsBase
	txtSets
}

const (
	gdKey    = "gd-key-0123456789"
	gdSecret = "gd-secret-0123456789abcdef"
)

func newGoDaddyMock(t *testing.T) *goDaddyMock {
	m := &goDaddyMock{}
	m.dnsBase = newDNSBase(t, http.HandlerFunc(m.serve))
	return m
}

func (m *goDaddyMock) Env() delivery.Env {
	return anyHostEnv(m.ts, map[string]string{"api_key": gdKey, "api_secret": gdSecret}, []string{"api_key", "api_secret"}, nil)
}
func (m *goDaddyMock) Reset() { m.mu.Lock(); m.sets, m.fail = nil, ""; m.mu.Unlock() }
func (m *goDaddyMock) Seed(fqdn, v string) {
	m.mu.Lock()
	m.seed(fqdn, v)
	m.mu.Unlock()
}
func (m *goDaddyMock) Records(fqdn string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.records(fqdn)
}

func (m *goDaddyMock) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "sso-key "+gdKey+":"+gdSecret {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if m.takeFailure(w) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	parts := pathParts(r, "/v1/domains")
	if len(parts) == 0 || parts[0] != m.zone {
		writeJSON(w, 404, map[string]any{"code": "UNKNOWN_DOMAIN", "message": "domain not found"})
		return
	}
	body, _ := io.ReadAll(r.Body)
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"domain": m.zone, "status": "ACTIVE"})
	case len(parts) == 2 && parts[1] == "records" && r.Method == http.MethodPatch:
		var recs []struct {
			Type, Name, Data string
			TTL              int
		}
		if json.Unmarshal(body, &recs) != nil || len(recs) == 0 {
			writeJSON(w, 422, map[string]any{"code": "INVALID_BODY"})
			return
		}
		for _, rec := range recs {
			if rec.Type != "TXT" || rec.Name == "" || rec.Data == "" || rec.TTL < 600 {
				writeJSON(w, 422, map[string]any{"code": "INVALID_BODY", "message": "ttl below the 600 second minimum or missing field"})
				return
			}
			m.seed(m.absName(rec.Name), rec.Data)
		}
		w.WriteHeader(http.StatusNoContent)
	case len(parts) == 4 && parts[1] == "records" && parts[2] == "TXT":
		fqdn := m.absName(parts[3])
		switch r.Method {
		case http.MethodGet:
			out := []map[string]any{}
			for _, v := range m.sets[fqdn] {
				out = append(out, map[string]any{"type": "TXT", "name": parts[3], "data": v, "ttl": 600})
			}
			writeJSON(w, 200, out)
		case http.MethodPut:
			var recs []struct {
				Data string
				TTL  int
			}
			if json.Unmarshal(body, &recs) != nil || len(recs) == 0 {
				writeJSON(w, 422, map[string]any{"code": "INVALID_BODY"})
				return
			}
			var vals []string
			for _, rec := range recs {
				if rec.Data == "" || rec.TTL < 600 {
					writeJSON(w, 422, map[string]any{"code": "INVALID_BODY", "message": "ttl below the 600 second minimum"})
					return
				}
				vals = append(vals, rec.Data)
			}
			m.sets[fqdn] = vals
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			delete(m.sets, fqdn)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestGoDaddyDNSPluginConforms(t *testing.T) {
	rt := newRuntime(t)
	DNS01Suite(t, Load(t, rt, repoPath(t, "plugins/godaddy-dns")), newGoDaddyMock(t))
}

// --- NS1 ---

type ns1Mock struct {
	*dnsBase
	// answers keeps each answer as its rdata strings, per fqdn.
	answers map[string][][]string
}

const ns1Key = "ns1-api-key-0123456789abcdef"

func newNS1Mock(t *testing.T) *ns1Mock {
	m := &ns1Mock{}
	m.dnsBase = newDNSBase(t, http.HandlerFunc(m.serve))
	return m
}

func (m *ns1Mock) Env() delivery.Env {
	return anyHostEnv(m.ts, map[string]string{"api_key": ns1Key}, []string{"api_key"}, nil)
}
func (m *ns1Mock) Reset() { m.mu.Lock(); m.answers, m.fail = nil, ""; m.mu.Unlock() }
func (m *ns1Mock) Seed(fqdn, v string) {
	m.mu.Lock()
	if m.answers == nil {
		m.answers = map[string][][]string{}
	}
	m.answers[fqdn] = append(m.answers[fqdn], []string{v})
	m.mu.Unlock()
}
func (m *ns1Mock) Records(fqdn string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, a := range m.answers[fqdn] {
		out = append(out, strings.Join(a, ""))
	}
	return out
}

func (m *ns1Mock) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-NSONE-Key") != ns1Key {
		writeJSON(w, 401, map[string]any{"message": "Unauthorized"})
		return
	}
	if m.takeFailure(w) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	parts := pathParts(r, "/v1/zones")
	if len(parts) == 0 || parts[0] != m.zone {
		writeJSON(w, 404, map[string]any{"message": "zone not found"})
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		if r.URL.Query().Get("records") != "false" {
			// A zone read without records=false drags the whole record list over the wire.
			writeJSON(w, 200, map[string]any{"zone": m.zone, "records": []any{"a lot"}})
			return
		}
		writeJSON(w, 200, map[string]any{"zone": m.zone})
		return
	}
	if len(parts) != 3 || parts[2] != "TXT" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	fqdn := parts[1]
	var body struct {
		Zone, Domain, Type string
		TTL                int
		Answers            []struct {
			Answer []string `json:"answer"`
		}
	}
	raw, _ := io.ReadAll(r.Body)
	if len(raw) > 0 && json.Unmarshal(raw, &body) != nil {
		writeJSON(w, 400, map[string]any{"message": "invalid JSON"})
		return
	}
	toAnswers := func() [][]string {
		var out [][]string
		for _, a := range body.Answers {
			out = append(out, a.Answer)
		}
		return out
	}
	_, exists := m.answers[fqdn]
	switch r.Method {
	case http.MethodGet:
		if !exists {
			writeJSON(w, 404, map[string]any{"message": "record not found"})
			return
		}
		ans := []map[string]any{}
		for _, a := range m.answers[fqdn] {
			ans = append(ans, map[string]any{"answer": a})
		}
		writeJSON(w, 200, map[string]any{"zone": m.zone, "domain": fqdn, "type": "TXT", "ttl": 3600, "answers": ans})
	case http.MethodPut:
		if exists {
			writeJSON(w, 400, map[string]any{"message": "record already exists"})
			return
		}
		if body.Zone != m.zone || body.Domain != fqdn || body.Type != "TXT" || body.TTL <= 0 || len(body.Answers) == 0 {
			writeJSON(w, 400, map[string]any{"message": "invalid record"})
			return
		}
		if m.answers == nil {
			m.answers = map[string][][]string{}
		}
		m.answers[fqdn] = toAnswers()
		writeJSON(w, 200, map[string]any{"zone": m.zone, "domain": fqdn})
	case http.MethodPost:
		if !exists {
			writeJSON(w, 404, map[string]any{"message": "record not found"})
			return
		}
		if len(body.Answers) == 0 {
			writeJSON(w, 400, map[string]any{"message": "answers required"})
			return
		}
		m.answers[fqdn] = toAnswers()
		writeJSON(w, 200, map[string]any{"zone": m.zone, "domain": fqdn})
	case http.MethodDelete:
		if !exists {
			writeJSON(w, 404, map[string]any{"message": "record not found"})
			return
		}
		delete(m.answers, fqdn)
		writeJSON(w, 200, map[string]any{})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestNS1DNSPluginConforms(t *testing.T) {
	rt := newRuntime(t)
	DNS01Suite(t, Load(t, rt, repoPath(t, "plugins/ns1-dns")), newNS1Mock(t))
}

// --- Akamai Edge DNS ---

// The mock verifies the EdgeGrid signature itself, from the credential the
// test hands over, with its own implementation of the documented algorithm
// (the plugin's is checked against the vendor's test vectors in its package).
const (
	akHost         = "akab-test-host.luna.akamaiapis.net"
	akClientToken  = "akab-client-token-conformance"
	akAccessToken  = "akab-access-token-conformance"
	akClientSecret = "conformance-client-secret-0123456789abcdef="
)

type akamaiMock struct {
	*dnsBase
	txtSets
	nonces   map[string]bool
	sigFails int
	now      func() time.Time
}

func newAkamaiMock(t *testing.T) *akamaiMock {
	m := &akamaiMock{nonces: map[string]bool{}, now: time.Now}
	m.dnsBase = newDNSBase(t, http.HandlerFunc(m.serve))
	return m
}

func (m *akamaiMock) Env() delivery.Env {
	return anyHostEnv(m.ts, map[string]string{
		"host": "https://" + akHost, "client_token": akClientToken, "client_secret": akClientSecret, "access_token": akAccessToken,
	}, []string{"client_secret", "client_token", "access_token"}, nil)
}
func (m *akamaiMock) Reset() {
	m.mu.Lock()
	m.sets, m.fail, m.nonces = nil, "", map[string]bool{}
	m.mu.Unlock()
}
func (m *akamaiMock) Seed(fqdn, v string) {
	m.mu.Lock()
	m.seed(fqdn, `"`+v+`"`)
	m.mu.Unlock()
}
func (m *akamaiMock) Records(fqdn string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, v := range m.records(fqdn) {
		out = append(out, strings.Trim(v, `"`))
	}
	return out
}

func hmacB64(key, msg string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(msg))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// verifySignature checks r's EdgeGrid Authorization header.
func (m *akamaiMock) verifySignature(r *http.Request, body []byte) error {
	h := r.Header.Get("Authorization")
	const prefix = "EG1-HMAC-SHA256 "
	if !strings.HasPrefix(h, prefix) {
		return fmt.Errorf("no EdgeGrid scheme")
	}
	i := strings.LastIndex(h, "signature=")
	if i < 0 {
		return fmt.Errorf("no signature")
	}
	unsigned, sig := h[:i], h[i+len("signature="):]
	fields := map[string]string{}
	for _, kv := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(unsigned, prefix), ";"), ";") {
		k, v, _ := strings.Cut(kv, "=")
		fields[k] = v
	}
	if fields["client_token"] != akClientToken || fields["access_token"] != akAccessToken {
		return fmt.Errorf("unknown tokens")
	}
	ts, err := time.Parse("20060102T15:04:05-0700", fields["timestamp"])
	if err != nil || ts.Sub(m.now()).Abs() > 30*time.Second {
		return fmt.Errorf("timestamp %q outside the 30 second window", fields["timestamp"])
	}
	if fields["nonce"] == "" || m.nonces[fields["nonce"]] {
		return fmt.Errorf("nonce missing or replayed")
	}
	m.nonces[fields["nonce"]] = true
	hash := ""
	if r.Method == http.MethodPost && len(body) > 0 {
		sum := sha256.Sum256(body)
		hash = base64.StdEncoding.EncodeToString(sum[:])
	}
	// r.Host is what the plugin put in the URL: the credential's host.
	toSign := strings.Join([]string{r.Method, "https", r.Host, r.URL.RequestURI(), "", hash, unsigned}, "\t")
	if hmacB64(hmacB64(akClientSecret, fields["timestamp"]), toSign) != sig {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func (m *akamaiMock) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.verifySignature(r, body); err != nil {
		m.sigFails++
		writeJSON(w, 401, map[string]any{"title": "Unauthorized", "detail": err.Error(), "status": 401})
		return
	}
	if r.Host != akHost {
		writeJSON(w, 400, map[string]any{"detail": "wrong host " + r.Host})
		return
	}
	m.mu.Unlock()
	failed := m.takeFailure(w)
	m.mu.Lock()
	if failed {
		return
	}
	parts := pathParts(r, "/config-dns/v2/zones")
	if len(parts) == 0 || parts[0] != m.zone {
		writeJSON(w, 404, map[string]any{"title": "Not Found", "status": 404})
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		writeJSON(w, 200, map[string]any{"zone": m.zone, "type": "PRIMARY", "activationState": "ACTIVE"})
		return
	}
	if len(parts) != 5 || parts[1] != "names" || parts[3] != "types" || parts[4] != "TXT" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	fqdn := parts[2]
	var set struct {
		Name  string   `json:"name"`
		Type  string   `json:"type"`
		TTL   *int     `json:"ttl"`
		RData []string `json:"rdata"`
	}
	if len(body) > 0 {
		if json.Unmarshal(body, &set) != nil || set.Name != fqdn || set.Type != "TXT" || set.TTL == nil || len(set.RData) == 0 {
			writeJSON(w, 400, map[string]any{"title": "Bad Request", "status": 400})
			return
		}
		for _, v := range set.RData {
			if !strings.HasPrefix(v, `"`) || !strings.HasSuffix(v, `"`) {
				writeJSON(w, 400, map[string]any{"title": "TXT rdata must be master file format strings", "status": 400})
				return
			}
		}
	}
	cur, exists := m.sets[fqdn]
	switch r.Method {
	case http.MethodGet:
		if !exists {
			writeJSON(w, 404, map[string]any{"title": "Not Found", "status": 404})
			return
		}
		writeJSON(w, 200, map[string]any{"name": fqdn, "type": "TXT", "ttl": 300, "rdata": cur})
	case http.MethodPost:
		if exists {
			writeJSON(w, 409, map[string]any{"title": "Conflict", "status": 409})
			return
		}
		if m.sets == nil {
			m.sets = map[string][]string{}
		}
		m.sets[fqdn] = slices.Clone(set.RData)
		writeJSON(w, 201, set)
	case http.MethodPut:
		if !exists {
			writeJSON(w, 404, map[string]any{"title": "Not Found", "status": 404})
			return
		}
		m.sets[fqdn] = slices.Clone(set.RData)
		writeJSON(w, 200, set)
	case http.MethodDelete:
		if !exists {
			writeJSON(w, 404, map[string]any{"title": "Not Found", "status": 404})
			return
		}
		delete(m.sets, fqdn)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestAkamaiEdgeDNSPluginConforms(t *testing.T) {
	rt := newRuntime(t)
	mock := newAkamaiMock(t)
	DNS01Suite(t, Load(t, rt, repoPath(t, "plugins/akamai-edgedns")), mock)
	if mock.sigFails != 0 {
		t.Fatalf("%d requests carried an EdgeGrid signature the provider rejected", mock.sigFails)
	}
}

// A plugin granted the credential's host can still not be pointed at a host
// outside akamaiapis.net by a mistyped credential: it refuses before signing.
func TestAkamaiRefusesAHostOutsideAkamai(t *testing.T) {
	rt := newRuntime(t)
	p := Load(t, rt, repoPath(t, "plugins/akamai-edgedns"))
	mock := newAkamaiMock(t)
	env := mock.Env()
	env.Credential["host"] = "https://evil.example.com"
	_, err := p.DNS01Present(t.Context(), env, "_acme-challenge.example.com", "v", 60)
	if err == nil || !strings.Contains(err.Error(), "akamaiapis.net") {
		t.Fatalf("err %v", err)
	}
	if mock.sigFails != 0 || len(mock.nonces) != 0 {
		t.Fatal("a request reached the provider")
	}
}
