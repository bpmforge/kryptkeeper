// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/dns01"
)

// The values below are the vendor's published EdgeGrid test vectors
// (akamai/AkamaiOPEN-edgegrid-python, akamai/edgegrid/test/testdata.json and
// test_edgegrid.py). The credentials are the vector's placeholders, not real.
var vector = edgeGrid{
	clientToken:  "akab-client-token-xxx-xxxxxxxxxxxxxxxx",
	clientSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=",
	accessToken:  "akab-access-token-xxx-xxxxxxxxxxxxxxxx",
}

const (
	vectorTimestamp = "20140321T19:34:21+0000"
	vectorNonce     = "nonce-xx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	vectorHost      = "akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net"
)

func TestEdgeGridSigningKeyVector(t *testing.T) {
	if got := vector.signingKey(vectorTimestamp); got != "znsRMDBRqTXGJ7Ojip3/h2FGPu3LuoMYWgv9PKEnE/o=" {
		t.Fatalf("signing key %s", got)
	}
}

func TestEdgeGridContentHashVector(t *testing.T) {
	if got := contentHash("POST", []byte("test_body")); got != "REPGqEEubBHzJMhwqDZtbt515/ntEvAMNriNR53zcdY=" {
		t.Fatalf("content hash %s", got)
	}
	// Only POST bodies are hashed, so a PUT or DELETE signs an empty field.
	if contentHash("PUT", []byte("test_body")) != "" || contentHash("DELETE", nil) != "" || contentHash("POST", nil) != "" {
		t.Fatal("content hash applies to non-empty POST bodies only")
	}
}

func TestEdgeGridAuthorizationVector(t *testing.T) {
	// requests' json= encodes {"key": "value"} with a space after the colon.
	got := vector.authorization("POST", vectorHost, "/testapi/v1/t3?extended=true", []byte(`{"key": "value"}`), vectorTimestamp, vectorNonce)
	want := "EG1-HMAC-SHA256 client_token=akab-client-token-xxx-xxxxxxxxxxxxxxxx;access_token=akab-access-token-xxx-xxxxxxxxxxxxxxxx;timestamp=20140321T19:34:21+0000;nonce=nonce-xx-xxxx-xxxx-xxxx-xxxxxxxxxxxx;signature=nONuDe50qGrPius4Rg4D2jfi/2zDZWAYRUG6RudJLNM="
	if got != want {
		t.Fatalf("authorization\n got %s\nwant %s", got, want)
	}
}

func TestEdgeGridTimestampAndNonce(t *testing.T) {
	now := time.Date(2014, 3, 21, 19, 34, 21, 0, time.FixedZone("x", 3600))
	a, err := vector.sign("GET", vectorHost, "/p", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := vector.sign("GET", vectorHost, "/p", nil, now)
	if !strings.Contains(a, "timestamp=20140321T18:34:21+0000;") {
		t.Fatalf("timestamp must be UTC: %s", a)
	}
	if a == b {
		t.Fatal("two signatures at one instant must differ by nonce")
	}
}

func TestAPIHostIsPinnedToAkamai(t *testing.T) {
	for in, ok := range map[string]bool{
		"https://akab-abc.luna.akamaiapis.net":      true,
		"https://akab-abc.luna.akamaiapis.net/":     true,
		"https://AKAB-ABC.luna.akamaiapis.net":      true,
		"akab-abc.luna.akamaiapis.net":              false, // no scheme
		"http://akab-abc.luna.akamaiapis.net":       false,
		"https://evil.example.com":                  false,
		"https://akamaiapis.net.evil.com":           false,
		"https://akamaiapis.net":                    false,
		"https://akab-abc.luna.akamaiapis.net:8443": false,
		"https://akab-abc.luna.akamaiapis.net/x":    false,
		"https://u:p@akab-abc.luna.akamaiapis.net":  false,
		"https://akab-abc.luna.akamaiapis.net/?a=b": false,
		"https://notakamaiapis.net":                 false,
		"":                                          false,
	} {
		if _, err := apiHost(in); (err == nil) != ok {
			t.Errorf("apiHost(%q): err %v, want ok=%v", in, err, ok)
		}
	}
}

type scripted struct {
	replies []abi.HTTPResponse
	seen    []abi.HTTPRequest
}

func (s *scripted) do(r abi.HTTPRequest) (abi.HTTPResponse, error) {
	s.seen = append(s.seen, r)
	resp := s.replies[0]
	s.replies = s.replies[1:]
	return resp, nil
}

func testBackend(s *scripted) *backend {
	return &backend{host: vectorHost, eg: vector, ttl: 60, send: s.do, now: func() time.Time { return time.Unix(0, 0) }}
}

func TestSetLifecycle(t *testing.T) {
	s := &scripted{replies: []abi.HTTPResponse{
		{Status: 200}, // zone
		{Status: 404}, // no set
		{Status: 201}, // POST
	}}
	if _, err := dns01.PresentRRSet(testBackend(s), "_acme-challenge.example.com", "one"); err != nil {
		t.Fatal(err)
	}
	post := s.seen[2]
	if post.Method != "POST" || post.URL != "https://"+vectorHost+"/config-dns/v2/zones/example.com/names/_acme-challenge.example.com/types/TXT" ||
		!strings.Contains(string(post.Body), `"rdata":["\"one\""]`) || !strings.HasPrefix(post.Headers["Authorization"], "EG1-HMAC-SHA256 client_token=") {
		t.Fatalf("%s %s %s", post.Method, post.URL, post.Body)
	}

	s = &scripted{replies: []abi.HTTPResponse{
		{Status: 200, Body: []byte(`{"name":"x","type":"TXT","ttl":300,"rdata":["\"ours\"","\"theirs\""]}`)},
		{Status: 200},
	}}
	b := testBackend(s)
	b.ttl = 0
	if _, err := dns01.CleanupRRSet(b, "_acme-challenge.example.com", "ours", "example.com"); err != nil {
		t.Fatal(err)
	}
	put := s.seen[1]
	if put.Method != "PUT" || strings.Contains(string(put.Body), "ours") || !strings.Contains(string(put.Body), "theirs") || !strings.Contains(string(put.Body), `"ttl":300`) {
		t.Fatalf("cleanup must rewrite the set under its own TTL: %s %s", put.Method, put.Body)
	}
}

func TestDecodeDoesNotMatchForeignValues(t *testing.T) {
	b := &backend{}
	if b.Decode(`"a" "b"`) == "a" || b.Decode(`"a\"b"`) == `a\"b` || b.Decode("bare") == "bare" {
		t.Fatal("only a plain single quoted string decodes to its value")
	}
	if b.Decode(b.Encode("abc")) != "abc" {
		t.Fatal("round trip")
	}
}

func TestRejectedClientDoesNotEchoTheBody(t *testing.T) {
	s := &scripted{replies: []abi.HTTPResponse{{Status: 401, Body: []byte(`client_secret xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=`)}}}
	_, err := testBackend(s).Zone("_acme-challenge.example.com")
	if err == nil || !strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "xxxxxxxxxx") {
		t.Fatalf("err %v", err)
	}
}
