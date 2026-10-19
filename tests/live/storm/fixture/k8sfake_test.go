// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func secretJSON(name string, crt, key []byte) []byte {
	b, _ := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "Secret", "type": "kubernetes.io/tls",
		"metadata": map[string]string{"name": name, "namespace": "storm"},
		"data": map[string]string{
			"tls.crt": base64.StdEncoding.EncodeToString(crt),
			"tls.key": base64.StdEncoding.EncodeToString(key),
		},
	})
	return b
}

func k8sDo(t *testing.T, srv *httptest.Server, method, path, token string, body []byte) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

// The hub's pusher does GET (404) -> POST, then GET (200) -> PUT on the next renewal.
func TestFakeK8sSecretRoundTrip(t *testing.T) {
	ca, err := newStubCA(stubConfig{Limit: 1, Window: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	crt, key, err := ca.signServerCert([]string{"x.test"})
	if err != nil {
		t.Fatal(err)
	}
	fake := newK8sFake("storm")
	srv := httptest.NewTLSServer(fake.Handler())
	defer srv.Close()
	path := "/api/v1/namespaces/storm/secrets"

	if c, _ := k8sDo(t, srv, "GET", path+"/s1", "wrong", nil); c != http.StatusUnauthorized {
		t.Fatalf("bad token: %d, want 401", c)
	}
	if c, _ := k8sDo(t, srv, "GET", path+"/s1", "storm", nil); c != http.StatusNotFound {
		t.Fatalf("missing secret: %d, want 404", c)
	}
	if c, b := k8sDo(t, srv, "POST", path, "storm", secretJSON("s1", crt, key)); c != http.StatusCreated {
		t.Fatalf("create: %d %s", c, b)
	}
	if c, _ := k8sDo(t, srv, "POST", path, "storm", secretJSON("s1", crt, key)); c != http.StatusConflict {
		t.Fatalf("duplicate create: %d, want 409", c)
	}
	c, b := k8sDo(t, srv, "GET", path+"/s1", "storm", nil)
	if c != http.StatusOK {
		t.Fatalf("get: %d", c)
	}
	var got struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(b, &got); err != nil || got.Metadata.ResourceVersion == "" {
		t.Fatalf("no resourceVersion in %s", b)
	}
	if c, _ := k8sDo(t, srv, "PUT", path+"/s1", "storm", secretJSON("s1", crt, key)); c != http.StatusOK {
		t.Fatalf("put: %d", c)
	}
	if c, _ := k8sDo(t, srv, "DELETE", path+"/s1", "storm", nil); c != http.StatusOK {
		t.Fatalf("delete: %d", c)
	}
	if c, _ := k8sDo(t, srv, "GET", path+"/s1", "storm", nil); c != http.StatusNotFound {
		t.Fatalf("after delete: %d, want 404", c)
	}
}

func TestVerifyListenerServesStoredCert(t *testing.T) {
	ca, err := newStubCA(stubConfig{Limit: 1, Window: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	fake := newK8sFake("storm")
	// serveVerifyListeners needs two consecutive ports; base+1 can be taken by
	// another process between probing and binding, so retry a few bases.
	var lns []net.Listener
	var base int
	for attempt := 0; ; attempt++ {
		free, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		base = free.Addr().(*net.TCPAddr).Port
		free.Close()
		if lns, err = fake.serveVerifyListeners("127.0.0.1", base, 2); err == nil {
			break
		} else if attempt == 9 {
			t.Fatal(err)
		}
	}
	defer func() {
		for _, l := range lns {
			l.Close()
		}
	}()
	fingerprint := func(i int) string {
		d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // fingerprint is the check, as in the hub's verifier
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(base+i)))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		sum := sha256.Sum256(conn.(*tls.Conn).ConnectionState().PeerCertificates[0].Raw)
		return string(sum[:])
	}
	before := fingerprint(1)

	crt, key, _ := ca.signServerCert([]string{"s1.test"})
	srv := httptest.NewTLSServer(fake.Handler())
	defer srv.Close()
	if c, b := k8sDo(t, srv, "POST", "/api/v1/namespaces/storm/secrets", "storm", secretJSON("s1", crt, key)); c != http.StatusCreated {
		t.Fatalf("create: %d %s", c, b)
	}
	after := fingerprint(1)
	if after == before {
		t.Fatal("listener 1 still serves the placeholder after the secret was stored")
	}
	want := sha256.Sum256(mustDER(t, crt))
	if after != string(want[:]) {
		t.Fatal("listener 1 does not serve the stored leaf")
	}
	if fingerprint(0) != before && fingerprint(0) == after {
		t.Fatal("listener 0 served secret s1")
	}
}
