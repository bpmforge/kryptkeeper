// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	kubeBody = "{\n  \"kind\": \"Status\",\n  \"apiVersion\": \"v1\",\n  \"metadata\": {},\n  \"status\": \"Failure\",\n  \"message\": \"Unauthorized\",\n  \"reason\": \"Unauthorized\",\n  \"code\": 401\n}"
	winrm401 = "HTTP/1.1 401 \r\nServer: Microsoft-HTTPAPI/2.0\r\nWWW-Authenticate: Negotiate\r\nWWW-Authenticate: Basic realm=\"WSMAN\"\r\nContent-Length: 0\r\n\r\n"
)

func TestHTTPIdentity(t *testing.T) {
	cases := []struct {
		name     string
		resp     string
		port     int
		tech     string
		conf     string
		platform string
	}{
		{"kube-apiserver 401", "HTTP/2 401\r\nContent-Type: application/json\r\n\r\n" + kubeBody, 6443, "kubernetes-api", ConfidenceMedium, PlatformUnknown},
		{"kube-apiserver 403 on a custom port", "HTTP/1.1 403 Forbidden\r\n\r\n" + kubeBody, 16443, "kubernetes-api", ConfidenceMedium, PlatformUnknown},
		{"JSON without kind Status", "HTTP/1.1 401\r\n\r\n{\"kind\":\"List\"}", 6443, TechUnknown, ConfidenceLow, PlatformUnknown},
		{"WinRM: 401 Negotiate and HTTPAPI", winrm401, 5986, "winrm", ConfidenceHigh, PlatformWindows},
		{"WinRM: 401 Negotiate alone", "HTTP/1.1 401\r\nWWW-Authenticate: Negotiate\r\n\r\n", 5986, "winrm", ConfidenceMedium, PlatformWindows},
		{"WinRM: 401 NTLM alone", "HTTP/1.1 401\r\nWWW-Authenticate: NTLM\r\n\r\n", 5986, "winrm", ConfidenceMedium, PlatformWindows},
		{"WinRM: HTTPAPI alone", "HTTP/1.1 404\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n", 5986, "winrm", ConfidenceMedium, PlatformWindows},
		{"Negotiate on 443 is only a Windows tell", "HTTP/1.1 401\r\nWWW-Authenticate: Negotiate\r\n\r\n", 443, TechUnknown, ConfidenceLow, PlatformWindows},
		{"200 on a WinRM port with a Negotiate header is not the 401 challenge", "HTTP/1.1 200\r\nWWW-Authenticate: Negotiate\r\n\r\n", 5986, TechUnknown, ConfidenceLow, PlatformWindows},
		{"WinRM port, nothing identifying", "HTTP/1.1 200\r\n\r\nhello", 5986, TechUnknown, ConfidenceLow, PlatformUnknown},
		{"garbage status line", "garbage\r\nWWW-Authenticate: Negotiate\r\n\r\n", 5986, TechUnknown, ConfidenceLow, PlatformWindows},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := httpEvidence(parseHTTPResponse(c.resp), c.port)
			fp := Resolve(ev)
			if fp.Tech != c.tech || fp.Confidence != c.conf || fp.Platform != c.platform {
				t.Fatalf("got %s/%s/%s want %s/%s/%s (%+v)", fp.Tech, fp.Confidence, fp.Platform, c.tech, c.conf, c.platform, ev)
			}
			for _, e := range ev {
				if strings.Contains(e.Value, "Unauthorized") || strings.Contains(e.Value, "metadata") || strings.Contains(e.Value, "WSMAN") {
					t.Errorf("body or challenge text leaked into evidence: %q", e.Value)
				}
			}
		})
	}
}

func TestParseHTTPStatus(t *testing.T) {
	for raw, want := range map[string]int{"HTTP/1.1 401 Unauthorized\r\n\r\n": 401, "HTTP/2 403\r\n\r\n": 403, "HTTP/1.1 abc\r\n\r\n": 0, "": 0, "SSH-2.0\r\n\r\n": 0} {
		if got := parseHTTPResponse(raw).status; got != want {
			t.Errorf("%q: status %d, want %d", raw, got, want)
		}
	}
}

// End to end over a real TLS+HTTP server, on the one connection the scan made.
func TestIdentityProbesOverTheScansConnection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		port    int
		handler http.HandlerFunc
		tech    string
	}{
		{"kubernetes", 6443, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(kubeBody))
		}, "kubernetes-api"},
		{"winrm", 5986, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("WWW-Authenticate", "Negotiate")
			w.WriteHeader(http.StatusUnauthorized)
		}, "winrm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port, accepts := httpsFixture(t, tc.handler)
			s := New(ScanConfig{Timeout: 3 * time.Second}) // not active: these are passive
			conn, _, err := s.dialTLS(context.Background(), "127.0.0.1", port, &tls.Config{InsecureSkipVerify: true})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			ep := s.finishTLSCapture(DiscoveredEndpoint{Host: "127.0.0.1", Port: tc.port, Reachable: true}, conn, conn.ConnectionState(), "127.0.0.1", tc.port, "tls")
			if fp := Resolve(ep.signals); fp.Tech != tc.tech {
				t.Fatalf("fingerprint = %+v (%+v)", fp, ep.signals)
			}
			if n := accepts.Load(); n != 1 {
				t.Fatalf("%d connections, want 1", n)
			}
		})
	}
}
