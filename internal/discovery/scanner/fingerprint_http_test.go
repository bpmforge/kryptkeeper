// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Recorded responses: header sets as the named products send them.
const (
	respTomcat  = "HTTP/1.1 200 \r\nServer: Apache-Coyote/1.1\r\nSet-Cookie: JSESSIONID=9F3A77C0DEADBEEF; Path=/; Secure\r\nContent-Length: 0\r\n\r\n"
	respIIS     = "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nX-Powered-By: ASP.NET\r\nX-AspNet-Version: 4.0.30319\r\nSet-Cookie: ASP.NET_SessionId=zzzz1234; path=/; HttpOnly\r\n\r\n"
	respF5      = "HTTP/1.1 200 OK\r\nSet-Cookie: BIGipServer~Prod~pool_secret_web=1677787402.36895.0000; path=/\r\n\r\n"
	respCitrix  = "HTTP/1.1 302 Found\r\nSet-Cookie: NSC_AAAC=xyz987; path=/; httponly\r\nSet-Cookie: citrix_ns_id=abc; Path=/\r\n\r\n"
	respNode    = "HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\nSet-Cookie: connect.sid=s%3Aabc.def; Path=/\r\n\r\n"
	respNeg     = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=\r\nWWW-Authenticate: NTLM\r\n\r\n"
	respKube    = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\n  \"kind\": \"Status\",\n  \"apiVersion\": \"v1\",\n  \"status\": \"Failure\",\n  \"message\": \"forbidden: User \\\"system:anonymous\\\" cannot get path \\\"/\\\"\"\n}"
	respOWA     = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>Outlook Web App</title></head><body>secret page content</body></html>"
	respHTTPAPI = "HTTP/1.1 404 Not Found\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n"
)

func evidenceTechs(ev []Evidence) []string {
	var out []string
	for _, e := range ev {
		out = append(out, e.Tech)
	}
	return out
}

func hasEvidence(ev []Evidence, tech, valueContains string) bool {
	for _, e := range ev {
		if e.Tech == tech && strings.Contains(e.Value, valueContains) {
			return true
		}
	}
	return false
}

func TestHTTPEvidenceFixtures(t *testing.T) {
	cases := []struct {
		name      string
		resp      string
		port      int
		tech      string // headline after Resolve
		conf      string
		platform  string
		mustHave  [][2]string // tech, value fragment
		mustNotIn []string    // fragments that must never be stored
	}{
		{"tomcat Coyote + JSESSIONID", respTomcat, 443, "tomcat", ConfidenceHigh, PlatformJava,
			[][2]string{{"tomcat", "Apache-Coyote"}, {"tomcat", "JSESSIONID"}}, []string{"9F3A77C0DEADBEEF"}},
		{"IIS + ASP.NET set", respIIS, 443, "iis", ConfidenceHigh, PlatformWindows,
			[][2]string{{"iis", "Microsoft-IIS"}, {"iis", "X-Powered-By: ASP.NET"}, {"iis", "X-AspNet-Version: 4.0.30319"}, {"iis", "ASP.NET_SessionId"}}, []string{"zzzz1234"}},
		{"F5 persistence cookie", respF5, 443, "f5-bigip", ConfidenceMedium, PlatformAppliance,
			[][2]string{{"f5-bigip", "BIGipServer*"}}, []string{"pool_secret_web", "1677787402"}},
		{"F5 in front of Apache is a tie, so unknown", "HTTP/1.1 200 OK\r\nServer: Apache\r\nSet-Cookie: BIGipServerpool=1.2.0000\r\n\r\n", 443, TechUnknown, ConfidenceLow, PlatformAppliance,
			[][2]string{{"f5-bigip", "BIGipServer*"}, {"apache", "Server: Apache"}}, nil},
		{"Citrix NSC_ and citrix_ns_id", respCitrix, 443, "citrix-adc", ConfidenceMedium, PlatformAppliance,
			[][2]string{{"citrix-adc", "NSC_*"}}, []string{"xyz987", "NSC_AAAC"}},
		{"node via connect.sid and Express", respNode, 443, "node", ConfidenceHigh, PlatformUnknown,
			[][2]string{{"node", "connect.sid"}, {"node", "Express"}}, []string{"s%3Aabc"}},
		{"Negotiate/NTLM vote windows without a tech", respNeg, 443, TechUnknown, ConfidenceLow, PlatformWindows,
			[][2]string{{"", "WWW-Authenticate: Negotiate"}, {"", "WWW-Authenticate: NTLM"}}, []string{"TlRMTVNT"}},
		{"kube-apiserver Status body", respKube, 6443, "kubernetes-api", ConfidenceMedium, PlatformUnknown,
			[][2]string{{"kubernetes-api", "kind=Status"}}, []string{"system:anonymous", "forbidden"}},
		{"Tomcat 10 error report (no Server header, no cookie)", "HTTP/1.1 404 \r\nContent-Type: text/html;charset=utf-8\r\n\r\n<!doctype html><html><head><title>HTTP Status 404 – Not Found</title></head><body><h1>HTTP Status 404 – Not Found</h1><hr class=\"line\" /><h3>Apache Tomcat/10.1.61</h3></body></html>", 8443, "tomcat", ConfidenceMedium, PlatformJava,
			[][2]string{{"tomcat", "Apache Tomcat error report"}}, []string{"10.1.61", "Status Report"}},
		{"a page that merely mentions Tomcat is not the error report", "HTTP/1.1 200 OK\r\n\r\n<p>We migrated from Apache Tomcat/9 last year</p>", 443, TechUnknown, ConfidenceLow, PlatformUnknown, nil, nil},
		{"OWA title", respOWA, 443, "exchange", ConfidenceMedium, PlatformWindows,
			[][2]string{{"exchange", "outlook web app"}}, []string{"secret page content"}},
		{"HTTPAPI on WinRM port", respHTTPAPI, 5986, "winrm", ConfidenceMedium, PlatformWindows,
			[][2]string{{"winrm", "Microsoft-HTTPAPI/2.0"}}, nil},
		{"HTTPAPI elsewhere is only a Windows tell", respHTTPAPI, 443, TechUnknown, ConfidenceLow, PlatformWindows,
			[][2]string{{"", "Microsoft-HTTPAPI/2.0"}}, nil},
		{"Kestrel", "HTTP/1.1 200 OK\r\nServer: Kestrel\r\n\r\n", 443, "kestrel", ConfidenceMedium, PlatformUnknown,
			[][2]string{{"kestrel", "Kestrel"}}, nil},
		{"Jetty", "HTTP/1.1 200 OK\r\nServer: Jetty(9.4.51.v20230217)\r\n\r\n", 443, "jetty", ConfidenceMedium, PlatformJava,
			[][2]string{{"jetty", "Jetty(9.4"}}, nil},
		{"Undertow reads as WildFly", "HTTP/1.1 200 OK\r\nServer: WildFly/10\r\nX-Powered-By: Undertow/1\r\n\r\n", 443, "wildfly", ConfidenceHigh, PlatformJava,
			[][2]string{{"wildfly", "Undertow"}}, nil},
		{"WebLogic", "HTTP/1.1 200 OK\r\nServer: Oracle-HTTP-Server WebLogic Server 14.1.1\r\n\r\n", 443, "weblogic", ConfidenceMedium, PlatformJava,
			[][2]string{{"weblogic", "WebLogic"}}, nil},
		{"WebSphere", "HTTP/1.1 200 OK\r\nServer: WebSphere Application Server/9.0\r\n\r\n", 443, "websphere", ConfidenceMedium, PlatformJava,
			[][2]string{{"websphere", "WebSphere"}}, nil},
		{"Apache on Windows", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Win64) OpenSSL/3.1.2\r\n\r\n", 443, "apache", ConfidenceMedium, PlatformWindows,
			[][2]string{{"apache", "Win64"}}, nil},
		{"nginx on Ubuntu", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\n\r\n", 443, "nginx", ConfidenceMedium, PlatformLinux,
			[][2]string{{"nginx", "nginx/1.24.0"}}, nil},
		{"unknown server keeps its token", "HTTP/1.1 200 OK\r\nServer: gws\r\n\r\n", 443, "other:gws", ConfidenceMedium, PlatformUnknown,
			[][2]string{{"other:gws", "Server: gws"}}, nil},
		{"nothing identifying", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>hello</html>", 443, TechUnknown, ConfidenceLow, PlatformUnknown, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := httpEvidence(parseHTTPResponse(c.resp), c.port)
			fp := Resolve(ev)
			if fp.Tech != c.tech || fp.Confidence != c.conf || fp.Platform != c.platform {
				t.Fatalf("got %s/%s/%s want %s/%s/%s (evidence %+v)", fp.Tech, fp.Confidence, fp.Platform, c.tech, c.conf, c.platform, ev)
			}
			for _, want := range c.mustHave {
				if !hasEvidence(ev, want[0], want[1]) {
					t.Errorf("missing evidence tech=%q value~%q in %+v", want[0], want[1], ev)
				}
			}
			for _, e := range ev {
				for _, bad := range c.mustNotIn {
					if strings.Contains(e.Value, bad) {
						t.Errorf("evidence stores %q: %+v", bad, e)
					}
				}
				if e.Signal != SignalHTTPHeader || e.Weight != 60 {
					t.Errorf("http rows must be http_header@60: %+v", e)
				}
			}
		})
	}
}

func TestHTTPEvidenceIsCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString("HTTP/1.1 200 OK\r\n")
	for i := 0; i < 100; i++ {
		b.WriteString("X-AspNet-Version: 4.0.30319\r\n")
	}
	b.WriteString("\r\n")
	if n := len(httpEvidence(parseHTTPResponse(b.String()), 443)); n != maxHTTPEvidence {
		t.Fatalf("evidence rows = %d, want cap %d", n, maxHTTPEvidence)
	}
}

func TestHTTPCookieEvidenceIsDeduplicated(t *testing.T) {
	r := "HTTP/1.1 200 OK\r\nSet-Cookie: JSESSIONID=a\r\nSet-Cookie: JSESSIONID=b\r\n\r\n"
	if n := len(httpEvidence(parseHTTPResponse(r), 443)); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
}

func TestParseHTTPResponseToleratesGarbage(t *testing.T) {
	for _, raw := range []string{"", "\r\n\r\n", "no colon lines\r\nat all", "HTTP/1.1 200 OK", "\x00\x01\x02:\r\n\r\n"} {
		_ = httpEvidence(parseHTTPResponse(raw), 443) // must not panic
	}
}

func TestLegacyServerTechUnchangedByTells(t *testing.T) {
	// server_tech compatibility: Coyote is still "apache" to the legacy classifier;
	// finalizeFingerprint overrides it with the fingerprint's tomcat.
	if got := classifyServerHeader(respTomcat); got != "apache" {
		t.Fatalf("legacy classification changed: %q", got)
	}
}

// httpsFixture serves HTTP over TLS on a counted listener, so a test can assert
// the probe reused the scan's connection.
func httpsFixture(t *testing.T, h http.Handler) (port int, accepts *atomic.Int32) {
	t.Helper()
	cfg, _ := fixtureTLSConfig(t, "web.example.com")
	l := listenLocal(t)
	accepts = new(atomic.Int32)
	counted := &countingListener{Listener: tls.NewListener(l, cfg), n: accepts}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 2 * time.Second}
	go func() { _ = srv.Serve(counted) }() // returns when the listener closes at cleanup
	t.Cleanup(func() { _ = srv.Close() })
	return portOf(l), accepts
}

type countingListener struct {
	net.Listener
	n *atomic.Int32
}

func (c *countingListener) Accept() (net.Conn, error) {
	conn, err := c.Listener.Accept()
	if err == nil {
		c.n.Add(1)
	}
	return conn, err
}

// End to end through the capture path with a real TLS+HTTP server: every
// passive signal comes from the one connection the scan already made (D-206).
func TestPassiveHTTPFingerprintUsesNoExtraConnection(t *testing.T) {
	port, accepts := httpsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "topsecretvalue"})
		w.WriteHeader(http.StatusOK)
	}))
	s := New(ScanConfig{Timeout: 3 * time.Second})
	conn, _, err := s.dialTLS(context.Background(), "127.0.0.1", port, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ep := s.finishTLSCapture(DiscoveredEndpoint{Host: "127.0.0.1", Port: 8443, Protocol: "https-alt", Reachable: true}, conn, conn.ConnectionState(), "127.0.0.1", 8443, "https-alt")
	out := finalizeFingerprint(ep, protocolEntry{port: 8443, protocol: "https-alt"})
	if out.Fingerprint.Tech != "tomcat" || out.Fingerprint.Confidence != ConfidenceHigh || out.ServerTech != "tomcat" {
		t.Fatalf("fingerprint = %+v server_tech=%q", out.Fingerprint, out.ServerTech)
	}
	if got := EvidenceJSON(out.Fingerprint.Evidence); strings.Contains(got, "topsecretvalue") {
		t.Fatalf("cookie value leaked into evidence: %s", got)
	}
	if n := accepts.Load(); n != 1 {
		t.Fatalf("fingerprinting opened %d connections, want exactly 1", n)
	}
}

// The probe must work in every tier: fast/targeted/full go through
// isHTTPPort, deep through the any-port rule.
func TestHTTPProbePortSelection(t *testing.T) {
	for _, port := range []int{443, 8443, 4443, 9443, 10443, 6443, 5986} {
		if !isHTTPPort(port) {
			t.Errorf("port %d must be HTTP-probed in fast/targeted/full scans", port)
		}
	}
	if isHTTPPort(636) || isHTTPPort(993) {
		t.Error("LDAPS and IMAPS must not be sent an HTTP request")
	}
}

// W34-01 removed the port-only WinRM recommendation; the HTTPAPI tell on the
// WinRM port is the observation that earns it back.
func TestWinRMRecommendationReturnsWithHTTPAPITell(t *testing.T) {
	ep := DiscoveredEndpoint{Host: "h", Port: 5986, Protocol: "winrm-https", Reachable: true, Certs: []DiscoveredCert{{}},
		ServerTech: classifyServerHeader(respHTTPAPI),
		signals:    httpEvidence(parseHTTPResponse(respHTTPAPI), 5986)}
	out := finalizeFingerprint(ep, protocolForPort(5986))
	if out.Fingerprint.Tech != "winrm" || out.Fingerprint.Confidence != ConfidenceMedium || out.RecommendedInstallMode != "iis" {
		t.Fatalf("fingerprint = %+v mode=%q", out.Fingerprint, out.RecommendedInstallMode)
	}
}
