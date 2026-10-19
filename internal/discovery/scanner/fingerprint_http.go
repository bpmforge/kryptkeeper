// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// httpProbeLimit caps what is read from the response: headers plus the little
// body the sniffers look at. No body is ever stored.
const httpProbeLimit = 4096

// maxHTTPEvidence bounds the rows one response can add, so a hostile server
// that sends hundreds of Set-Cookie lines cannot bloat tech_evidence.
const maxHTTPEvidence = 12

type httpHeader struct{ name, value string }

type httpResponse struct {
	status  int // 0 when the status line was unreadable
	headers []httpHeader
	body    string
}

// parseHTTPResponse splits a raw response into header lines and the body that
// followed in the same read. It is deliberately lenient: this is an identity
// probe against arbitrary servers, not an HTTP client.
func parseHTTPResponse(raw string) httpResponse {
	head, body, _ := strings.Cut(raw, "\r\n\r\n")
	var r httpResponse
	r.body = body
	lines := strings.Split(head, "\r\n")
	if f := strings.Fields(lines[0]); len(f) >= 2 && strings.HasPrefix(f[0], "HTTP/") {
		r.status, _ = strconv.Atoi(f[1]) // a non-numeric status stays 0
	}
	for _, line := range lines[min(1, len(lines)):] { // first line is the status line
		name, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		r.headers = append(r.headers, httpHeader{strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(val)})
	}
	return r
}

func (r httpResponse) values(name string) []string {
	var out []string
	for _, h := range r.headers {
		if h.name == name {
			out = append(out, h.value)
		}
	}
	return out
}

// probeHTTP sends one GET over the already-open TLS connection and returns the
// legacy server_tech token plus the evidence rows. It opens no connection of
// its own (D-206), so it is safe in every scan tier.
//
// GET rather than HEAD because the Kubernetes and OWA tells live in the body.
func probeHTTP(conn net.Conn, host string, port int, timeout time.Duration) (string, []Evidence) {
	_ = conn.SetDeadline(time.Now().Add(timeout))        // best-effort read deadline; a fingerprint probe failure is non-fatal
	defer func() { _ = conn.SetDeadline(time.Time{}) }() // clear deadline; error irrelevant on a closing conn
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Kryptkeeper-Scan\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", nil
	}
	buf := make([]byte, httpProbeLimit)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return "", nil
	}
	// The body often arrives in a second TLS record. One short extra read picks
	// it up without letting a keep-alive server hold the scan for the full
	// timeout.
	if strings.HasSuffix(string(buf[:n]), "\r\n\r\n") && n < len(buf) {
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond)) // bounded; a miss just means no body sniff
		m, _ := conn.Read(buf[n:])
		if m > 0 {
			n += m
		}
	}
	resp := string(buf[:n])
	return classifyServerHeader(resp), httpEvidence(parseHTTPResponse(resp), port)
}

// cookieTells maps a Set-Cookie name to the technology it betrays. The
// evidence stores the canonical token, never the cookie value, and for the
// prefixed families never the suffix (BIGipServer<pool> carries the pool name).
var cookieTells = []struct {
	match    func(name string) bool
	token    string
	tech     string
	platform string
}{
	{func(n string) bool { return n == "jsessionid" }, "JSESSIONID", "tomcat", ""},
	{func(n string) bool { return n == "asp.net_sessionid" }, "ASP.NET_SessionId", "iis", PlatformWindows},
	{func(n string) bool { return strings.HasPrefix(n, "bigipserver") }, "BIGipServer*", "f5-bigip", PlatformAppliance},
	{func(n string) bool { return strings.HasPrefix(n, "nsc_") || n == "citrix_ns_id" }, "NSC_*", "citrix-adc", PlatformAppliance},
	{func(n string) bool { return n == "connect.sid" }, "connect.sid", "node", ""},
}

// serverTells are checked before the generic web-server names because the
// generic names would swallow them (Apache-Coyote contains "apache").
var serverTells = []struct{ substr, tech string }{
	{"apache-coyote", "tomcat"},
	{"kestrel", "kestrel"},
	{"jetty", "jetty"},
	{"undertow", "wildfly"},
	{"wildfly", "wildfly"},
	{"weblogic", "weblogic"},
	{"websphere", "websphere"},
}

var (
	serverWindowsRe = regexp.MustCompile(`\((win32|win64|windows)[^)]*\)`)
	serverLinuxRe   = regexp.MustCompile(`\((ubuntu|debian|centos|red hat|rhel|fedora|unix|suse|alpine|amazon)[^)]*\)`)
	tomcatErrorRe   = regexp.MustCompile(`<h3>Apache Tomcat/[0-9][0-9A-Za-z.\-]*</h3>`)
	owaTitleRe      = regexp.MustCompile(`(?is)<title>[^<]*(outlook web app|outlook|microsoft exchange)[^<]*</title>`)
)

// httpEvidence turns a parsed response into evidence rows. Every row stores a
// header or token, never a body fragment.
func httpEvidence(r httpResponse, port int) []Evidence {
	var ev []Evidence
	add := func(value, tech, platform string) {
		if len(ev) >= maxHTTPEvidence {
			return
		}
		e := NewEvidence(SignalHTTPHeader, value, tech)
		e.Platform = platform
		ev = append(ev, e)
	}

	for _, v := range r.values("server") {
		lower := strings.ToLower(v)
		line := "Server: " + v
		platform := ""
		switch {
		case serverWindowsRe.MatchString(lower):
			platform = PlatformWindows
		case serverLinuxRe.MatchString(lower):
			platform = PlatformLinux
		}
		if strings.Contains(lower, "microsoft-httpapi") {
			// http.sys fronts WinRM, SSTP, ADFS and more; only the WinRM ports
			// name a product, everywhere else it is a Windows tell alone.
			tech := ""
			if port == 5985 || port == 5986 {
				tech = "winrm"
			}
			add(line, tech, PlatformWindows)
			continue
		}
		if tech := tellTech(lower); tech != "" {
			add(line, tech, platform)
			continue
		}
		if tech := classifyServerValue(lower); tech != "" {
			if tech == "iis" {
				platform = PlatformWindows
			}
			add(line, tech, platform)
		}
	}

	for _, v := range r.values("x-powered-by") {
		lower := strings.ToLower(v)
		line := "X-Powered-By: " + v
		switch {
		case strings.Contains(lower, "asp.net"):
			add(line, "iis", PlatformWindows)
		case strings.Contains(lower, "tomcat"):
			add(line, "tomcat", "")
		case strings.Contains(lower, "jetty"):
			add(line, "jetty", "")
		case strings.Contains(lower, "undertow") || strings.Contains(lower, "wildfly"):
			add(line, "wildfly", "")
		case strings.Contains(lower, "weblogic"):
			add(line, "weblogic", "")
		case strings.Contains(lower, "websphere"):
			add(line, "websphere", "")
		case strings.HasPrefix(lower, "express"):
			add(line, "node", "")
		}
	}
	for _, v := range r.values("x-aspnet-version") {
		add("X-AspNet-Version: "+v, "iis", PlatformWindows)
	}

	seenCookie := map[string]bool{}
	for _, c := range r.values("set-cookie") {
		name, _, _ := strings.Cut(c, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		for _, t := range cookieTells {
			if t.match(name) && !seenCookie[t.token] {
				seenCookie[t.token] = true
				add("Set-Cookie: "+t.token, t.tech, t.platform)
			}
		}
	}

	for _, v := range r.values("www-authenticate") {
		lower := strings.ToLower(v)
		// Scheme names only: a Negotiate challenge can carry a token.
		switch {
		case strings.HasPrefix(lower, "negotiate"):
			add("WWW-Authenticate: Negotiate", "", PlatformWindows)
		case strings.HasPrefix(lower, "ntlm"):
			add("WWW-Authenticate: NTLM", "", PlatformWindows)
		}
	}

	for _, e := range httpIdentityEvidence(r, port) {
		if len(ev) < maxHTTPEvidence {
			ev = append(ev, e)
		}
	}
	// Tomcat 8.5+ sends no Server header and no session cookie for a request
	// to an empty webapp root, but its 404/error report names the product.
	if tomcatErrorRe.MatchString(r.body) {
		add("body: Apache Tomcat error report", "tomcat", PlatformJava)
	}
	if m := owaTitleRe.FindStringSubmatch(r.body); m != nil {
		add("body: title="+strings.ToLower(m[1]), "exchange", PlatformWindows)
	}
	return ev
}

func tellTech(lowerServer string) string {
	for _, t := range serverTells {
		if strings.Contains(lowerServer, t.substr) {
			return t.tech
		}
	}
	return ""
}
