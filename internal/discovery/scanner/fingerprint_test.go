// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"reflect"
	"strings"
	"testing"
)

func ev(signal, value, tech string) Evidence { return NewEvidence(signal, value, tech) }

func TestSignalWeights(t *testing.T) {
	want := map[string]int{
		SignalListener: 100, SignalHTTPHeader: 60, SignalBanner: 60, SignalRootDSE: 60, SignalTDS: 60,
		SignalCertIssuer: 40, SignalCertSubj: 40, SignalCertExt: 40, SignalTLSStack: 25, SignalPort: 10,
	}
	for sig, w := range want {
		if got := SignalWeight(sig); got != w {
			t.Errorf("SignalWeight(%s) = %d, want %d", sig, got, w)
		}
	}
	if SignalWeight("nonsense") != 0 {
		t.Error("an unknown signal must weigh nothing")
	}
}

func TestResolvePrecedenceAndConfidence(t *testing.T) {
	cases := []struct {
		name     string
		ev       []Evidence
		tech     string
		conf     string
		platform string
	}{
		{"no evidence", nil, TechUnknown, ConfidenceLow, PlatformUnknown},
		{"port only", []Evidence{ev(SignalPort, "winrm-https", "winrm")}, "winrm", ConfidenceLow, PlatformWindows},
		{"tls stack alone never names a tech", []Evidence{ev(SignalTLSStack, "jsse", "")}, TechUnknown, ConfidenceLow, PlatformJava},
		{"one header is medium", []Evidence{ev(SignalHTTPHeader, "Server: nginx/1.25", "nginx")}, "nginx", ConfidenceMedium, PlatformUnknown},
		{"one cert row is medium", []Evidence{ev(SignalCertIssuer, "CN=SSL_Self_Signed_Fallback", "mssql")}, "mssql", ConfidenceMedium, PlatformUnknown},
		{"listener alone is high", []Evidence{ev(SignalListener, "sqlservr", "mssql")}, "mssql", ConfidenceHigh, PlatformUnknown},
		{"listener with hidden uid is medium", []Evidence{{Signal: SignalListener, Value: "sqlservr", Tech: "mssql", Weight: 60}}, "mssql", ConfidenceMedium, PlatformUnknown},
		{"two independent strong signals are high", []Evidence{
			ev(SignalHTTPHeader, "Server: Apache-Coyote/1.1", "tomcat"),
			ev(SignalCertSubj, "CN=tomcat", "tomcat"),
		}, "tomcat", ConfidenceHigh, PlatformJava},
		{"two headers of one response are independent", []Evidence{
			ev(SignalHTTPHeader, "Server: Apache-Coyote/1.1", "tomcat"),
			ev(SignalHTTPHeader, "Set-Cookie: JSESSIONID", "tomcat"),
		}, "tomcat", ConfidenceHigh, PlatformJava},
		{"the same header twice is one observation", []Evidence{
			ev(SignalHTTPHeader, "Server: nginx", "nginx"),
			ev(SignalHTTPHeader, "Server: nginx", "nginx"),
		}, "nginx", ConfidenceMedium, PlatformUnknown},
		{"port and tls stack never lift confidence", []Evidence{
			ev(SignalPort, "kubernetes-api", "kubernetes-api"),
			ev(SignalTLSStack, "go", ""),
		}, "kubernetes-api", ConfidenceLow, PlatformUnknown},
		{"listener outranks a conflicting header", []Evidence{
			ev(SignalListener, "httpd", "apache"),
			ev(SignalHTTPHeader, "Server: nginx", "nginx"),
		}, "apache", ConfidenceHigh, PlatformUnknown},
		{"banner outranks certificate", []Evidence{
			ev(SignalBanner, "220 mail ESMTP Postfix", "postfix"),
			ev(SignalCertIssuer, "CN=Exim", "exim"),
		}, "postfix", ConfidenceMedium, PlatformLinux},
		{"certificate outranks port", []Evidence{
			ev(SignalCertSubj, "CN=vcenter", "vmware-vcenter"),
			ev(SignalPort, "postgres", "postgres"),
		}, "vmware-vcenter", ConfidenceMedium, PlatformAppliance},
		{"summed weak signals can beat one stronger one", []Evidence{
			ev(SignalCertIssuer, "a", "iis"), ev(SignalCertSubj, "b", "iis"),
			ev(SignalHTTPHeader, "Server: nginx", "nginx"),
		}, "iis", ConfidenceHigh, PlatformWindows},
		{"equal score, heavier single signal wins", []Evidence{
			ev(SignalHTTPHeader, "Server: nginx", "nginx"),
			ev(SignalCertIssuer, "x", "apache"), ev(SignalPort, "y", "apache"), ev(SignalPort, "z", "apache"),
		}, "nginx", ConfidenceMedium, PlatformUnknown},
		{"a true tie is unknown", []Evidence{
			ev(SignalHTTPHeader, "Server: nginx", "nginx"),
			ev(SignalBanner, "SSH-2.0-OpenSSH", "openssh"),
		}, TechUnknown, ConfidenceLow, PlatformUnknown},
		{"explicit platform vote without a tech", []Evidence{
			{Signal: SignalHTTPHeader, Value: "WWW-Authenticate: Negotiate", Weight: 60, Platform: PlatformWindows},
		}, TechUnknown, ConfidenceLow, PlatformWindows},
		{"platform tie is unknown", []Evidence{
			ev(SignalHTTPHeader, "Server: Microsoft-IIS/10.0", "iis"),
			ev(SignalBanner, "220 Postfix", "postfix"),
		}, TechUnknown, ConfidenceLow, PlatformUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fp := Resolve(c.ev)
			if fp.Tech != c.tech || fp.Confidence != c.conf || fp.Platform != c.platform {
				t.Fatalf("got tech=%s conf=%s platform=%s, want %s/%s/%s", fp.Tech, fp.Confidence, fp.Platform, c.tech, c.conf, c.platform)
			}
			if fp.Evidence == nil {
				t.Fatal("evidence must be an empty slice, never nil, so it serializes as []")
			}
		})
	}
}

func TestResolveIsDeterministicAndKeepsEvidenceOrderedByWeight(t *testing.T) {
	in := []Evidence{ev(SignalPort, "p", "nginx"), ev(SignalListener, "nginx", "nginx"), ev(SignalCertSubj, "c", "nginx")}
	first := Resolve(in)
	for i := 0; i < 20; i++ {
		if got := Resolve(in); !reflect.DeepEqual(got, first) {
			t.Fatalf("resolve is not deterministic: %+v vs %+v", got, first)
		}
	}
	if first.Evidence[0].Signal != SignalListener || first.Evidence[2].Signal != SignalPort {
		t.Fatalf("evidence not ordered by weight: %+v", first.Evidence)
	}
	if in[0].Signal != SignalPort {
		t.Fatal("Resolve must not reorder the caller's slice")
	}
}

func TestResolveTLSStackField(t *testing.T) {
	fp := Resolve([]Evidence{ev(SignalTLSStack, "SChannel", "")})
	if fp.TLSStack != "schannel" || fp.Platform != PlatformWindows {
		t.Fatalf("tls stack = %q platform = %q", fp.TLSStack, fp.Platform)
	}
	if got := Resolve(nil).TLSStack; got != "unknown" {
		t.Fatalf("default tls stack = %q", got)
	}
}

func TestNormalizeTech(t *testing.T) {
	cases := map[string]string{
		"":                       "",
		"  NGINX ":               "nginx",
		"litespeed":              "other:litespeed",
		"Other:Foo":              "other:foo",
		"gws/1.0 (weird)":        "other:gws1.0weird",
		"!!!":                    "",
		strings.Repeat("a", 100): "other:" + strings.Repeat("a", maxOtherToken),
	}
	for in, want := range cases {
		if got := NormalizeTech(in); got != want {
			t.Errorf("NormalizeTech(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEvidenceValueIsRedacted(t *testing.T) {
	e := NewEvidence(SignalHTTPHeader, "Server: x\x00\x1b[31m"+strings.Repeat("y", 500), "nginx")
	if len(e.Value) > maxEvidenceValue || strings.ContainsAny(e.Value, "\x00\x1b") {
		t.Fatalf("value not redacted: %q", e.Value)
	}
}

func TestIsWebServerTech(t *testing.T) {
	for _, tech := range []string{"nginx", "tomcat", "iis", "kestrel"} {
		if !IsWebServerTech(tech) {
			t.Errorf("%s should be a web server", tech)
		}
	}
	for _, tech := range []string{"mssql", "postfix", "other:litespeed", TechUnknown} {
		if IsWebServerTech(tech) {
			t.Errorf("%s should not be a web server", tech)
		}
	}
}

func TestEvidenceJSONRoundTrip(t *testing.T) {
	in := []Evidence{ev(SignalBanner, "SSH-2.0-OpenSSH_9.6", "openssh")}
	got := ParseEvidenceJSON(EvidenceJSON(in))
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("round trip: %+v != %+v", got, in)
	}
	if EvidenceJSON(nil) != "" || ParseEvidenceJSON("") != nil || ParseEvidenceJSON("{not json") != nil {
		t.Fatal("empty and malformed input must degrade to no evidence")
	}
}

func TestPortEvidence(t *testing.T) {
	if got := portEvidence("winrm-https"); len(got) != 1 || got[0].Tech != "winrm" || got[0].Weight != 10 {
		t.Fatalf("winrm port evidence = %+v", got)
	}
	for _, ambiguous := range []string{"https", "ldaps", "imaps", "tls", ""} {
		if portEvidence(ambiguous) != nil {
			t.Errorf("%q is ambiguous and must not vote", ambiguous)
		}
	}
}

// A port-only endpoint is a guess: low confidence, and never a recommendation.
func TestPortOnlyEndpointNeverRecommends(t *testing.T) {
	ep := DiscoveredEndpoint{Host: "h", Port: 5986, Protocol: "winrm-https", Reachable: true, Certs: []DiscoveredCert{{}}}
	out := finalizeFingerprint(ep, protocolForPort(5986))
	if out.Fingerprint == nil || out.Fingerprint.Tech != "winrm" || out.Fingerprint.Confidence != ConfidenceLow {
		t.Fatalf("fingerprint = %+v", out.Fingerprint)
	}
	if out.RecommendedInstallMode != "" || out.ServerTech != "" {
		t.Fatalf("port-only endpoint must not recommend or claim a server: %+v", out)
	}
}

func TestServerTechMirrorsWebServerFingerprint(t *testing.T) {
	ep := DiscoveredEndpoint{Host: "h", Port: 443, Protocol: "https", Reachable: true, Certs: []DiscoveredCert{{}},
		ServerTech: "apache-coyote/1.1",
		signals:    []Evidence{ev(SignalHTTPHeader, "Server: Apache-Coyote/1.1", "tomcat")}}
	out := finalizeFingerprint(ep, protocolForPort(443))
	if out.ServerTech != "tomcat" || out.Fingerprint.Confidence != ConfidenceMedium {
		t.Fatalf("server_tech = %q fp = %+v", out.ServerTech, out.Fingerprint)
	}
}

func TestUnreachableEndpointGetsNoFingerprint(t *testing.T) {
	out := finalizeFingerprint(DiscoveredEndpoint{Error: "tls dial: refused"}, protocolForPort(443))
	if out.Fingerprint != nil {
		t.Fatalf("a closed port must stay unrecorded: %+v", out.Fingerprint)
	}
}
