// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"strings"
)

// W34-04: identity tells that need the status line or a port to mean anything.
// They read the response probeHTTP already fetched with its one GET, so they
// cost no connection in any tier (D-206 restricts only the active probes).

var kubeStatusRe = regexp.MustCompile(`"kind"\s*:\s*"Status"`)

// winRMPort reports the WinRM listener ports. 5985 is plain HTTP and is never
// reached by a TLS scan; it is listed so the rule reads the same as the
// product's own port table.
func winRMPort(port int) bool { return port == 5985 || port == 5986 }

// httpIdentityEvidence returns the rows that name a Kubernetes API server or a
// WinRM service from one response.
//
//   - A JSON body of kind Status is what kube-apiserver answers an anonymous
//     request with (401 or 403). The body never reaches the evidence value.
//   - On a WinRM port, an unauthenticated request is answered 401 with a
//     Negotiate (or NTLM) challenge, or by http.sys (Microsoft-HTTPAPI). Either
//     names WinRM and a Windows host. Negotiate off a WinRM port stays the
//     platform-only vote httpEvidence already records.
func httpIdentityEvidence(r httpResponse, port int) []Evidence {
	var ev []Evidence
	if kubeStatusRe.MatchString(r.body) {
		ev = append(ev, withPlatform(NewEvidence(SignalHTTPHeader, "body: kind=Status", "kubernetes-api"), ""))
	}
	if winRMPort(port) && r.status == 401 {
		for _, v := range r.values("www-authenticate") {
			lower := strings.ToLower(v)
			switch {
			case strings.HasPrefix(lower, "negotiate"):
				ev = append(ev, withPlatform(NewEvidence(SignalHTTPHeader, "WWW-Authenticate: Negotiate (401 on WinRM port)", "winrm"), PlatformWindows))
			case strings.HasPrefix(lower, "ntlm"):
				ev = append(ev, withPlatform(NewEvidence(SignalHTTPHeader, "WWW-Authenticate: NTLM (401 on WinRM port)", "winrm"), PlatformWindows))
			}
		}
	}
	return ev
}

func withPlatform(e Evidence, platform string) Evidence {
	e.Platform = platform
	return e
}
