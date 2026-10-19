// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package tenantidor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Route is one OpenAPI operation. Path is the full template as served,
// including the /api/v1 prefix where the spec's server base applies.
type Route struct{ Method, Path string }

// Result is the suite outcome.
type Result struct {
	Routes   int
	Requests int
	Leaks    []Leak
	Elapsed  time.Duration
}

// nonexistentID is substituted where no victim collection matches, so the
// route is still exercised without pretending to be a cross-tenant probe.
const nonexistentID = "idor-nonexistent"

// LoadRoutes reads the `METHOD<TAB>path` file run.sh extracts from the spec.
func LoadRoutes(path string) ([]Route, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var out []Route
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		m, p, ok := strings.Cut(line, "\t")
		if !ok || !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("bad route line %q", line)
		}
		out = append(out, Route{Method: strings.ToUpper(m), Path: p})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no routes in %s (fail closed)", path)
	}
	return out, sc.Err()
}

// substitute fills {param} segments from the victim collection named by the
// preceding literal segment(s). subst reports that a victim id went in.
func substitute(path string, collections map[string]string) (string, bool) {
	segs := strings.Split(path, "/")
	subst := false
	for i, s := range segs {
		if !strings.HasPrefix(s, "{") {
			continue
		}
		val := nonexistentID
		if i >= 1 {
			if i >= 2 {
				if id, ok := collections[segs[i-2]+"/"+segs[i-1]]; ok {
					val, subst = id, true
					segs[i] = url.PathEscape(val)
					continue
				}
			}
			if id, ok := collections[segs[i-1]]; ok {
				val, subst = id, true
			}
		}
		segs[i] = url.PathEscape(val)
	}
	return strings.Join(segs, "/"), subst
}

// writeBody returns the request body for a write. Most routes get `{}`; a
// handful of well-known cross-tenant shapes (validation doc section 4) carry
// victim ids so a body-borne reference is actually exercised.
func (f *Fixture) writeBody(method, route string) []byte {
	g := func(k string) string {
		if v := f.ids[k]; v != "" {
			return v
		}
		return nonexistentID
	}
	var v any
	switch method + " " + route {
	case "POST /api/v1/api-keys":
		v = map[string]any{"name": "idor-probe", "principal_id": "idor-probe", "role": "pki-admin", "scopes": []string{"*"}, "tenant": VictimTenant}
	case "POST /api/v1/cas":
		v = map[string]any{"name": "idor-sub", "type": "intermediate", "subject_cn": "idor-sub", "parent_ca_id": g("ca")}
	case "POST /api/v1/certificates/bulk-revoke":
		v = map[string]any{"fingerprints": []string{g("certificate")}}
	case "POST /api/v1/notifications/silences":
		v = map[string]any{"target_type": "certificate", "target_id": g("certificate")}
	case "POST /api/v1/targets":
		v = map[string]any{"name": "idor-probe", "host": "idor-probe.example.test", "credential_ref": g("credential")}
	case "POST /api/v1/pending-actions":
		v = map[string]any{"action_type": "revoke", "params": map[string]any{"fingerprint": g("certificate")}}
	case "POST /api/v1/discovery/scan-jobs/requeue", "POST /api/v1/discovery/scan-jobs/cancel":
		v = map[string]any{"scan_job_id": g("discovery-scan")}
	default:
		return []byte("{}")
	}
	raw, _ := json.Marshal(v)
	return raw
}

// Run replays every route as every attacker: all reads first, then writes, so
// a destructive leak cannot hide later reads behind a deleted victim.
func Run(c *apiClient, f *Fixture, routes []Route, al Allowlist, logf func(string, ...any)) Result {
	start := time.Now()
	res := Result{Routes: len(routes)}
	probe := func(r Route) {
		path, subst := substitute(r.Path, f.Collections)
		if r.Method == http.MethodGet && strings.HasSuffix(path, "/search") {
			path += "?q=" + url.QueryEscape(f.Victim.Marker)
		}
		var body []byte
		if r.Method != http.MethodGet {
			body = f.writeBody(r.Method, r.Path)
		}
		for _, a := range f.Attackers {
			st, data, err := c.do(a.Token, r.Method, path, body)
			res.Requests++
			if err != nil {
				logf("transport error %s %s as %s: %v", r.Method, path, a.Role, err)
				continue
			}
			if al.Allows(r.Method, r.Path) {
				continue
			}
			if l := DetectExchange(a, r.Method, path, body, st, data, f.Victim, subst); l != nil {
				res.Leaks = append(res.Leaks, *l)
			}
		}
	}
	for _, r := range routes {
		if r.Method == http.MethodGet {
			probe(r)
		}
	}
	for _, r := range routes {
		if r.Method != http.MethodGet {
			probe(r)
		}
	}
	res.Elapsed = time.Since(start)
	return res
}
