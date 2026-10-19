// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package tenantidor is a black-box cross-tenant IDOR harness: it replays every
// OpenAPI operation as several roles of one tenant against another tenant's
// seeded data and reports anything that reads or writes across the boundary.
package tenantidor

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
)

// Principal is one authenticated caller of the hub under test.
type Principal struct{ Tenant, Role, Token string }

// Leak is one cross-tenant read or write observed on the wire.
type Leak struct {
	Principal Principal
	Method    string
	Path      string
	Status    int
	Why       string
}

func (l Leak) String() string {
	return fmt.Sprintf("LEAK %s %s as %s/%s -> %d: %s", l.Method, l.Path, l.Principal.Tenant, l.Principal.Role, l.Status, l.Why)
}

// VictimSet is everything that belongs to the victim tenant. Marker is
// embedded in every seeded name; IDs holds the identifiers the harness
// substitutes into path params; Tenant is the victim tenant's own id, which
// is only meaningful in a request body (it is not secret on a response).
type VictimSet struct {
	Marker string
	IDs    map[string]bool
	Tenant string
}

func is2xx(status int) bool { return status >= 200 && status < 300 }

// Detect classifies one exchange from the response alone. 401/403/404 never
// leak; only a 2xx can.
func Detect(p Principal, method, path string, status int, body []byte, victim VictimSet) *Leak {
	return detect(p, method, path, status, nil, body, victim, false)
}

// DetectExchange is Detect plus the knowledge of how the request was built:
// reqBody is the JSON sent, subst reports that a path param carries a victim id.
func DetectExchange(p Principal, method, path string, reqBody []byte, status int, body []byte, victim VictimSet, subst bool) *Leak {
	return detect(p, method, path, status, reqBody, body, victim, subst)
}

func detect(p Principal, method, path string, status int, reqBody, body []byte, victim VictimSet, subst bool) *Leak {
	if !is2xx(status) || p.Tenant == "" {
		return nil
	}
	mk := func(why string) *Leak {
		return &Leak{Principal: p, Method: method, Path: path, Status: status, Why: why}
	}
	// A batch endpoint (bulk-revoke) answers 200 and lists every refused item
	// under "failed" with its id echoed back. That is a refusal, not a leak, so
	// only the "succeeded" half is judged.
	body, batchOK := stripBatchRefusals(body)
	switch route := strings.SplitN(path, "?", 2)[0]; {
	case strings.HasSuffix(route, "/audit"), strings.HasSuffix(route, "/audit/export"):
		body = stripOwnDeniedAuditRows(body, p.Tenant)
	}
	if victim.Marker != "" && bytes.Contains(body, []byte(victim.Marker)) {
		return mk("response body contains victim marker " + victim.Marker)
	}
	for id := range victim.IDs {
		if id != "" && bytes.Contains(body, []byte(id)) {
			return mk("response body contains victim id " + id)
		}
	}
	write := method != "GET" && method != "HEAD"
	if write {
		for id := range victim.IDs {
			if id != "" && strings.Contains(path, id) {
				return mk("write on victim id in path succeeded")
			}
		}
		for id := range victim.IDs {
			if id != "" && bytes.Contains(reqBody, []byte(id)) && batchOK {
				return mk("write referencing victim id " + id + " in body succeeded")
			}
		}
		if victim.Tenant != "" && bytes.Contains(reqBody, []byte(`"`+victim.Tenant+`"`)) && batchOK {
			return mk("write naming victim tenant " + victim.Tenant + " in body succeeded")
		}
	}
	if subst && batchOK {
		return mk("2xx on a path with victim identifiers substituted")
	}
	return nil
}

// stripBatchRefusals removes a top-level "failed" array from a batch response.
// ok is false when the response is a batch envelope in which nothing
// succeeded: the exchange then carries no cross-tenant effect at all.
func stripBatchRefusals(body []byte) (stripped []byte, ok bool) {
	var env map[string]json.RawMessage
	if json.Unmarshal(body, &env) != nil {
		return body, true
	}
	failed, hasFailed := env["failed"]
	succeeded, hasSucceeded := env["succeeded"]
	if !hasFailed || !hasSucceeded {
		return body, true
	}
	var f, s []json.RawMessage
	if json.Unmarshal(failed, &f) != nil || json.Unmarshal(succeeded, &s) != nil {
		return body, true
	}
	delete(env, "failed")
	out, err := json.Marshal(env)
	if err != nil {
		return body, true
	}
	return out, len(s) > 0
}

// stripOwnDeniedAuditRows drops audit rows that record the attacker's own
// refused probes. Those rows are stamped with the attacker's tenant and echo
// the victim id the attacker itself sent, so they disclose nothing. A row in
// the attacker's tenant with any other outcome is kept and still judged.
func stripOwnDeniedAuditRows(body []byte, attackerTenant string) []byte {
	own := func(tenant, outcome any) bool { return tenant == attackerTenant && outcome == "denied" }
	// GET /audit envelope, or the JSON export (a bare array).
	var env map[string]json.RawMessage
	if json.Unmarshal(body, &env) == nil {
		var rows []map[string]any
		if json.Unmarshal(env["data"], &rows) != nil {
			return body
		}
		kept := rows[:0]
		for _, row := range rows {
			if !own(row["tenant"], row["outcome"]) {
				kept = append(kept, row)
			}
		}
		data, err := json.Marshal(kept)
		if err != nil {
			return body
		}
		env["data"] = data
		if out, err := json.Marshal(env); err == nil {
			return out
		}
		return body
	}
	var arr []map[string]any
	if json.Unmarshal(body, &arr) == nil {
		kept := arr[:0]
		for _, row := range arr {
			if !own(row["tenant"], row["outcome"]) {
				kept = append(kept, row)
			}
		}
		if out, err := json.Marshal(kept); err == nil {
			return out
		}
		return body
	}
	// CSV export: locate the outcome and tenant columns from the header.
	recs, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil || len(recs) == 0 {
		return body
	}
	oi, ti := -1, -1
	for i, h := range recs[0] {
		switch h {
		case "outcome":
			oi = i
		case "tenant":
			ti = i
		}
	}
	if oi < 0 || ti < 0 {
		return body
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	for i, rec := range recs {
		if i > 0 && len(rec) > oi && len(rec) > ti && own(rec[ti], rec[oi]) {
			continue
		}
		_ = w.Write(rec)
	}
	w.Flush()
	return buf.Bytes()
}

// Allowlist is the set of design-global routes that are exempt from leak
// judgement. Every entry must carry a reason, so exemptions stay reviewable.
type Allowlist map[string]string

// ParseAllowlist reads `METHOD path<TAB>reason` lines. `#` starts a comment;
// a line without a reason is an error (fail closed).
func ParseAllowlist(data []byte) (Allowlist, error) {
	out := Allowlist{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, reason, ok := strings.Cut(line, "\t")
		reason = strings.TrimSpace(reason)
		if !ok || reason == "" {
			return nil, fmt.Errorf("allowlist line %d: missing tab-separated reason", n)
		}
		out[strings.TrimSpace(key)] = reason
	}
	return out, sc.Err()
}

// Allows reports whether METHOD + route template is exempt.
func (a Allowlist) Allows(method, route string) bool {
	_, ok := a[method+" "+route]
	return ok
}
