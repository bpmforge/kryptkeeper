// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package sshkeys

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPolicyValidate(t *testing.T) {
	user := Policy{CertTypes: []string{"user"}, AllowedPrincipals: []string{"deploy", "ops.team-1"}, MaxTTLHours: 8}
	host := Policy{CertTypes: []string{"host"}, HostPatterns: []string{"*.corp.example", "build01.corp.example"}, MaxTTLHours: 720}
	cases := []struct {
		name string
		p    Policy
		bad  string
	}{
		{"user ok", user, ""},
		{"host ok", host, ""},
		{"both ok", Policy{CertTypes: []string{"user", "host"}, AllowedPrincipals: []string{"deploy"}, HostPatterns: []string{"a.example"}, MaxTTLHours: 24}, ""},
		{"no types", Policy{MaxTTLHours: 1}, "cert_types"},
		{"bad type", Policy{CertTypes: []string{"admin"}, MaxTTLHours: 1}, "cert_types"},
		{"dup type", Policy{CertTypes: []string{"user", "user"}, AllowedPrincipals: []string{"a"}, MaxTTLHours: 1}, "duplicate"},
		{"user no principals", Policy{CertTypes: []string{"user"}, MaxTTLHours: 1}, "allowed_principals is required"},
		{"wildcard principal", Policy{CertTypes: []string{"user"}, AllowedPrincipals: []string{"*"}, MaxTTLHours: 1}, "wildcards"},
		{"long principal", Policy{CertTypes: []string{"user"}, AllowedPrincipals: []string{strings.Repeat("a", 65)}, MaxTTLHours: 1}, "1-64"},
		{"space principal", Policy{CertTypes: []string{"user"}, AllowedPrincipals: []string{"a b"}, MaxTTLHours: 1}, "1-64"},
		{"host no patterns", Policy{CertTypes: []string{"host"}, MaxTTLHours: 1}, "host_patterns is required"},
		{"uppercase host", Policy{CertTypes: []string{"host"}, HostPatterns: []string{"Host.Example"}, MaxTTLHours: 1}, "DNS name"},
		{"mid wildcard", Policy{CertTypes: []string{"host"}, HostPatterns: []string{"a.*.example"}, MaxTTLHours: 1}, "DNS name"},
		{"bare wildcard", Policy{CertTypes: []string{"host"}, HostPatterns: []string{"*"}, MaxTTLHours: 1}, "DNS name"},
		{"double wildcard", Policy{CertTypes: []string{"host"}, HostPatterns: []string{"*.*.example"}, MaxTTLHours: 1}, "DNS name"},
		{"stray principals on host", Policy{CertTypes: []string{"host"}, HostPatterns: []string{"a.example"}, AllowedPrincipals: []string{"x"}, MaxTTLHours: 1}, "only meaningful"},
		{"zero ttl", Policy{CertTypes: []string{"user"}, AllowedPrincipals: []string{"a"}}, "max_ttl_hours"},
		{"user over ceiling", Policy{CertTypes: []string{"user"}, AllowedPrincipals: []string{"a"}, MaxTTLHours: 25}, "ceiling"},
		{"host over ceiling", Policy{CertTypes: []string{"host"}, HostPatterns: []string{"a.example"}, MaxTTLHours: 721}, "ceiling"},
		{"mixed over user ceiling", Policy{CertTypes: []string{"user", "host"}, AllowedPrincipals: []string{"a"}, HostPatterns: []string{"a.example"}, MaxTTLHours: 48}, "ceiling"},
	}
	for _, c := range cases {
		err := c.p.Validate()
		if c.bad == "" {
			if err != nil {
				t.Errorf("%s: unexpected %v", c.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.bad) {
			t.Errorf("%s: err %v, want containing %q", c.name, err, c.bad)
		}
	}
}

func TestMatchesHost(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"a.example", "a.example", true},
		{"a.example", "A.Example", true},
		{"a.example", "b.example", false},
		{"*.corp.example", "web.corp.example", true},
		{"*.corp.example", "a.b.corp.example", false},
		{"*.corp.example", "corp.example", false},
		{"*.corp.example", ".corp.example", false},
		{"*.corp.example", "evilcorp.example", false},
	}
	for _, c := range cases {
		if got := MatchesHost(c.pattern, c.name); got != c.want {
			t.Errorf("MatchesHost(%q,%q)=%v want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestPolicyCheck(t *testing.T) {
	p := Policy{CertTypes: []string{"user", "host"}, AllowedPrincipals: []string{"deploy"}, HostPatterns: []string{"*.corp.example"}, MaxTTLHours: 4}
	h := time.Hour
	denied := []struct {
		name  string
		typ   string
		princ []string
		ttl   time.Duration
	}{
		{"root", "user", []string{"root"}, h},
		{"one bad of two", "user", []string{"deploy", "root"}, h},
		{"no principals", "user", nil, h},
		{"wrong host", "host", []string{"evil.example"}, h},
		{"deep host", "host", []string{"a.b.corp.example"}, h},
		{"ttl over max", "user", []string{"deploy"}, 5 * h},
		{"unknown type", "admin", []string{"deploy"}, h},
	}
	for _, c := range denied {
		if _, err := p.Check(c.typ, c.princ, c.ttl); !errors.Is(err, ErrPolicyDenied) {
			t.Errorf("%s: err %v, want ErrPolicyDenied", c.name, err)
		}
	}
	hostOnly := Policy{CertTypes: []string{"host"}, HostPatterns: []string{"a.example"}, MaxTTLHours: 1}
	if _, err := hostOnly.Check("user", []string{"x"}, h); !errors.Is(err, ErrPolicyDenied) {
		t.Errorf("type not in policy: %v", err)
	}
	if ttl, err := p.Check("user", []string{"deploy"}, 3*h); err != nil || ttl != 3*h {
		t.Errorf("in-policy: %v %v", ttl, err)
	}
	if ttl, err := p.Check("user", []string{"deploy"}, 0); err != nil || ttl != 4*h {
		t.Errorf("default lowered to max: %v %v", ttl, err)
	}
	if ttl, err := p.Check("host", []string{"web.corp.example"}, 0); err != nil || ttl != 4*h {
		t.Errorf("host default lowered to max: %v %v", ttl, err)
	}
	big := Policy{CertTypes: []string{"user"}, AllowedPrincipals: []string{"deploy"}, MaxTTLHours: 24}
	if ttl, _ := big.Check("user", []string{"deploy"}, 0); ttl != UserCertDefaultTTL {
		t.Errorf("default kept when under max: %v", ttl)
	}
}
