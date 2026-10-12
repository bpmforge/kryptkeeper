// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package adsync

import (
	"fmt"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

// W17-10: the production LDAPClient this package's own contract has
// named since it was written ("Production implementation uses
// go-ldap/ldap/v3") but never had — it shipped with a stub only, because
// the dependency was unapproved. With go-ldap approved (2026-08-19, MIT)
// the package is completable.
//
// Writes here land in the AD Configuration naming context, where ADCS
// publishes certificate templates. That is a high-blast-radius container:
// every domain member reads it. So this client is deliberately thin —
// it maps the interface onto go-ldap and nothing more; policy about WHAT
// to write stays in Service.

// ldapDefaultPageSize matches AD's usual MaxPageSize. Paging is not
// optional: without the paged-results control (1.2.840.113556.1.4.319) a
// domain controller silently truncates a large result set with no error,
// so a partial template list would look complete. Same discipline as the
// W13-04 inventory pull.
const ldapDefaultPageSize = uint32(1000)

// GoLDAPClient implements LDAPClient over a real directory.
type GoLDAPClient struct {
	conn     *ldap.Conn
	pageSize uint32
}

// DialAndBind connects to the directory and authenticates.
//
// The URL scheme decides transport security: ldaps:// is TLS, ldap:// is
// cleartext. A simple bind sends the password, so a cleartext URL leaks
// the service credential to anyone on the path — refused here rather
// than left to the operator to notice, unless explicitly allowed.
func DialAndBind(url, bindDN, password string, allowCleartext bool) (*GoLDAPClient, error) {
	u := strings.TrimSpace(url)
	if !allowCleartext && !strings.HasPrefix(strings.ToLower(u), "ldaps://") {
		return nil, fmt.Errorf("adsync: refusing a simple bind over %q — a cleartext bind exposes the service credential; use ldaps:// or set allowCleartext explicitly", u)
	}
	conn, err := ldap.DialURL(u)
	if err != nil {
		return nil, fmt.Errorf("adsync: dial %s: %w", u, err)
	}
	if err := conn.Bind(bindDN, password); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("adsync: bind %s: %w", bindDN, err)
	}
	return &GoLDAPClient{conn: conn, pageSize: ldapDefaultPageSize}, nil
}

// Search runs a paged subtree search and returns every entry.
func (c *GoLDAPClient) Search(baseDN, filter string, attrs []string) ([]LDAPEntry, error) {
	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, attrs, nil,
	)
	res, err := c.conn.SearchWithPaging(req, c.pageSize)
	if err != nil {
		return nil, fmt.Errorf("adsync: search %s: %w", baseDN, err)
	}
	out := make([]LDAPEntry, 0, len(res.Entries))
	for _, e := range res.Entries {
		attrMap := make(map[string][]string, len(e.Attributes))
		for _, a := range e.Attributes {
			attrMap[a.Name] = a.Values
		}
		out = append(out, LDAPEntry{DN: e.DN, Attributes: attrMap})
	}
	return out, nil
}

func (c *GoLDAPClient) Add(dn string, attrs map[string][]string) error {
	req := ldap.NewAddRequest(dn, nil)
	for name, values := range attrs {
		req.Attribute(name, values)
	}
	if err := c.conn.Add(req); err != nil {
		return fmt.Errorf("adsync: add %s: %w", dn, err)
	}
	return nil
}

func (c *GoLDAPClient) Modify(dn string, changes []LDAPChange) error {
	req := ldap.NewModifyRequest(dn, nil)
	for _, ch := range changes {
		switch strings.ToLower(ch.Operation) {
		case "add":
			req.Add(ch.Attribute, ch.Values)
		case "replace":
			req.Replace(ch.Attribute, ch.Values)
		case "delete":
			req.Delete(ch.Attribute, ch.Values)
		default:
			// An unknown operation must not be silently dropped: that
			// would report a successful sync that did not happen.
			return fmt.Errorf("adsync: modify %s: unknown operation %q", dn, ch.Operation)
		}
	}
	if err := c.conn.Modify(req); err != nil {
		return fmt.Errorf("adsync: modify %s: %w", dn, err)
	}
	return nil
}

func (c *GoLDAPClient) Delete(dn string) error {
	if err := c.conn.Del(ldap.NewDelRequest(dn, nil)); err != nil {
		return fmt.Errorf("adsync: delete %s: %w", dn, err)
	}
	return nil
}

func (c *GoLDAPClient) Close() error { return c.conn.Close() }
