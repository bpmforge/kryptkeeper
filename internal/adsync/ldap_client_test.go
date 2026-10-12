// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package adsync

import (
	"strings"
	"testing"
)

// W17-10: the production LDAP client. A real directory is not available
// in unit tests, so these pin the decisions that are ours rather than
// go-ldap's: transport safety, unknown-operation handling, and that
// GoLDAPClient actually satisfies the contract it was written for.

// The whole point of the ticket: the package's named production client
// must satisfy its own interface.
func TestGoLDAPClientSatisfiesLDAPClient(t *testing.T) {
	var _ LDAPClient = (*GoLDAPClient)(nil)
}

// A simple bind sends the password. Over cleartext ldap:// that hands
// the service credential to anyone on the path, so it is refused unless
// explicitly allowed.
func TestDialRefusesCleartextBindByDefault(t *testing.T) {
	_, err := DialAndBind("ldap://dc.example.com:389", "CN=svc", "s3cret", false)
	if err == nil {
		t.Fatal("a cleartext simple bind must be refused by default")
	}
	if !strings.Contains(err.Error(), "cleartext") {
		t.Fatalf("the refusal must name the reason, got %v", err)
	}
	// And it must refuse BEFORE dialling — the error must not be a
	// network error from an attempted connection.
	if strings.Contains(err.Error(), "dial") {
		t.Fatalf("the guard must refuse before dialling, got %v", err)
	}
}

// The escape hatch exists (lab/test directories), and when taken the
// guard must not be what fails — a dial failure proves it got past it.
func TestDialAllowsCleartextWhenExplicit(t *testing.T) {
	_, err := DialAndBind("ldap://127.0.0.1:1/", "CN=svc", "s3cret", true)
	if err == nil {
		t.Fatal("expected a dial failure against a dead port")
	}
	if strings.Contains(err.Error(), "cleartext") {
		t.Fatalf("explicit opt-in must bypass the transport guard, got %v", err)
	}
}

// An unknown modify operation must error rather than be dropped:
// silently skipping it would report a successful sync that did not
// happen.
func TestModifyRejectsUnknownOperation(t *testing.T) {
	c := &GoLDAPClient{} // conn unused: the guard fires before any I/O
	err := c.Modify("CN=t,CN=Configuration", []LDAPChange{
		{Operation: "frobnicate", Attribute: "displayName", Values: []string{"x"}},
	})
	if err == nil {
		t.Fatal("an unknown modify operation must not be silently dropped")
	}
	if !strings.Contains(err.Error(), "frobnicate") {
		t.Fatalf("the error must name the offending operation, got %v", err)
	}
}

// Paging must be requested with a non-zero size, or a domain controller
// silently truncates at MaxPageSize and a partial result looks complete.
func TestDefaultPageSizeIsNonZero(t *testing.T) {
	if ldapDefaultPageSize == 0 {
		t.Fatal("a zero page size disables the paged-results control")
	}
	c := &GoLDAPClient{pageSize: ldapDefaultPageSize}
	if c.pageSize == 0 {
		t.Fatal("the client must carry a non-zero page size")
	}
}
