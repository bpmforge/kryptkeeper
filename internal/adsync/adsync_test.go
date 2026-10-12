// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package adsync

import (
	"context"
	"fmt"
	"testing"
)

// stubLDAPClient satisfies LDAPClient without a real LDAP server.
type stubLDAPClient struct {
	entries []LDAPEntry
	addErr  error
}

func (s *stubLDAPClient) Search(_ string, _ string, _ []string) ([]LDAPEntry, error) {
	return s.entries, nil
}
func (s *stubLDAPClient) Add(_ string, _ map[string][]string) error { return s.addErr }
func (s *stubLDAPClient) Modify(_ string, _ []LDAPChange) error     { return nil }
func (s *stubLDAPClient) Delete(_ string) error                     { return nil }
func (s *stubLDAPClient) Close() error                              { return nil }

func TestNewService(t *testing.T) {
	svc := NewService(&stubLDAPClient{}, "CN=config,DC=example,DC=com", "kryptkeeper-ca")
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestSyncTemplatesNoExisting(t *testing.T) {
	client := &stubLDAPClient{entries: []LDAPEntry{}}
	svc := NewService(client, "CN=config,DC=example,DC=com", "kryptkeeper-ca")

	templates := []TemplateSync{
		{Name: "WebServer", DisplayName: "Web Server", OID: "1.3.6.1.4.1.311.21.8.1"},
	}
	result, err := svc.SyncTemplates(context.Background(), templates)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Created != 1 {
		t.Errorf("expected 1 created, got %d", result.Created)
	}
}

func TestSyncTemplatesEmpty(t *testing.T) {
	client := &stubLDAPClient{entries: []LDAPEntry{}}
	svc := NewService(client, "CN=config,DC=example,DC=com", "kryptkeeper-ca")
	result, err := svc.SyncTemplates(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Created != 0 || result.Updated != 0 {
		t.Errorf("expected 0 changes, got created=%d updated=%d", result.Created, result.Updated)
	}
}

func TestSyncTemplatesUpdatesExisting(t *testing.T) {
	// Pre-populate with an existing template.
	client := &stubLDAPClient{
		entries: []LDAPEntry{
			{
				DN:         "CN=WebServer,CN=config,DC=example,DC=com",
				Attributes: map[string][]string{"cn": {"WebServer"}},
			},
		},
	}
	svc := NewService(client, "CN=config,DC=example,DC=com", "kryptkeeper-ca")

	templates := []TemplateSync{
		{Name: "WebServer", DisplayName: "Web Server Updated", OID: "1.3.6.1.4.1.311.21.8.1"},
	}
	result, err := svc.SyncTemplates(context.Background(), templates)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Updated != 1 {
		t.Errorf("expected 1 updated, got %d", result.Updated)
	}
	if result.Created != 0 {
		t.Errorf("expected 0 created, got %d", result.Created)
	}
}

func TestSyncTemplatesRecordsAddErrors(t *testing.T) {
	import_errors := fmt.Errorf("LDAP: insufficient permissions") //nolint:goerr113
	client := &stubLDAPClient{addErr: import_errors}
	svc := NewService(client, "CN=config,DC=example,DC=com", "kryptkeeper-ca")

	templates := []TemplateSync{
		{Name: "FailTemplate", DisplayName: "Fail", OID: "1.3.6.1.4.1.311.21.8.99"},
	}
	result, err := svc.SyncTemplates(context.Background(), templates)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error to be recorded in result")
	}
	if result.Created != 0 {
		t.Errorf("expected 0 created, got %d", result.Created)
	}
}

func TestRegisterEnrollmentService(t *testing.T) {
	client := &stubLDAPClient{}
	svc := NewService(client, "CN=config,DC=example,DC=com", "kryptkeeper-ca")
	if err := svc.RegisterEnrollmentService([]byte{0x30, 0x01, 0x00}, "KryptKeeper CA"); err != nil {
		t.Fatalf("RegisterEnrollmentService: %v", err)
	}
}

func TestGetAttr(t *testing.T) {
	attrs := map[string][]string{
		"cn":          {"test-value"},
		"displayName": {"Display", "Secondary"},
		"empty":       {},
	}
	if got := getAttr(attrs, "cn"); got != "test-value" {
		t.Errorf("getAttr cn = %q, want test-value", got)
	}
	if got := getAttr(attrs, "displayName"); got != "Display" {
		t.Errorf("getAttr displayName = %q, want Display", got)
	}
	if got := getAttr(attrs, "empty"); got != "" {
		t.Errorf("getAttr empty = %q, want empty string", got)
	}
	if got := getAttr(attrs, "missing"); got != "" {
		t.Errorf("getAttr missing = %q, want empty string", got)
	}
}

func TestBuildModifyChanges(t *testing.T) {
	attrs := map[string][]string{
		"objectClass": {"pKICertificateTemplate"},
		"cn":          {"WebServer"},
		"displayName": {"Web Server"},
	}
	changes := buildModifyChanges(attrs)
	// objectClass and cn should be skipped.
	for _, c := range changes {
		if c.Attribute == "objectClass" || c.Attribute == "cn" {
			t.Errorf("expected objectClass/cn to be filtered from changes, got %q", c.Attribute)
		}
		if c.Operation != "replace" {
			t.Errorf("expected replace operation, got %q", c.Operation)
		}
	}
	if len(changes) != 1 {
		t.Errorf("expected 1 change (displayName), got %d", len(changes))
	}
}
