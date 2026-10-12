// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package adsync

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

// LDAPClient abstracts LDAP operations for testability.
// Production implementation uses go-ldap/ldap/v3.
type LDAPClient interface {
	Search(baseDN string, filter string, attrs []string) ([]LDAPEntry, error)
	Add(dn string, attrs map[string][]string) error
	Modify(dn string, changes []LDAPChange) error
	Delete(dn string) error
	Close() error
}

// LDAPEntry represents an LDAP search result entry.
type LDAPEntry struct {
	DN         string
	Attributes map[string][]string
}

// LDAPChange represents a single attribute modification.
type LDAPChange struct {
	Operation string // add, replace, delete
	Attribute string
	Values    []string
}

// TemplateSync holds the ADCS template attributes to sync to AD.
type TemplateSync struct {
	Name                string
	DisplayName         string
	OID                 string
	SchemaVersion       int
	EnrollmentFlag      int
	PrivateKeyFlag      int
	CertificateNameFlag int
	MinimalKeySize      int
	ValidityPeriod      string
	RenewalOverlap      string
	KeyUsage            []string
	ExtendedKeyUsage    []string
}

// SyncResult tracks what happened during a sync operation.
type SyncResult struct {
	Created  int
	Updated  int
	Deleted  int
	Errors   []string
	Duration time.Duration
}

// Service manages synchronization of certificate templates to Active Directory.
type Service struct {
	client       LDAPClient
	configDN     string // e.g., CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com
	enrollmentDN string // e.g., CN=Enrollment Services,...
	serviceName  string // kryptkeeper service registration name
}

// NewService creates an AD sync service.
func NewService(client LDAPClient, configDN string, serviceName string) *Service {
	enrollmentDN := strings.Replace(configDN, "CN=Certificate Templates", "CN=Enrollment Services", 1)
	return &Service{
		client:       client,
		configDN:     configDN,
		enrollmentDN: enrollmentDN,
		serviceName:  serviceName,
	}
}

// SyncTemplates writes kryptkeeper templates to AD as pKICertificateTemplate objects.
func (s *Service) SyncTemplates(ctx context.Context, templates []TemplateSync) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{}

	existing, err := s.listExistingTemplates()
	if err != nil {
		return nil, fmt.Errorf("list existing templates: %w", err)
	}
	existingMap := make(map[string]LDAPEntry)
	for _, e := range existing {
		cn := getAttr(e.Attributes, "cn")
		if cn != "" {
			existingMap[cn] = e
		}
	}

	for _, tmpl := range templates {
		dn := fmt.Sprintf("CN=%s,%s", tmpl.Name, s.configDN)
		attrs := templateToLDAPAttrs(tmpl)

		if _, exists := existingMap[tmpl.Name]; exists {
			changes := buildModifyChanges(attrs)
			if err := s.client.Modify(dn, changes); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("modify %s: %v", tmpl.Name, err))
				continue
			}
			result.Updated++
			log.Printf("adsync: updated template %s", tmpl.Name)
		} else {
			if err := s.client.Add(dn, attrs); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("add %s: %v", tmpl.Name, err))
				continue
			}
			result.Created++
			log.Printf("adsync: created template %s", tmpl.Name)
		}
		delete(existingMap, tmpl.Name)
	}

	result.Duration = time.Since(start)
	return result, nil
}

// RegisterEnrollmentService creates the pKIEnrollmentService object in AD.
func (s *Service) RegisterEnrollmentService(caCertDER []byte, caName string) error {
	dn := fmt.Sprintf("CN=%s,%s", s.serviceName, s.enrollmentDN)
	attrs := map[string][]string{
		"objectClass":          {"pKIEnrollmentService"},
		"cn":                   {s.serviceName},
		"displayName":          {s.serviceName + " Certificate Enrollment"},
		"dNSHostName":          {s.serviceName},
		"cACertificate":        {string(caCertDER)},
		"certificateTemplates": {},
	}
	return s.client.Add(dn, attrs)
}

func (s *Service) listExistingTemplates() ([]LDAPEntry, error) {
	return s.client.Search(s.configDN, "(objectClass=pKICertificateTemplate)", []string{"cn", "msPKI-Cert-Template-OID"})
}

func templateToLDAPAttrs(t TemplateSync) map[string][]string {
	attrs := map[string][]string{
		"objectClass":                   {"pKICertificateTemplate"},
		"cn":                            {t.Name},
		"displayName":                   {t.DisplayName},
		"msPKI-Cert-Template-OID":       {t.OID},
		"msPKI-Template-Schema-Version": {fmt.Sprintf("%d", t.SchemaVersion)},
		"msPKI-Enrollment-Flag":         {fmt.Sprintf("%d", t.EnrollmentFlag)},
		"msPKI-Private-Key-Flag":        {fmt.Sprintf("%d", t.PrivateKeyFlag)},
		"msPKI-Certificate-Name-Flag":   {fmt.Sprintf("%d", t.CertificateNameFlag)},
		"msPKI-Minimal-Key-Size":        {fmt.Sprintf("%d", t.MinimalKeySize)},
		"pKIDefaultKeySpec":             {"1"},
	}
	if len(t.ExtendedKeyUsage) > 0 {
		attrs["pKIExtendedKeyUsage"] = t.ExtendedKeyUsage
	}
	return attrs
}

func buildModifyChanges(attrs map[string][]string) []LDAPChange {
	changes := make([]LDAPChange, 0, len(attrs))
	for k, v := range attrs {
		if k == "objectClass" || k == "cn" {
			continue
		}
		changes = append(changes, LDAPChange{Operation: "replace", Attribute: k, Values: v})
	}
	return changes
}

func getAttr(attrs map[string][]string, key string) string {
	vals := attrs[key]
	if len(vals) > 0 {
		return vals[0]
	}
	return ""
}
