// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

// W13-04: live ADCS inventory sync. Microsoft ADCS publishes issued
// certificates into Active Directory as binary userCertificate
// attributes; this source pulls them READ-ONLY over LDAP v3, replacing
// the W11-05 export-file path for connected deployments. Synced certs
// enter as origin=synced / management_state=external like every other
// InventorySource.

const defaultADCSFilter = "(userCertificate=*)"

// adcsDefaultPageSize matches AD's usual MaxPageSize. The paged-results
// control (1.2.840.113556.1.4.319) is mandatory: without it a domain
// controller silently truncates the result set at MaxPageSize, so a
// large estate would be under-reported with no error. SearchWithPaging
// sends the control and buffers every page.
const adcsDefaultPageSize = uint32(1000)

// ldapConn is the injected LDAP boundary — *ldap.Conn satisfies it
// structurally, so the real adapter is zero-glue and tests inject a
// fake directory (the house provider pattern).
type ldapConn interface {
	Bind(username, password string) error
	SearchWithPaging(req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)
	Close() error
}

type adcsLiveSource struct {
	url        string
	bindDN     string
	password   string
	searchBase string
	filter     string
	pageSize   uint32
	dial       func(url string) (ldapConn, error)
}

func newADCSLiveSource(ctx context.Context, configJSON, credentialRef string, creds OutboundCredentialStore) (InventorySource, error) {
	var cfg struct {
		LDAPURL    string `json:"ldap_url"`
		BindDN     string `json:"bind_dn"`
		SearchBase string `json:"search_base"`
		Filter     string `json:"filter"`
		PageSize   uint32 `json:"page_size"`
	}
	_ = json.Unmarshal([]byte(configJSON), &cfg) // malformed config zeroes out; the required-field checks below catch it
	if cfg.LDAPURL == "" || cfg.SearchBase == "" {
		return nil, errors.New("adcs_live source requires config_json.ldap_url and config_json.search_base")
	}
	if credentialRef == "" || creds == nil {
		return nil, errors.New("adcs_live source requires credential_ref holding the LDAP bind password")
	}
	secret, err := creds.Resolve(ctx, credentialRef)
	if err != nil {
		return nil, fmt.Errorf("adcs_live credential %q: %w", credentialRef, err)
	}
	filter := cfg.Filter
	if filter == "" {
		filter = defaultADCSFilter
	}
	pageSize := cfg.PageSize
	if pageSize == 0 {
		pageSize = adcsDefaultPageSize
	}
	return &adcsLiveSource{
		url:        cfg.LDAPURL,
		bindDN:     cfg.BindDN,
		password:   adcsBindPassword(secret),
		searchBase: cfg.SearchBase,
		filter:     filter,
		pageSize:   pageSize,
		dial:       dialLDAP,
	}, nil
}

// adcsBindPassword unwraps the stored bind password; see credentialSecretString.
func adcsBindPassword(secret []byte) string {
	return credentialSecretString(secret, "password")
}

// credentialSecretString unwraps a stored single-secret credential.
// POST /api/v1/credentials keeps "payload" as raw JSON, so a secret stored as
// a JSON string arrives here still quoted; sending it with the quotes included
// is an auth failure the operator cannot diagnose. An object payload is read
// from field; a bare (non-JSON) secret is still accepted as-is.
func credentialSecretString(secret []byte, field string) string {
	trimmed := strings.TrimSpace(string(secret))
	var str string
	if json.Unmarshal([]byte(trimmed), &str) == nil {
		return str
	}
	var obj map[string]any
	if json.Unmarshal([]byte(trimmed), &obj) == nil {
		if v, ok := obj[field].(string); ok && v != "" {
			return v
		}
	}
	return trimmed
}

// dialLDAP is the default dialer; *ldap.Conn satisfies ldapConn.
func dialLDAP(url string) (ldapConn, error) {
	return ldap.DialURL(url)
}

func (s *adcsLiveSource) Fetch(_ context.Context) ([]SyncedCertificate, error) {
	conn, err := s.dial(s.url)
	if err != nil {
		return nil, fmt.Errorf("adcs_live dial %s: %w", s.url, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.Bind(s.bindDN, s.password); err != nil {
		return nil, fmt.Errorf("adcs_live bind %s: %w", s.bindDN, err)
	}

	req := ldap.NewSearchRequest(
		s.searchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		s.filter,
		[]string{"userCertificate"},
		nil,
	)
	res, err := conn.SearchWithPaging(req, s.pageSize)
	if err != nil {
		return nil, fmt.Errorf("adcs_live search %s: %w", s.searchBase, err)
	}

	var out []SyncedCertificate
	for _, entry := range res.Entries {
		for _, der := range entry.GetRawAttributeValues("userCertificate") {
			// A published userCertificate is DER. LDAP carries no
			// disposition, so status is active (same as the export
			// path); the W11-06 takeover flow changes management state.
			// Unparseable blobs are skipped, never fatal — one bad
			// directory row must not sink the whole sync.
			if _, perr := x509.ParseCertificate(der); perr != nil {
				continue
			}
			out = append(out, SyncedCertificate{
				PEM:            string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
				UpstreamStatus: "active",
			})
		}
	}
	return out, nil
}
