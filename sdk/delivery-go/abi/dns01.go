// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package abi

// Operations of the dns01 kind (D-325). A plugin only writes and deletes one
// TXT record at its DNS provider; the hub checks propagation itself with its
// own resolvers and the CA validates, so a plugin cannot make a challenge
// "pass" by saying so.
const (
	OpDNS01Present = "dns01.present"
	OpDNS01Cleanup = "dns01.cleanup"
)

// DNS01PresentRequest asks the plugin to publish TXT value at fqdn
// ("_acme-challenge.example.com", no trailing dot). Value is the challenge
// digest the CA will look for, not a secret. TTLSeconds is a hint: a provider
// with a higher minimum raises it.
type DNS01PresentRequest struct {
	Invocation
	FQDN       string `json:"fqdn"`
	Value      string `json:"value"`
	TTLSeconds int    `json:"ttl"`
}

// DNS01PresentResult says where the record went. RecordID is opaque to the
// hub and handed back to cleanup. Zone is the provider zone that holds the
// record, which the hub needs to find the authoritative name servers; it
// treats it as untrusted (it must be a suffix of the fqdn).
type DNS01PresentResult struct {
	RecordID string `json:"record_id"`
	Zone     string `json:"zone"`
}

// DNS01CleanupRequest removes the record Present wrote. Providers that keep
// one record set per name (GoDaddy, NS1, Akamai) hold other challenge values
// at the same name (a wildcard and its base name), so a plugin removes only
// Value and leaves the rest.
type DNS01CleanupRequest struct {
	Invocation
	FQDN     string `json:"fqdn"`
	Value    string `json:"value"`
	RecordID string `json:"record_id"`
}

// DNS01CleanupResult reports the removal. A record that is already gone is
// still Removed: cleanup is idempotent.
type DNS01CleanupResult struct {
	Removed bool `json:"removed"`
}
