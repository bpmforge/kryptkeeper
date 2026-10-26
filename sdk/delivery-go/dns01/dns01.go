// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package dns01 is the Go SDK for Kryptkeeper DNS-01 plugins (kind "dns01",
// D-325): a plugin that writes and deletes the one TXT record an ACME DNS-01
// challenge needs at a DNS provider. It shares the sandbox, Host and ABI of
// delivery plugins; only the operations differ. The hub, not the plugin,
// checks that the record is visible before the CA validates.
package dns01

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

// Plugin publishes and removes challenge records.
type Plugin interface {
	Present(h *delivery.Host, req abi.DNS01PresentRequest) (abi.DNS01PresentResult, error)
	Cleanup(h *delivery.Host, req abi.DNS01CleanupRequest) (abi.DNS01CleanupResult, error)
}

// Register sets the plugin this module serves. Call it from init.
func Register(p Plugin) {
	delivery.RegisterHandler(func(h *delivery.Host, op string, in []byte) (json.RawMessage, error) {
		return Handle(p, h, op, in)
	})
}

// Handle runs one operation on p. It is exported for plugin tests that drive
// a plugin without WebAssembly.
func Handle(p Plugin, h *delivery.Host, op string, in []byte) (json.RawMessage, error) {
	switch op {
	case abi.OpDNS01Present:
		var req abi.DNS01PresentRequest
		if err := json.Unmarshal(in, &req); err != nil {
			return nil, err
		}
		if err := CheckName(req.FQDN, req.Value); err != nil {
			return nil, err
		}
		res, err := p.Present(h, req)
		if err != nil {
			return nil, err
		}
		return json.Marshal(res)
	case abi.OpDNS01Cleanup:
		var req abi.DNS01CleanupRequest
		if err := json.Unmarshal(in, &req); err != nil {
			return nil, err
		}
		if err := CheckName(req.FQDN, req.Value); err != nil {
			return nil, err
		}
		res, err := p.Cleanup(h, req)
		if err != nil {
			return nil, err
		}
		return json.Marshal(res)
	}
	return nil, fmt.Errorf("unknown operation %q for a dns01 plugin", op)
}

// CheckName refuses a request whose name or value could not be a challenge
// record, before any provider URL is built from it: the fqdn goes into URL
// paths, so characters that change a path, query or header are rejected.
func CheckName(fqdn, value string) error {
	if fqdn == "" || value == "" {
		return errors.New("fqdn and value are required")
	}
	if len(fqdn) > 253 || strings.HasSuffix(fqdn, ".") {
		return errors.New("fqdn must be a name without a trailing dot, at most 253 characters")
	}
	for _, r := range fqdn {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_'
		if !ok {
			return fmt.Errorf("fqdn has a character a DNS name cannot carry: %q", r)
		}
	}
	if len(value) > 255 {
		return errors.New("value must be at most 255 characters")
	}
	for _, r := range value {
		// Printable ASCII without quote or backslash: nothing a provider's
		// master-file or JSON encoding would need to escape.
		if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
			return fmt.Errorf("value has a character a plain TXT string cannot carry: %q", r)
		}
	}
	return nil
}

// ParentCandidates lists fqdn's parent names longest first, stopping before
// the bare TLD, so a delegated subzone wins over its parent.
func ParentCandidates(fqdn string) []string {
	labels := strings.Split(fqdn, ".")
	var out []string
	for i := 1; i < len(labels)-1; i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}

// RelativeName is fqdn relative to zone ("@" for the apex), the form
// providers whose record names are zone-relative take.
func RelativeName(fqdn, zone string) string {
	if strings.EqualFold(fqdn, zone) {
		return "@"
	}
	return strings.TrimSuffix(fqdn, "."+zone)
}

// Refused describes a provider answer that was not a success without
// echoing its body: a provider can reflect the request, and the request
// carries the credential.
func Refused(vendor, what string, resp abi.HTTPResponse) error {
	return fmt.Errorf("%s: %s: HTTP %d", vendor, what, resp.Status)
}

// RRSet is a provider that stores every TXT value of one name in a single
// record set (GoDaddy, NS1, Akamai): writing one value must keep the others,
// because a certificate for example.com and *.example.com puts two values at
// _acme-challenge.example.com. Values are in the provider's stored form;
// Encode and Decode convert between that and the plain value.
type RRSet interface {
	// Zone finds the zone that holds fqdn.
	Zone(fqdn string) (string, error)
	// Read returns the stored values at fqdn; none when the name has no TXT.
	Read(zone, fqdn string) ([]string, error)
	// Write replaces old with next: it creates the set when old is empty,
	// updates it, and deletes it when next is empty.
	Write(zone, fqdn string, old, next []string) error
	Encode(value string) string
	Decode(stored string) string
}

// PresentRRSet adds value to the set at fqdn, keeping what is already there.
// The record id is the zone, which is all cleanup needs besides the name.
func PresentRRSet(b RRSet, fqdn, value string) (abi.DNS01PresentResult, error) {
	zone, err := b.Zone(fqdn)
	if err != nil {
		return abi.DNS01PresentResult{}, err
	}
	old, err := b.Read(zone, fqdn)
	if err != nil {
		return abi.DNS01PresentResult{}, err
	}
	for _, s := range old {
		if b.Decode(s) == value {
			return abi.DNS01PresentResult{RecordID: zone, Zone: zone}, nil
		}
	}
	next := append(append([]string(nil), old...), b.Encode(value))
	if err := b.Write(zone, fqdn, old, next); err != nil {
		return abi.DNS01PresentResult{}, err
	}
	return abi.DNS01PresentResult{RecordID: zone, Zone: zone}, nil
}

// CleanupRRSet removes value from the set at fqdn and leaves every other
// value. A name or value that is already gone is success. recordID is the
// zone Present returned; an empty one is looked up again.
func CleanupRRSet(b RRSet, fqdn, value, recordID string) (abi.DNS01CleanupResult, error) {
	zone := recordID
	if zone == "" {
		var err error
		if zone, err = b.Zone(fqdn); err != nil {
			return abi.DNS01CleanupResult{}, err
		}
	}
	cur, err := b.Read(zone, fqdn)
	if err != nil {
		return abi.DNS01CleanupResult{}, err
	}
	rest := make([]string, 0, len(cur))
	for _, s := range cur {
		if b.Decode(s) != value {
			rest = append(rest, s)
		}
	}
	if len(rest) == len(cur) {
		return abi.DNS01CleanupResult{Removed: true}, nil
	}
	if err := b.Write(zone, fqdn, cur, rest); err != nil {
		return abi.DNS01CleanupResult{}, err
	}
	return abi.DNS01CleanupResult{Removed: true}, nil
}
