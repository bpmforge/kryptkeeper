// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package abi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Manifest describes a plugin (manifest.json, next to its .wasm). The hub
// reads it before loading anything else and shows its capabilities to the
// operator in fixed wording (docs/design/DELIVERY_PLUGINS.md).
type Manifest struct {
	APIVersion string `json:"api_version"`
	// Kind says which family of operations the plugin serves (D-321). Absent
	// means "delivery", so every manifest written before kinds existed stays
	// valid byte for byte; ParseManifest fills the default on the parsed value
	// only, never in the stored JSON, because a signature covers those bytes.
	Kind             string           `json:"kind,omitempty"`
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Version          string           `json:"version"`
	Publisher        string           `json:"publisher"`
	License          string           `json:"license,omitempty"`
	Source           string           `json:"source,omitempty"`
	Artifact         Artifact         `json:"artifact"`
	Capabilities     Capabilities     `json:"capabilities"`
	CredentialSchema map[string]Field `json:"credential_schema,omitempty"`
	TargetSchema     map[string]Field `json:"target_schema,omitempty"`
	// Verification says how the hub proves a push landed: "" or "tls" dials
	// the target and fingerprints what it serves; "readback" (secret stores,
	// which serve nothing) asks the plugin for the stored PEM via OpVerify
	// and fingerprints that. Either way the hub decides, never the plugin.
	Verification string `json:"verification,omitempty"`
	// VerifyPropagationSeconds is how long after the quick verify attempts the
	// hub keeps polling for the pushed certificate (CDN edges and custom-cert
	// bindings take minutes to propagate). 0 keeps the quick attempts only.
	// The comparison is unchanged; only the time allowed for it to succeed.
	VerifyPropagationSeconds int `json:"verify_propagation_seconds,omitempty"`
}

// MaxVerifyPropagationSeconds bounds VerifyPropagationSeconds.
const MaxVerifyPropagationSeconds = 1800

// Verification modes a manifest may declare.
const (
	VerificationTLS      = "tls"
	VerificationReadback = "readback"
)

// Artifact pins the WebAssembly module.
type Artifact struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// Capabilities is everything a plugin may do beyond computing. Nothing
// undeclared is ever granted, and an unknown capability name refuses the
// manifest, so a plugin cannot ask for something the hub does not show.
type Capabilities struct {
	ReceivePrivateKey bool     `json:"receive_private_key,omitempty"`
	TrustStore        bool     `json:"trust_store,omitempty"`
	ElevatedExec      bool     `json:"elevated_exec,omitempty"`
	RemoteExec        bool     `json:"remote_exec,omitempty"`
	Network           *Network `json:"network,omitempty"`
	FileWrite         []string `json:"file_write,omitempty"`
	TLSVerify         bool     `json:"tls_verify,omitempty"`
	// ProvideCredentials belongs to the credentials kind (W38-07): the plugin
	// returns credentials the hub uses to log in to other systems. Critical,
	// so enabling such a plugin needs a second person. A credentials plugin
	// must declare it and no other kind may.
	ProvideCredentials bool `json:"provide_credentials,omitempty"`
}

// Network scopes outbound HTTPS. HostsFromCredential names the credential
// field (a URL) whose host the plugin may reach; Hosts lists any others.
type Network struct {
	HostsFromCredential string   `json:"hosts_from_credential,omitempty"`
	Hosts               []string `json:"hosts,omitempty"`
	Ports               []int    `json:"ports,omitempty"`
}

// Field is one credential or target setting.
type Field struct {
	Type     string `json:"type"`
	Required bool   `json:"required,omitempty"`
	Secret   bool   `json:"secret,omitempty"`
	Default  string `json:"default,omitempty"`
}

var (
	idPattern     = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9][a-z0-9-]*)+$`)
	semverPattern = regexp.MustCompile(`^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$`)
	hexPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fieldTypes    = map[string]bool{"string": true, "url": true, "pem": true, "int": true, "bool": true}
)

// ParseManifest decodes and validates a manifest. Unknown fields anywhere
// (including unknown capability names) are refused.
func ParseManifest(raw []byte) (Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("manifest: %w", err)
	}
	if dec.More() {
		return Manifest{}, errors.New("manifest: trailing data")
	}
	if m.Kind == "" {
		m.Kind = KindDelivery
	}
	return m, m.Validate()
}

// Validate checks a manifest's own consistency.
func (m Manifest) Validate() error {
	if err := m.validateKind(); err != nil {
		return err
	}
	switch {
	case m.APIVersion != APIVersion:
		return fmt.Errorf("manifest: api_version %q is not supported (want %s)", m.APIVersion, APIVersion)
	case !idPattern.MatchString(m.ID):
		return fmt.Errorf("manifest: id %q must be reverse-DNS style, e.g. community.a10-thunder", m.ID)
	case strings.TrimSpace(m.Name) == "" || strings.TrimSpace(m.Publisher) == "":
		return errors.New("manifest: name and publisher are required")
	case !semverPattern.MatchString(m.Version):
		return fmt.Errorf("manifest: version %q is not semver", m.Version)
	case m.Artifact.File == "" || strings.ContainsAny(m.Artifact.File, `/\`):
		return errors.New("manifest: artifact.file must be a bare file name")
	case !hexPattern.MatchString(m.Artifact.SHA256):
		return errors.New("manifest: artifact.sha256 must be 64 lowercase hex characters")
	case m.Verification != "" && m.Verification != VerificationTLS && m.Verification != VerificationReadback:
		return fmt.Errorf("manifest: verification %q is not supported (want %q or %q)", m.Verification, VerificationTLS, VerificationReadback)
	case m.VerifyPropagationSeconds < 0 || m.VerifyPropagationSeconds > MaxVerifyPropagationSeconds:
		return fmt.Errorf("manifest: verify_propagation_seconds %d out of range (0..%d)", m.VerifyPropagationSeconds, MaxVerifyPropagationSeconds)
	}
	if n := m.Capabilities.Network; n != nil {
		if n.HostsFromCredential == "" && len(n.Hosts) == 0 {
			return errors.New("manifest: network needs hosts_from_credential or hosts")
		}
		if n.HostsFromCredential != "" {
			f, ok := m.CredentialSchema[n.HostsFromCredential]
			if !ok || f.Type != "url" {
				return fmt.Errorf("manifest: network.hosts_from_credential %q must name a url field of credential_schema", n.HostsFromCredential)
			}
		}
		for _, h := range n.Hosts {
			if h == "" || strings.ContainsAny(h, "*/: ") {
				return fmt.Errorf("manifest: network host %q must be a plain host name", h)
			}
		}
		for _, p := range n.Ports {
			if p < 1 || p > 65535 {
				return fmt.Errorf("manifest: network port %d out of range", p)
			}
		}
	}
	for _, p := range m.Capabilities.FileWrite {
		if !strings.HasPrefix(p, "/") && !(len(p) > 2 && p[1] == ':') {
			return fmt.Errorf("manifest: file_write path %q must be absolute", p)
		}
		if strings.Contains(p, "..") {
			return fmt.Errorf("manifest: file_write path %q may not contain ..", p)
		}
	}
	if (m.Capabilities.ElevatedExec || m.Capabilities.TrustStore) && !m.Capabilities.RemoteExec {
		return errors.New("manifest: elevated_exec and trust_store need remote_exec")
	}
	for name, f := range m.CredentialSchema {
		if !fieldTypes[f.Type] {
			return fmt.Errorf("manifest: credential_schema.%s has unknown type %q", name, f.Type)
		}
	}
	for name, f := range m.TargetSchema {
		if !fieldTypes[f.Type] {
			return fmt.Errorf("manifest: target_schema.%s has unknown type %q", name, f.Type)
		}
		if f.Secret {
			return fmt.Errorf("manifest: target_schema.%s is marked secret; secrets belong in credential_schema", name)
		}
	}
	return nil
}

// Within reports whether every capability in c is also in declared, so a
// grant can never exceed what the manifest showed the operator.
func (c Capabilities) Within(declared Capabilities) bool {
	if (c.ProvideCredentials && !declared.ProvideCredentials) || (c.ReceivePrivateKey && !declared.ReceivePrivateKey) || (c.TrustStore && !declared.TrustStore) ||
		(c.ElevatedExec && !declared.ElevatedExec) || (c.RemoteExec && !declared.RemoteExec) ||
		(c.TLSVerify && !declared.TLSVerify) {
		return false
	}
	if c.Network != nil {
		d := declared.Network
		if d == nil || (c.Network.HostsFromCredential != "" && c.Network.HostsFromCredential != d.HostsFromCredential) ||
			!subset(c.Network.Hosts, d.Hosts) || !subsetInt(c.Network.Ports, d.Ports) {
			return false
		}
	}
	return subset(c.FileWrite, declared.FileWrite)
}

func subset(a, b []string) bool {
	set := make(map[string]bool, len(b))
	for _, v := range b {
		set[v] = true
	}
	for _, v := range a {
		if !set[v] {
			return false
		}
	}
	return true
}

func subsetInt(a, b []int) bool {
	if len(a) == 0 {
		return true
	}
	if len(b) == 0 {
		return false
	}
	set := make(map[int]bool, len(b))
	for _, v := range b {
		set[v] = true
	}
	for _, v := range a {
		if !set[v] {
			return false
		}
	}
	return true
}

// Capability tiers, as the hub shows and gates them (D-116).
const (
	TierCritical = "critical"
	TierHigh     = "high"
	TierStandard = "standard"
)

// Tier is the highest tier in c. Critical: the plugin receives private keys
// or changes trust stores. High: it runs commands, as admin or not, or has
// any network access (a fixed host list or the host named by a credential
// field: the latter is attacker-influenced configuration, so it is not a
// lesser grant). Standard: the rest.
func (c Capabilities) Tier() string {
	switch {
	case c.ReceivePrivateKey || c.TrustStore || c.ProvideCredentials:
		return TierCritical
	case c.ElevatedExec || c.RemoteExec || (c.Network != nil && (len(c.Network.Hosts) > 0 || c.Network.HostsFromCredential != "")):
		return TierHigh
	}
	return TierStandard
}

// validateKind checks the kind and the capabilities it may carry. Only a
// delivery plugin may ask for key material, trust-store changes, file writes
// or remote commands: the other kinds talk to one vendor API and get nothing
// that touches a certificate's private key or a managed host.
func (m Manifest) validateKind() error {
	kind := m.Kind
	if kind == "" {
		kind = KindDelivery
	}
	if kind == KindIssuer {
		return errors.New("manifest: kind \"issuer\" is reserved; issuer plugins are not supported by this hub yet")
	}
	if !Kinds[kind] {
		return fmt.Errorf("manifest: kind %q is not supported (want one of %s)", kind, strings.Join(KindNames(), ", "))
	}
	c := m.Capabilities
	// The capability is what makes the hub treat the plugin as Critical, so a
	// credentials plugin without it would slip past the second-person enable,
	// and any other kind carrying it would be mislabelled.
	switch {
	case kind == KindCredentials && !c.ProvideCredentials:
		return errors.New("manifest: a credentials plugin must declare provide_credentials")
	case kind != KindCredentials && c.ProvideCredentials:
		return fmt.Errorf("manifest: capability provide_credentials is only for the credentials kind, not %s", kind)
	}
	if kind != KindDelivery {
		switch {
		case c.ReceivePrivateKey, c.TrustStore, c.RemoteExec, c.ElevatedExec, len(c.FileWrite) > 0:
			return fmt.Errorf("manifest: a %s plugin may not declare receive_private_key, trust_store, remote_exec, elevated_exec or file_write", kind)
		case c.Network == nil:
			return fmt.Errorf("manifest: a %s plugin needs a network grant to reach its service", kind)
		}
	}
	return nil
}
