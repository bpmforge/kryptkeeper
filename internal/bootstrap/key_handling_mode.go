// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"sort"
	"strings"
)

// W23-46: where a target's private key is created and held. The mode is a
// declared attribute that the API validates; the renewal executor refuses a
// mode it cannot honour, and the key-custody report lists the effective mode
// of every target.
const (
	KeyModeClientCSR           = "client_csr"
	KeyModeHubGenerated        = "hub_generated"
	KeyModeHSMResidentCA       = "hsm_resident_ca"
	KeyModeMacOSNonExtractable = "macos_non_extractable"
)

var (
	errKeyHandlingModeUnsupported = errors.New("key_handling_mode is not supported in v1.0")
	errKeyHandlingModeInvalid     = errors.New("invalid key_handling_mode")
	errKeyHandlingModeMismatch    = errors.New("key_handling_mode is not compatible with install_mode")
	errRenewalKeyModeMismatch     = errors.New("target key_handling_mode is client_csr: the key is created on the host, so the hub does not generate or push one")
)

// keyModeSourceExplicit / keyModeSourceDerived say whether the effective mode
// was set on the target or derived from its install_mode.
const (
	keyModeSourceExplicit = "explicit"
	keyModeSourceDerived  = "derived"
)

// unsupportedKeyHandlingModes are recognised spellings of Windows CNG and TPM
// custody. They are rejected rather than silently accepted as labels: nothing
// in v1.0 can honour them.
var unsupportedKeyHandlingModes = map[string]bool{
	"windowscng": true, "cng": true, "tpm": true, "tpmresident": true, "windowsnonexportable": true,
}

type unsupportedKeyModeError struct{ mode string }

func (e unsupportedKeyModeError) Error() string {
	return `key_handling_mode "` + e.mode + `" is not supported in v1.0 (planned for v1.x)`
}
func (unsupportedKeyModeError) Is(target error) bool { return target == errKeyHandlingModeUnsupported }

type invalidKeyModeError struct{ mode string }

func (e invalidKeyModeError) Error() string {
	return `invalid key_handling_mode "` + e.mode + `": must be one of client_csr, hub_generated, hsm_resident_ca, macos_non_extractable`
}
func (invalidKeyModeError) Is(target error) bool { return target == errKeyHandlingModeInvalid }

func keyModeInstallModes(mode string) (allowed string, ok bool) {
	switch mode {
	case KeyModeClientCSR:
		return "agent|acme|cloud", true
	case KeyModeHubGenerated:
		return "ssh|f5|citrix|k8s|iis|sqlserver|rdp|exchange|plugin", true
	case KeyModeMacOSNonExtractable:
		return "keychain", true
	}
	return "", false
}

// validateKeyHandlingMode checks a mode against the install_mode it rides on.
// "" means unset (derived) and is always valid.
func validateKeyHandlingMode(mode, installMode string) error {
	if mode == "" {
		return nil
	}
	norm := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(mode))
	if unsupportedKeyHandlingModes[norm] {
		return unsupportedKeyModeError{mode: mode}
	}
	switch mode {
	case KeyModeClientCSR, KeyModeHubGenerated, KeyModeHSMResidentCA, KeyModeMacOSNonExtractable:
	default:
		return invalidKeyModeError{mode: mode}
	}
	// hsm_resident_ca is a label (CA keys held in PKCS#11/KMS, UC-M03 mode 3):
	// accepted with any install_mode and with no behavioural effect.
	if allowed, ok := keyModeInstallModes(mode); ok {
		for _, m := range strings.Split(allowed, "|") {
			if m == installMode {
				return nil
			}
		}
		return keyModeMismatchError{mode: mode, installMode: installMode, allowed: allowed}
	}
	return nil
}

type keyModeMismatchError struct{ mode, installMode, allowed string }

func (e keyModeMismatchError) Error() string {
	return "key_handling_mode " + e.mode + " is not compatible with install_mode " + e.installMode + " (needs " + strings.ReplaceAll(e.allowed, "|", ", ") + ")"
}
func (keyModeMismatchError) Is(target error) bool { return target == errKeyHandlingModeMismatch }

// effectiveKeyHandlingMode returns the explicit mode, else the one implied by
// the install_mode.
func effectiveKeyHandlingMode(t ManagedTarget) (mode, source string) {
	if t.KeyHandlingMode != "" {
		return t.KeyHandlingMode, keyModeSourceExplicit
	}
	switch t.InstallMode {
	case "agent", "acme", "cloud":
		return KeyModeClientCSR, keyModeSourceDerived
	case "keychain":
		return KeyModeMacOSNonExtractable, keyModeSourceDerived
	default: // ssh, f5, citrix, k8s, iis, sqlserver, rdp, exchange, plugin
		return KeyModeHubGenerated, keyModeSourceDerived
	}
}

// withEffectiveMode decorates a target for a response. The field is not
// persisted and is never read from a request body.
func withEffectiveMode(t ManagedTarget) ManagedTarget {
	t.EffectiveKeyHandlingMode, _ = effectiveKeyHandlingMode(t)
	return t
}

func withEffectiveModes(items []ManagedTarget) []ManagedTarget {
	out := make([]ManagedTarget, len(items))
	for i, t := range items {
		out[i] = withEffectiveMode(t)
	}
	return out
}

// TargetKeyModeEntry is one target's row in the key-custody report.
type TargetKeyModeEntry struct {
	TargetID    string `json:"target_id"`
	Name        string `json:"name"`
	Host        string `json:"host"`
	InstallMode string `json:"install_mode"`
	Mode        string `json:"mode"`
	Source      string `json:"source"`
}

func targetKeyModeEntries(items []ManagedTarget) []TargetKeyModeEntry {
	out := make([]TargetKeyModeEntry, 0, len(items))
	for _, t := range items {
		mode, source := effectiveKeyHandlingMode(t)
		out = append(out, TargetKeyModeEntry{TargetID: t.ID, Name: t.Name, Host: t.Host, InstallMode: t.InstallMode, Mode: mode, Source: source})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// withCredentialPrivileged marks targets whose credential is flagged
// privileged (W34-11). A missing store or credential leaves the target as is.
func withCredentialPrivileged(ctx context.Context, creds OutboundCredentialStore, items []ManagedTarget) []ManagedTarget {
	if creds == nil {
		return items
	}
	cache := map[string]bool{}
	out := make([]ManagedTarget, len(items))
	for i, t := range items {
		out[i] = t
		if t.CredentialRef == "" {
			continue
		}
		priv, seen := cache[t.CredentialRef]
		if !seen {
			if m, err := creds.Get(ctx, t.CredentialRef); err == nil {
				priv = m.Privileged
			}
			cache[t.CredentialRef] = priv
		}
		out[i].CredentialPrivileged = priv
	}
	return out
}
