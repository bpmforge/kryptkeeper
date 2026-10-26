// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package abi

// OpCredentialsGet is the one operation of the credentials kind: fetch one
// credential from the plugin's secret manager at the moment the hub needs it
// (W38-07, D-324). The plugin holds nothing between calls (each operation is a
// fresh instance) and the hub never stores what it returns.
const OpCredentialsGet = "credentials.get"

// CredentialsGetRequest asks for one credential. Invocation.Credential holds
// the fields that log the plugin in to its secret manager (the source's own
// credential); Reference says which secret to fetch (a CyberArk safe and
// object, a Secret Server secret id): its keys are the plugin's own and the
// hub passes them through untouched.
type CredentialsGetRequest struct {
	Invocation
	Reference map[string]string `json:"reference"`
}

// CredentialsGetResult is the credential. Fields are named for the payload
// the consuming credential type expects (private_key_pem and user for ssh_key,
// base_url, username and password for windows_password); the hub validates
// them against that type's shape and refuses the credential if they do not
// fit. LeaseSeconds is how long the manager says the value stays valid; the
// hub never caches past an operator-set TTL, and never past the lease.
type CredentialsGetResult struct {
	Fields       map[string]string `json:"fields"`
	LeaseSeconds int               `json:"lease_seconds,omitempty"`
}

// Limits the hub applies to a result so a hostile or broken plugin cannot
// hand it an unbounded payload.
const (
	MaxCredentialFields     = 32
	MaxCredentialFieldBytes = 64 << 10
)
