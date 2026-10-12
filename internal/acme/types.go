// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto"
	"time"
)

// Account represents an ACME account.
type Account struct {
	ID            string           `json:"id"`
	Key           crypto.PublicKey `json:"-"`
	KeyThumbprint string           `json:"key_thumbprint"`
	Contact       []string         `json:"contact,omitempty"`
	Status        string           `json:"status"` // valid, deactivated, revoked
	CreatedAt     time.Time        `json:"created_at"`
}

// Order represents an ACME order.
type Order struct {
	ID             string       `json:"id"`
	AccountID      string       `json:"account_id"`
	Status         string       `json:"status"` // pending, ready, processing, valid, invalid
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
	NotBefore      *time.Time   `json:"notBefore,omitempty"`
	NotAfter       *time.Time   `json:"notAfter,omitempty"`
	Expires        time.Time    `json:"expires"`
	CreatedAt      time.Time    `json:"created_at"`
}

// Identifier is an identifier in an ACME order; only type "dns" is accepted.
type Identifier struct {
	Type  string `json:"type"` // dns, ip
	Value string `json:"value"`
}

// Authorization represents an ACME authorization.
type Authorization struct {
	ID         string      `json:"id"`
	AccountID  string      `json:"account_id"`
	Identifier Identifier  `json:"identifier"`
	Wildcard   bool        `json:"wildcard,omitempty"` // RFC 8555 §7.1.3; Identifier holds the base domain
	Status     string      `json:"status"`             // pending, valid, invalid, deactivated, expired, revoked
	Challenges []Challenge `json:"challenges"`
	Expires    time.Time   `json:"expires"`
}

// Challenge represents an ACME challenge.
type Challenge struct {
	Type      string     `json:"type"` // http-01, dns-01, tls-alpn-01
	URL       string     `json:"url"`
	Token     string     `json:"token"`
	Status    string     `json:"status"` // pending, processing, valid, invalid
	Validated *time.Time `json:"validated,omitempty"`
	Error     *Problem   `json:"error,omitempty"`
}

// Problem is an RFC 7807 problem detail for ACME errors.
type Problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

// Directory is the ACME directory object.
type Directory struct {
	NewNonce    string `json:"newNonce"`
	NewAccount  string `json:"newAccount"`
	NewOrder    string `json:"newOrder"`
	RevokeCert  string `json:"revokeCert"`
	KeyChange   string `json:"keyChange"`
	RenewalInfo string `json:"renewalInfo,omitempty"` // ARI (draft-ietf-acme-ari)
}

// RenewalInfoResponse is the response body for GET /acme/renewalInfo/{certID}.
// certID is base64url(issuerKeyHash) + "." + base64url(certSerial) per the ARI draft.
type RenewalInfoResponse struct {
	SuggestedWindow RenewalWindow `json:"suggestedWindow"`
	// ExplanationURL provides a human-readable reason for the renewal window (optional).
	ExplanationURL string `json:"explanationURL,omitempty"`
}

// RenewalWindow is the suggested renewal time range.
type RenewalWindow struct {
	Start string `json:"start"` // RFC 3339
	End   string `json:"end"`   // RFC 3339
}
