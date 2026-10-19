// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command azure is a delivery plugin that imports the renewed certificate
// into Azure Key Vault as a new certificate version and repoints an
// Application Gateway SSL certificate (mode appgw) or a Front Door secret
// (mode frontdoor) at that exact version. Both serve the certificate on the
// public name, so the hub verifies with the default TLS dial.
//
// The binding is always set to the VERSIONED secret id, so the swap is
// deterministic and reversible (Application Gateway reads a versionless id
// only on a four-hour poll). Rollback is the same ARM PUT with the prior
// value after a fresh GET. Superseded Key Vault versions are never deleted.
//
// The ARM documents are round-tripped as generic maps and only the one field
// is changed: a typed struct would silently drop fields on PUT.
//
// Minimum RBAC for the service principal (client_id / client_secret):
//   - Key Vault: Certificates import and get/list (for example the role
//     "Key Vault Certificates Officer", or a vault access policy with
//     certificate Import, Get and List).
//   - Application Gateway: write on the gateway (Network Contributor on it).
//   - Front Door: write on the profile's secrets (CDN Profile Contributor).
//
// The gateway's managed identity (or Front Door's service principal) needs
// Get on the vault's secrets separately; this plugin does not grant it.
//
// Token flow: client-credentials on the Microsoft identity platform v2
// endpoint, one token per resource (https://vault.azure.net/.default for Key
// Vault, https://management.azure.com/.default for ARM); scopes are not
// combined.
//
// Vendor limits to know: Application Gateway documents Key Vault TLS
// certificates as PFX, while this plugin imports PEM (the stdlib cannot
// build PFX); if the gateway refuses a PEM-backed secret the update fails
// provisioning and the prior binding is restored. Front Door does not
// support elliptic-curve certificates.
//
// API shapes: Key Vault certificates import (api-version 7.4), Application
// Gateway 2023-09-01 and Front Door secrets 2023-05-01.
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

func init() { delivery.Register(azure{}) }

func main() {}

type azure struct{}

const (
	modeAppGW     = "appgw"
	modeFrontDoor = "frontdoor"
)

var (
	guidPattern    = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	groupPattern   = regexp.MustCompile(`^[A-Za-z0-9._()-]{1,90}$`)
	resNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,80}$`)
	certNamePat    = regexp.MustCompile(`^[A-Za-z0-9-]{1,127}$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
	secretIDPat    = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(:[0-9]+)?/secrets/[A-Za-z0-9-]{1,127}(/[A-Za-z0-9]{1,64})?/?$`)
	tokenPattern   = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
)

type config struct {
	mode, sub, group, certName string
	gateway, sslCert           string // appgw
	profile, secret            string // frontdoor
}

func parse(inv abi.Invocation) (config, error) {
	t := inv.Target
	c := config{mode: t["mode"], sub: t["subscription_id"], group: t["resource_group"], certName: t["keyvault_cert_name"],
		gateway: t["gateway_name"], sslCert: t["ssl_certificate_name"], profile: t["profile_name"], secret: t["secret_name"]}
	for _, k := range []string{"vault_url", "tenant_id", "client_id", "client_secret"} {
		if inv.Credential[k] == "" {
			return c, fmt.Errorf("credential %s is required", k)
		}
	}
	switch {
	case !guidPattern.MatchString(c.sub):
		return c, errors.New("target subscription_id must be a GUID")
	case !groupPattern.MatchString(c.group):
		return c, errors.New("target resource_group is required")
	case !certNamePat.MatchString(c.certName):
		return c, errors.New("target keyvault_cert_name is required (letters, digits and - only)")
	}
	switch c.mode {
	case modeAppGW:
		if !resNamePattern.MatchString(c.gateway) || !resNamePattern.MatchString(c.sslCert) {
			return c, errors.New("target gateway_name and ssl_certificate_name are required for mode appgw")
		}
	case modeFrontDoor:
		if !resNamePattern.MatchString(c.profile) || !resNamePattern.MatchString(c.secret) {
			return c, errors.New("target profile_name and secret_name are required for mode frontdoor")
		}
	default:
		return c, errors.New("target mode must be appgw or frontdoor")
	}
	return c, nil
}

// handle is the RollbackHandle. Prior and New are the binding values (the
// secret id for appgw, the secret version for frontdoor); Prior is "" when
// there was nothing to return to.
type handle struct {
	Mode  string `json:"mode"`
	Prior string `json:"prior"`
	New   string `json:"new"`
	SID   string `json:"sid"`
}

func parseHandle(s string, c config) (handle, error) {
	var hd handle
	ok := json.Unmarshal([]byte(s), &hd) == nil && hd.Mode == c.mode
	if c.mode == modeAppGW {
		ok = ok && secretIDPat.MatchString(hd.New) && (hd.Prior == "" || secretIDPat.MatchString(hd.Prior))
	} else {
		ok = ok && versionPattern.MatchString(hd.New) && (hd.Prior == "" || versionPattern.MatchString(hd.Prior))
	}
	if !ok {
		return handle{}, errors.New("rollback handle is not an Azure handle")
	}
	return hd, nil
}

// binding is the ARM half of a delivery.
type binding interface {
	// current is the binding value now (secret id or version).
	current() (string, error)
	// set points the binding at value and waits for provisioning.
	set(value string) error
	// value maps a Key Vault import result to the binding value.
	value(imp imported) string
}

func newBinding(z *az, c config) binding {
	if c.mode == modeAppGW {
		return &appGW{z: z, c: c}
	}
	return &frontDoor{z: z, c: c}
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// leafFingerprint is the SHA-256 of the first certificate in certPEM.
func leafFingerprint(certPEM string) string {
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil || b.Type != "CERTIFICATE" {
		return ""
	}
	return sha256Hex(b.Bytes)
}

// pkcs8PEM re-encodes a private key as PKCS#8, the only format Key Vault
// accepts for a PEM import.
func pkcs8PEM(keyPEM string) (string, error) {
	b, _ := pem.Decode([]byte(keyPEM))
	if b == nil {
		return "", errors.New("private key is not PEM")
	}
	var key any
	var err error
	switch b.Type {
	case "PRIVATE KEY":
		return keyPEM, nil
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(b.Bytes)
	default:
		return "", errors.New("unsupported private key type")
	}
	if err != nil {
		return "", errors.New("private key is not parseable")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", errors.New("private key cannot be converted to PKCS#8")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func (azure) Validate(h *delivery.Host, req abi.ValidateRequest) error {
	c, err := parse(req.Invocation)
	if err != nil {
		return err
	}
	z := newAZ(h, req.Invocation)
	if _, err := newBinding(z, c).current(); err != nil {
		return err
	}
	return z.listCertificates()
}

func (azure) Push(h *delivery.Host, req abi.PushRequest) (abi.PushResult, error) {
	fail := func(outcome, detail string) (abi.PushResult, error) {
		return abi.PushResult{Outcome: outcome, Detail: detail}, nil
	}
	c, err := parse(req.Invocation)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	fp := leafFingerprint(req.CertPEM)
	if fp == "" {
		return fail(abi.OutcomeWriteFailed, "certificate is not PEM")
	}
	key, err := pkcs8PEM(req.KeyPEM)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	z := newAZ(h, req.Invocation)
	b := newBinding(z, c)

	// Nothing has changed if the binding cannot be read.
	prior, err := b.current()
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	imp, err := z.importCert(c.certName, req.CertPEM+"\n"+key, fp)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	hd := handle{Mode: c.mode, Prior: prior, New: b.value(imp), SID: imp.SID}

	err = b.set(hd.New)
	if err == nil {
		var got string
		if got, err = b.current(); err == nil && got != hd.New {
			err = errors.New("binding read back does not reference the imported version")
		}
	}
	if err != nil {
		detail := err.Error()
		switch {
		case prior == "":
			detail += "; no previous binding to restore"
		case prior != hd.New:
			if rerr := b.set(prior); rerr != nil {
				detail += "; RESTORE FAILED: " + rerr.Error()
			}
		}
		return fail(abi.OutcomeBindingFailed, detail)
	}
	raw, _ := json.Marshal(hd)
	return abi.PushResult{Installed: true, Outcome: abi.OutcomeInstalled, RollbackHandle: string(raw)}, nil
}

func (azure) Rollback(h *delivery.Host, req abi.RollbackRequest) (abi.RollbackResult, error) {
	c, err := parse(req.Invocation)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	hd, err := parseHandle(req.Handle, c)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	if hd.Prior == "" {
		return abi.RollbackResult{Detail: "no previous binding"}, nil
	}
	if err := newBinding(newAZ(h, req.Invocation), c).set(hd.Prior); err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	return abi.RollbackResult{RolledBack: true}, nil
}

// errCode returns a plain error code token from an Azure error body
// ({"error":{"code":"..."}}), or "".
func errCode(body []byte) string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	if !tokenPattern.MatchString(e.Error.Code) {
		return ""
	}
	return " " + strings.TrimSpace(e.Error.Code)
}
