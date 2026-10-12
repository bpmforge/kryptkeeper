// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

// Per-source rate ceilings for the two unauthenticated SAML SSO endpoints,
// matching the shape of the OIDC login/callback pair (auth_oidc_login.go)
// without their per-client-keying refinement -- that's W6-11/W6-12's
// concern, out of this ticket's write_scope to extend. allowRateLimit
// requires every caller to share the same window (auth_rate_limit.go's
// sweep-budget comment), so this reuses time.Minute like every other bucket
// in the package.
const (
	defaultSAMLLoginLimit = 120
	defaultSAMLACSLimit   = 120
)

// parseSAMLIDPCertificatesPEM parses one or more concatenated PEM-encoded
// X.509 certificates -- operator-supplied IdP signing certificate(s),
// acceptance #6 -- into the roots samlServiceProviderFromConfig's
// IDPCertificateStore validates SAML Response signatures against. A
// malformed block is skipped with a warning rather than failing the whole
// configuration, matching this package's existing tolerant-parse convention
// (e.g. APP_SCIM_GROUP_ROLE_MAP_JSON in auth_config.go).
func parseSAMLIDPCertificatesPEM(raw string) []*x509.Certificate {
	var certs []*x509.Certificate
	rest := []byte(raw)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("warning: invalid SAML IdP certificate PEM block; skipping: %v", err)
			continue
		}
		certs = append(certs, cert)
	}
	return certs
}

// samlServiceProviderFromConfig builds the gosaml2 SP used to build
// AuthnRequests (acceptance #2) and validate Responses (acceptance #3/#4)
// from operator-supplied IdP metadata/certificates (acceptance #6,
// auth_config.go). Returns nil when SAML login isn't enabled or is missing a
// required field, so callers fail closed (503) instead of constructing a
// half-configured SP that would validate against an empty certificate store.
//
// SignAuthnRequests is left at its zero value (false): Kryptkeeper is a
// Service Provider only -- never an IdP, the reason gosaml2 was chosen over
// crewjam/saml (see plan.json's W6-09 notes) -- and signing the outbound
// AuthnRequest needs an SP private key this ticket's acceptance criteria
// never asks for. Most IdPs do not require a signed AuthnRequest; one that
// does is a follow-up, not silently unsupported here.
func samlServiceProviderFromConfig(cfg authValidatorConfig) *saml2.SAMLServiceProvider {
	if !cfg.samlLoginEnabled {
		return nil
	}
	if cfg.samlIDPSSOURL == "" || cfg.samlIDPIssuer == "" || cfg.samlSPIssuer == "" ||
		cfg.samlACSURL == "" || len(cfg.samlIDPCertificates) == 0 || cfg.loginSigning == "" {
		return nil
	}
	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      cfg.samlIDPSSOURL,
		IdentityProviderIssuer:      cfg.samlIDPIssuer,
		ServiceProviderIssuer:       cfg.samlSPIssuer,
		AssertionConsumerServiceURL: cfg.samlACSURL,
		AudienceURI:                 firstNonEmpty(cfg.samlAudience, cfg.samlSPIssuer),
		IDPCertificateStore: &dsig.MemoryX509CertificateStore{
			Roots: cfg.samlIDPCertificates,
		},
	}
}

// samlAssertionEmail resolves the account-matching email out of a validated
// assertion: an Email/email attribute if the IdP sends one, else the NameID
// itself -- many IdPs issue NameID with Format=emailAddress, the same
// convention OIDC login relies on its ID token's "email" claim for
// (auth_oidc_login.go).
func samlAssertionEmail(info *saml2.AssertionInfo) string {
	if email := strings.TrimSpace(info.Values.Get("Email")); email != "" {
		return email
	}
	if email := strings.TrimSpace(info.Values.Get("email")); email != "" {
		return email
	}
	return strings.TrimSpace(info.NameID)
}

// safeRelativeRedirect returns raw when it is a same-origin relative path,
// else fallback. It guards every post-login redirect (the SAML ?redirect= and
// RelayState echo, and the configured OIDC/SAML landing paths) against open
// redirects. Browsers rewrite "\" to "/" while resolving a Location, so
// "/\evil.example" would otherwise leave the origin (A2A7-005 / A07-1): the
// path must start with a single "/" and may contain no backslash or control
// character anywhere.
func safeRelativeRedirect(raw string, fallback string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '/' {
		return fallback
	}
	if len(raw) > 1 && (raw[1] == '/' || raw[1] == '\\') {
		return fallback
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' || raw[i] < 0x20 || raw[i] == 0x7f {
			return fallback
		}
	}
	if u, err := url.Parse(raw); err != nil || u.Scheme != "" || u.Host != "" {
		return fallback
	}
	return raw
}

// registerSAMLLoginHandlers wires the browser-facing SAML SSO login flow: a
// GET redirect endpoint (SP-initiated AuthnRequest, acceptance #2) and a
// POST assertion consumer service endpoint (HTTP-POST binding, the only
// binding this SP advertises -- see samlServiceProviderFromConfig).
// userProvider resolves the assertion's identity to an already-provisioned
// Kryptkeeper account, mirroring OIDC login's policy (auth_oidc_login.go):
// SCIM/an operator provisions accounts, this endpoint never creates one.
//
// The session minted below (Authenticator.mintSessionForUser, auth.go) is
// redeemed on every subsequent request by authenticateBootstrap's
// login-session-JWT branch (auth_bootstrap.go), gated on
// cfg.anyLoginFlowEnabled() -- which includes cfg.samlLoginEnabled (W6-13),
// so a SAML-only deployment (APP_SAML_LOGIN_ENABLED=true, password login and
// OIDC login both off) survives the request after the one that established
// it. TestSAMLACS_HappyPath_EstablishesSessionAndDeniesAdminAction
// (auth_saml_test.go) exercises a genuine SAML-only config end-to-end.
func registerSAMLLoginHandlers(mux *http.ServeMux, auth *Authenticator, userProvider UserProvider, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/auth/saml/login", getOnly(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		if !auth.allowRateLimit("saml-login:"+clientIP(r), defaultSAMLLoginLimit, time.Minute, now) {
			writeTooManyRequests(w, "rate limit exceeded")
			return
		}

		sp := samlServiceProviderFromConfig(auth.config)
		if sp == nil {
			emitAuditEvent(r, auditProvider, "", "auth.saml.login", "auth", "saml-login", AuditOutcomeFailure)
			writeServiceUnavailable(w, "saml login unavailable")
			return
		}

		relayState := safeRelativeRedirect(r.URL.Query().Get("redirect"), "")

		// Same as sp.BuildAuthURL(relayState), but built from the document so
		// the request ID is known: the ACS accepts a response only if its
		// InResponseTo names a request recorded here (A2A7-008).
		doc, err := sp.BuildAuthRequestDocument()
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "auth.saml.login", "auth", "saml-login", AuditOutcomeFailure)
			writeServiceUnavailable(w, "saml login unavailable")
			return
		}
		requestID := ""
		if root := doc.Root(); root != nil {
			requestID = root.SelectAttrValue("ID", "")
		}
		redirectURL, err := sp.BuildAuthURLFromDocument(relayState, doc)
		if err != nil || requestID == "" {
			emitAuditEvent(r, auditProvider, "", "auth.saml.login", "auth", "saml-login", AuditOutcomeFailure)
			writeServiceUnavailable(w, "saml login unavailable")
			return
		}
		if !auth.hardening.saml.issueRequest(requestID, now) {
			// Fail closed, retryable: no redirect without a recorded request.
			emitAuditEvent(r, auditProvider, "", "auth.saml.login", "auth", "saml-login", AuditOutcomeFailure)
			writeTooManyRequests(w, "too many pending saml logins")
			return
		}

		emitAuditEvent(r, auditProvider, "", "auth.saml.login", "auth", "saml-login", AuditOutcomeSuccess)
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}))

	mux.HandleFunc("/api/v1/auth/saml/acs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}

		now := time.Now()
		if !auth.allowRateLimit("saml-acs:"+clientIP(r), defaultSAMLACSLimit, time.Minute, now) {
			writeTooManyRequests(w, "rate limit exceeded")
			return
		}

		sp := samlServiceProviderFromConfig(auth.config)
		if sp == nil {
			emitAuditEvent(r, auditProvider, "", "auth.saml.acs", "auth", "saml-acs", AuditOutcomeFailure)
			writeServiceUnavailable(w, "saml login unavailable")
			return
		}

		if err := r.ParseForm(); err != nil {
			emitAuditEvent(r, auditProvider, "", "auth.saml.acs", "auth", "saml-acs", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		encodedResponse := strings.TrimSpace(r.PostFormValue("SAMLResponse"))
		if encodedResponse == "" {
			emitAuditEvent(r, auditProvider, "", "auth.saml.acs", "auth", "saml-acs", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		// The literal call acceptance #2 requires. A non-nil err here covers
		// a malformed/undecodable response, a bad envelope or per-assertion
		// signature, a missing Subject/NameID, a non-Success status --
		// AND acceptance #4's signature-wrapping (XSW) attempt: a wrapped
		// or second Assertion element fails gosaml2's per-assertion/envelope
		// signature verification and surfaces here as an error, not below.
		assertionInfo, err := sp.RetrieveAssertionInfo(encodedResponse)
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "auth.saml.acs", "auth", "saml-acs", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		// MANDATORY (acceptance #3): an expired assertion or one addressed
		// to a different audience comes back as a WARNING on
		// AssertionInfo.WarningInfo, not as the non-nil error handled above
		// -- checking only err would accept both. A nil WarningInfo is
		// treated as fail-closed too: gosaml2 always populates it on the
		// success path RetrieveAssertionInfo returns, but this is a PKI
		// product and a defensive nil check here costs nothing.
		if assertionInfo.WarningInfo == nil || assertionInfo.WarningInfo.InvalidTime || assertionInfo.WarningInfo.NotInAudience {
			emitAuditEvent(r, auditProvider, "", "auth.saml.acs", "auth", "saml-acs", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		// MANDATORY (acceptance #3): reject unless the Response envelope
		// itself was signature-verified. gosaml2 also accepts a response
		// that is unsigned overall but carries an individually-signed
		// Assertion (ResponseSignatureValidated stays false in that case);
		// requiring the stricter envelope-level proof here is the
		// deliberate, simpler fail-safe this criterion asks for.
		if !assertionInfo.ResponseSignatureValidated {
			emitAuditEvent(r, auditProvider, "", "auth.saml.acs", "auth", "saml-acs", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		// A2A7-008 / A07-2: the response must answer a request this hub issued
		// (InResponseTo) and its assertion IDs must be unseen. An unsolicited
		// (IdP-initiated) response is refused unless the operator opted in.
		if !auth.hardening.saml.checkSAMLResponseFreshness(assertionInfo.Assertions, samlIdPInitiatedAllowed(), now) {
			emitAuditEvent(r, auditProvider, "", "auth.saml.acs", "auth", "saml-acs", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		email := samlAssertionEmail(assertionInfo)
		if email == "" {
			emitAuditEvent(r, auditProvider, "", "auth.saml.acs", "auth", "saml-acs", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		user, found, err := findUserByEmail(r.Context(), userProvider, email)
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "auth.saml.acs", "auth", "saml-acs", AuditOutcomeFailure)
			writeServiceUnavailable(w, "user lookup unavailable")
			return
		}
		if !found {
			// No SCIM/operator-provisioned account for this identity --
			// provisioning is SCIM's job, not this login flow's (mirrors
			// OIDC login's policy, auth_oidc_login.go): no just-in-time
			// account creation here.
			emitAuditEvent(r, auditProvider, "", "auth.saml.acs", "auth", "saml-acs", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if isDeprovisionedStatus(user.Status) {
			emitAuditEvent(r, auditProvider, user.ID, "auth.saml.acs", "auth", "saml-acs", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		// Establishes the SAME session POST /api/v1/auth/login and the OIDC
		// callback issue (acceptance #5): user.Role is the SCIM/operator-
		// resolved UserRecord.Role (S-34), embedded as the session's "role"
		// claim by mintHS256JWT and recovered by authenticateBootstrap on
		// every subsequent request via its login-session-JWT branch (auth
		// type "local", never "bootstrap") -- a SAML principal never
		// reaches authenticateBootstrap's raw-bootstrap-token branch, which
		// only ever matches the literal bootstrap token value.
		accessToken, accessTTL, _, _, err := auth.mintSessionForUser(user.ID, user.Role, now)
		if err != nil {
			emitAuditEvent(r, auditProvider, user.ID, "auth.saml.acs", "auth", "saml-acs", AuditOutcomeFailure)
			writeServiceUnavailable(w, "saml login unavailable")
			return
		}

		setSessionCookie(w, r, accessToken, accessTTL)
		emitAuditEvent(r, auditProvider, user.ID, "auth.saml.acs", "auth", "saml-acs", AuditOutcomeSuccess)

		redirect := safeRelativeRedirect(r.PostFormValue("RelayState"), safeRelativeRedirect(auth.config.samlPostLoginRedirectURL, "/"))
		http.Redirect(w, r, redirect, http.StatusFound)
	})
}
