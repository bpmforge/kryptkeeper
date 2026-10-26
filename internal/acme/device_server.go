// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

// Server side of device-attest-01 (W40-02): the order, the challenge and the
// finalize checks. The verification itself is in device_attest.go.

import (
	"context"
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/clientip"
	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/metrics"
)

func hasPermanentIdentifier(ids []Identifier) bool {
	for _, id := range ids {
		if id.Type == identifierTypePermanent {
			return true
		}
	}
	return false
}

func isDeviceOrder(o *Order) bool {
	return len(o.Identifiers) == 1 && o.Identifiers[0].Type == identifierTypePermanent
}

// effectiveTemplateID is the template governing this directory: the
// provisioner's, else the server-wide one.
func (s *Server) effectiveTemplateID() string {
	if s.provisioner != nil && s.provisioner.TemplateID != "" {
		return s.provisioner.TemplateID
	}
	return s.device.cfg.DefaultTemplateID
}

// deviceOffered reports whether this directory offers device attestation, and
// when not, why (for the audit row only; the client gets a uniform refusal).
// Both a configured root and an explicit template flag are required, so no
// existing template or directory changes behaviour (D-316 rule 1, D-317 rule 2).
func (s *Server) deviceOffered(ctx context.Context) (bool, string) {
	if s.device == nil {
		return false, "device attestation is not configured (no attestation roots)"
	}
	if s.provisioner != nil && !s.provisioner.offers(challengeDeviceAttest) {
		return false, "provisioner does not offer device-attest-01"
	}
	id := s.effectiveTemplateID()
	if id == "" || s.device.cfg.TemplateAllows == nil {
		return false, "no template governs this directory"
	}
	ok, err := s.device.cfg.TemplateAllows(ctx, id)
	if err != nil {
		logging.Warnf("acme device attestation: template %q lookup failed: %v", id, err)
		return false, "template lookup failed"
	}
	if !ok {
		return false, "template does not allow device attestation"
	}
	return true, ""
}

// auditDevice records one device-attestation outcome. detail carries the
// reason, format and ordered identifier; never attestation bytes (D-316 rule 6).
func (s *Server) auditDevice(r *http.Request, action, actor, outcome, detail string) {
	if s.eab.audit == nil {
		return
	}
	s.eab.audit(r.Context(), AuditEvent{Action: action, Actor: actor, Outcome: outcome, SourceIP: clientip.FromEnv().ClientIP(r), Detail: detail})
}

func (s *Server) handleNewDeviceOrder(w http.ResponseWriter, r *http.Request, accountID string, idents []Identifier) {
	reject := func(status int, problem, detail, reason string) {
		s.auditDevice(r, "acme.device_attest.reject", accountID, "denied", "order refused: "+reason)
		s.writeACMEError(w, status, problem, detail)
	}
	if offered, why := s.deviceOffered(r.Context()); !offered {
		reject(http.StatusBadRequest, "urn:ietf:params:acme:error:unsupportedIdentifier", "identifier type \"permanent-identifier\" is not supported", why)
		return
	}
	// One device per order keeps finalize's binding between the attested key,
	// the identifier and the certificate unambiguous.
	if len(idents) != 1 {
		reject(http.StatusBadRequest, "urn:ietf:params:acme:error:rejectedIdentifier", "a permanent-identifier order carries exactly one identifier", "order mixes identifiers")
		return
	}
	if _, err := parsePermanentIdentifier(idents[0].Value); err != nil {
		reject(http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", err.Error(), "malformed identifier: "+err.Error())
		return
	}
	value := idents[0].Value

	now := time.Now().UTC()
	authz := &Authorization{
		ID: generateID("authz"), AccountID: accountID,
		Identifier: Identifier{Type: identifierTypePermanent, Value: value},
		Status:     "pending", Expires: now.Add(7 * 24 * time.Hour),
	}
	authz.Challenges = []Challenge{{Type: challengeDeviceAttest, URL: s.baseURL + "/acme/challenge/" + authz.ID + "/" + challengeDeviceAttest, Token: generateToken(), Status: "pending"}}
	s.store.SaveAuthz(authz)

	order := &Order{
		ID: generateID("order"), AccountID: accountID, Status: "pending",
		Identifiers:    []Identifier{authz.Identifier},
		Authorizations: []string{s.baseURL + "/acme/authz/" + authz.ID},
		Expires:        now.Add(7 * 24 * time.Hour), CreatedAt: now,
	}
	order.Finalize = s.baseURL + "/acme/finalize/" + order.ID
	s.store.SaveOrder(order)
	metrics.ACMEOrdersCreated.Inc()

	nonce, _ := s.nonces.New()
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Location", s.baseURL+"/acme/order/"+order.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(order)
}

// handleDeviceChallenge validates a device-attest-01 response. It is called
// with s.mu held and releases it. Validation is synchronous: it is CPU only,
// so there is no goroutine and no window in which a second POST could race it
// beyond the processing mark set here.
func (s *Server) handleDeviceChallenge(w http.ResponseWriter, r *http.Request, payload []byte, authz *Authorization, ch *Challenge, accountID string) {
	if s.device == nil || authz.Identifier.Type != identifierTypePermanent || ch.Status != "pending" {
		s.mu.Unlock()
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "challenge is not pending")
		return
	}
	ch.Status = "processing"
	s.store.SaveAuthz(authz)
	authzID, orderedID, token := authz.ID, authz.Identifier.Value, ch.Token
	s.mu.Unlock()

	format := "-"
	// fail marks the challenge and authorization invalid and answers with the
	// draft's badAttestationStatement. client is the detail the requester gets.
	fail := func(client, reason string) {
		s.auditDevice(r, "acme.device_attest.reject", accountID, "denied", fmt.Sprintf("reason=%s; format=%s; identifier=%s", reason, format, orderedID))
		s.mu.Lock()
		failChallenge(s.store, ch, authz, errBadAttestationStatement, client)
		s.mu.Unlock()
		s.writeACMEError(w, http.StatusBadRequest, errBadAttestationStatement, client)
	}

	var req struct {
		AttObj string `json:"attObj"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || req.AttObj == "" {
		fail("response must carry attObj", "response has no attObj")
		return
	}
	attObj, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(req.AttObj, "="))
	if err != nil {
		fail("attObj is not base64url", "attObj is not base64url")
		return
	}
	keyAuth, err := s.keyAuthorization(accountID, token)
	if err != nil {
		fail("could not compute key authorization", "key authorization unavailable")
		return
	}
	res, err := s.device.verify(attObj, token, keyAuth)
	if err != nil {
		format = peekFormat(s.device, attObj)
		fail(err.Error(), err.Error())
		return
	}
	format = res.Format

	want, perr := parsePermanentIdentifier(orderedID)
	if perr != nil {
		fail("identifier is malformed", "stored identifier malformed")
		return
	}
	matched := false
	for _, id := range res.Identifiers {
		if sameIdentifier(want, id) {
			matched = true
		}
	}
	if !matched {
		fail("the attested device identifier does not match the order", "attested identifier differs from the order")
		return
	}
	thumb, err := publicKeyThumbprint(res.Key)
	if err != nil {
		fail("attested key is not usable", "attested key cannot be encoded")
		return
	}
	caID, cerr := ca.ResolveCAID(s.caEngine, s.caID)
	if cerr != nil {
		s.unprocess(authz, ch)
		s.auditDevice(r, "acme.device_attest.reject", accountID, "failure", fmt.Sprintf("reason=no issuing CA; format=%s; identifier=%s", format, orderedID))
		s.writeACMEError(w, http.StatusServiceUnavailable, "urn:ietf:params:acme:error:serverInternal", noCADetail(cerr))
		return
	}
	// Attestation proves the hardware; the inventory proves it is ours (D-317).
	allowed, aerr := false, error(nil)
	if s.device.cfg.DeviceAllowed != nil {
		allowed, aerr = s.device.cfg.DeviceAllowed(r.Context(), caID, orderedID)
	}
	if aerr != nil {
		logging.Warnf("acme device attestation: inventory lookup failed: %v", aerr)
		s.unprocess(authz, ch)
		s.auditDevice(r, "acme.device_attest.reject", accountID, "failure", fmt.Sprintf("reason=inventory lookup failed; format=%s; identifier=%s", format, orderedID))
		s.writeACMEError(w, http.StatusServiceUnavailable, "urn:ietf:params:acme:error:serverInternal", "device inventory unavailable")
		return
	}
	if !allowed {
		fail("the device is not in this hub's device inventory", "device not in allow-list")
		return
	}

	now := time.Now().UTC()
	s.mu.Lock()
	ch.Status, ch.Validated, ch.Error = "valid", &now, nil
	authz.Status = "valid"
	authz.AttestedKeyThumbprint, authz.AttestationFormat = thumb, format
	s.store.SaveAuthz(authz)
	s.updateOrderStatus()
	snapshot := *ch
	s.mu.Unlock()
	s.auditDevice(r, "acme.device_attest.accept", accountID, "success", fmt.Sprintf("format=%s; identifier=%s; authz=%s", format, orderedID, authzID))

	nonce, _ := s.nonces.New()
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Link", fmt.Sprintf(`<%s/acme/authz/%s>;rel="up"`, s.baseURL, authzID))
	_ = json.NewEncoder(w).Encode(snapshot)
}

// unprocess puts a challenge back to pending after a transient server-side
// failure, so the client may answer again.
func (s *Server) unprocess(authz *Authorization, ch *Challenge) {
	s.mu.Lock()
	ch.Status = "pending"
	s.store.SaveAuthz(authz)
	s.mu.Unlock()
}

// peekFormat names the attestation format for the audit row, or "-".
func peekFormat(d *deviceAttestation, attObj []byte) string {
	var ao attestationObject
	if d.dec.Unmarshal(attObj, &ao) == nil && (ao.Fmt == "apple" || ao.Fmt == "tpm") {
		return ao.Fmt
	}
	return "-"
}

// deviceFinalizeError is a finalize refusal with the ACME problem to send.
type deviceFinalizeError struct {
	status          int
	problem, detail string
}

func badDeviceCSR(detail string) *deviceFinalizeError {
	return &deviceFinalizeError{http.StatusBadRequest, "urn:ietf:params:acme:error:badCSR", detail}
}

// checkDeviceFinalize enforces the finalize rules of D-316/D-317 and returns
// the identifier the certificate will carry: the attested key must be the CSR
// key, the CSR may name only the ordered identifier, and the template and
// inventory must still allow the device.
func (s *Server) checkDeviceFinalize(r *http.Request, accountID string, order *Order, csr *x509.CertificateRequest, accountKey crypto.PublicKey) (*ca.PermanentIdentifier, *deviceFinalizeError) {
	ordered := order.Identifiers[0].Value
	refuse := func(status int, problem, detail, reason string) *deviceFinalizeError {
		s.auditDevice(r, "acme.device_attest.reject", accountID, "denied", fmt.Sprintf("finalize refused: %s; identifier=%s", reason, ordered))
		return &deviceFinalizeError{status, problem, detail}
	}
	if s.device == nil {
		return nil, refuse(http.StatusForbidden, "urn:ietf:params:acme:error:unauthorized", "device attestation is not enabled", "device attestation not configured")
	}
	if offered, why := s.deviceOffered(r.Context()); !offered {
		return nil, refuse(http.StatusForbidden, "urn:ietf:params:acme:error:unauthorized", "device attestation is not permitted for this template", why)
	}
	want, err := parsePermanentIdentifier(ordered)
	if err != nil || len(order.Authorizations) != 1 {
		return nil, refuse(http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "order is malformed", "order malformed")
	}
	authzID := order.Authorizations[0][strings.LastIndex(order.Authorizations[0], "/")+1:]
	s.mu.Lock()
	authz, ok := s.store.LoadAuthz(authzID)
	var thumb string
	valid := ok && authz.Status == "valid"
	if ok {
		thumb = authz.AttestedKeyThumbprint
	}
	s.mu.Unlock()
	if !valid || thumb == "" {
		return nil, refuse(http.StatusForbidden, "urn:ietf:params:acme:error:unauthorized", "the device has not been attested", "no attested key on the authorization")
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, badDeviceCSR("CSR signature invalid")
	}
	if err := ca.CheckPublicKeyStrength(csr.PublicKey); err != nil {
		return nil, badDeviceCSR("key too weak: " + err.Error())
	}
	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 || len(csr.URIs) > 0 || len(csr.EmailAddresses) > 0 {
		return nil, badDeviceCSR("CSR must not contain DNS, IP, URI or email subject alternative names")
	}
	ids, foreign, perr := ca.SANPermanentIdentifiers(csr.Extensions)
	if perr != nil || foreign > 0 || len(ids) > 1 || (len(ids) == 1 && !sameIdentifier(want, ids[0])) {
		return nil, badDeviceCSR("CSR may carry only the ordered permanent identifier")
	}
	if accountKey != nil {
		a, aerr := x509.MarshalPKIXPublicKey(accountKey)
		c, cerr := x509.MarshalPKIXPublicKey(csr.PublicKey)
		if aerr == nil && cerr == nil && subtle.ConstantTimeCompare(a, c) == 1 {
			return nil, badDeviceCSR("CSR must not reuse the account key")
		}
	}
	csrThumb, err := publicKeyThumbprint(csr.PublicKey)
	if err != nil || subtle.ConstantTimeCompare([]byte(csrThumb), []byte(thumb)) != 1 {
		return nil, refuse(http.StatusBadRequest, "urn:ietf:params:acme:error:badCSR", "CSR public key is not the attested device key", "CSR key differs from the attested key")
	}

	caID, cerr := ca.ResolveCAID(s.caEngine, s.caID)
	if cerr != nil {
		return nil, &deviceFinalizeError{http.StatusServiceUnavailable, "urn:ietf:params:acme:error:serverInternal", noCADetail(cerr)}
	}
	allowed, aerr := false, error(nil)
	if s.device.cfg.DeviceAllowed != nil {
		allowed, aerr = s.device.cfg.DeviceAllowed(r.Context(), caID, ordered)
	}
	if aerr != nil {
		logging.Warnf("acme device attestation: inventory lookup failed at finalize: %v", aerr)
		return nil, &deviceFinalizeError{http.StatusServiceUnavailable, "urn:ietf:params:acme:error:serverInternal", "device inventory unavailable"}
	}
	if !allowed {
		return nil, refuse(http.StatusForbidden, "urn:ietf:params:acme:error:unauthorized", "the device is not in this hub's device inventory", "device not in allow-list")
	}
	return &want, nil
}
