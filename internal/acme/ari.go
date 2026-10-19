package acme

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

const (
	// ariRetryAfterSeconds is the polling interval hint (6 h) sent as
	// delta-seconds Retry-After, per RFC 9773.
	ariRetryAfterSeconds = "21600"
	// ariMaxSerialBytes is the RFC 5280 limit for a certificate serial.
	ariMaxSerialBytes = 20
)

// ariEntry is an issued certificate paired with the order that produced it.
type ariEntry struct {
	order *Order
	leaf  *x509.Certificate
}

// handleRenewalInfo implements ACME Renewal Information (RFC 9773).
// GET /acme/renewalInfo/{certID}
// certID = base64url(AuthorityKeyIdentifier.keyIdentifier) + "." + base64url(serial DER content)
//
// Every certID the server cannot resolve (malformed, unknown serial, issuer
// key identifier mismatch) answers the same 404 so a client cannot probe
// which serials exist.
func (s *Server) handleRenewalInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	aki, serial, ok := parseARICertID(strings.TrimPrefix(r.URL.Path, "/acme/renewalInfo/"))
	if !ok {
		s.writeARINotFound(w)
		return
	}
	entries := s.ariEntries()
	target := findCertByARI(entries, aki, serial)
	if target == nil {
		s.writeARINotFound(w)
		return
	}

	renewNow := s.isARIRevoked(target.leaf) || s.isARISuperseded(target, entries)
	window := ariWindow(target.leaf, time.Now().UTC(), renewNow)

	nonce, _ := s.nonces.New()
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", ariRetryAfterSeconds)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(window)
}

// writeARINotFound is the single not-found response for renewalInfo.
func (s *Server) writeARINotFound(w http.ResponseWriter) {
	s.writeACMEError(w, http.StatusNotFound, "urn:ietf:params:acme:error:malformed", "certificate not found")
}

// parseARICertID splits a certID into the decoded AKI and serial bytes.
func parseARICertID(certID string) (aki, serial []byte, ok bool) {
	akiB64, serialB64, found := strings.Cut(certID, ".")
	if !found || akiB64 == "" || serialB64 == "" || strings.Contains(serialB64, ".") {
		return nil, nil, false
	}
	aki, err := base64.RawURLEncoding.DecodeString(akiB64)
	if err != nil || len(aki) == 0 {
		return nil, nil, false
	}
	serial, err = base64.RawURLEncoding.DecodeString(serialB64)
	if err != nil || len(serial) == 0 || len(serial) > ariMaxSerialBytes {
		return nil, nil, false
	}
	return aki, serial, true
}

// ariWindow computes the suggested renewal window. A renewNow certificate
// (revoked or superseded) gets a window that has just closed. Otherwise
// start = notAfter - validity/3 and end = notAfter - 7d; for a 90-day cert
// that is day 60 .. day 83.
func ariWindow(cert *x509.Certificate, now time.Time, renewNow bool) RenewalInfoResponse {
	var start, end time.Time
	if renewNow {
		start, end = now.Add(-time.Hour), now
	} else {
		validity := cert.NotAfter.Sub(cert.NotBefore)
		start = cert.NotAfter.Add(-validity / 3)
		end = cert.NotAfter.Add(-7 * 24 * time.Hour)
		if end.Before(start) {
			end = start.Add(24 * time.Hour)
		}
		if end.Before(now) {
			start = now.Add(time.Hour)
			end = now.Add(25 * time.Hour)
		}
	}
	return RenewalInfoResponse{
		SuggestedWindow: RenewalWindow{
			Start: start.UTC().Format(time.RFC3339),
			End:   end.UTC().Format(time.RFC3339),
		},
	}
}

// ariEntries loads every issued certificate in the store. No cache: a cached
// view would go stale the moment a certificate is revoked.
func (s *Server) ariEntries() []ariEntry {
	var out []ariEntry
	for _, order := range s.store.ListOrders() {
		if order.Certificate == "" {
			continue
		}
		_, id, found := strings.Cut(order.Certificate, "/acme/cert/")
		if !found {
			continue
		}
		pemBytes, ok := s.store.LoadCert(id)
		if !ok || len(pemBytes) == 0 {
			continue
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			continue
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		out = append(out, ariEntry{order: order, leaf: leaf})
	}
	return out
}

// findCertByARI returns the entry whose serial equals serial (compared as
// integers, so a DER leading 0x00 for a high-bit serial is irrelevant) and
// whose AuthorityKeyId equals aki. A cert without an AKI never matches.
func findCertByARI(entries []ariEntry, aki, serial []byte) *ariEntry {
	want := new(big.Int).SetBytes(serial)
	for i := range entries {
		leaf := entries[i].leaf
		if leaf.SerialNumber.Cmp(want) != 0 {
			continue
		}
		if len(leaf.AuthorityKeyId) == 0 || !bytes.Equal(leaf.AuthorityKeyId, aki) {
			continue
		}
		return &entries[i]
	}
	return nil
}

// isARIRevoked reports revocation through either the ACME-local map or the
// downstream revocation store (admin API, UI, bulk-revoke). A lookup error
// fails open: a poll must never 5xx.
func (s *Server) isARIRevoked(cert *x509.Certificate) bool {
	s.mu.Lock()
	_, local := s.revoked[certFingerprint(cert)]
	s.mu.Unlock()
	if local {
		return true
	}
	if s.revStore == nil {
		return false
	}
	caID, err := s.resolveIssuingCAID(cert)
	if err != nil {
		logging.Warnf("acme renewal-info: cannot resolve issuing CA for serial=%s: %v", cert.SerialNumber, err)
		return false
	}
	revoked, _, _, err := s.revStore.IsRevoked(cert.SerialNumber, caID)
	if err != nil {
		logging.Warnf("acme renewal-info: revocation lookup failed for serial=%s: %v", cert.SerialNumber, err)
		return false
	}
	return revoked
}

// isARISuperseded reports whether the same account holds a newer, unrevoked
// certificate for the identical DNS-name set.
func (s *Server) isARISuperseded(target *ariEntry, entries []ariEntry) bool {
	names := sortedNames(target.leaf)
	for i := range entries {
		e := &entries[i]
		if e.leaf.SerialNumber.Cmp(target.leaf.SerialNumber) == 0 && bytes.Equal(e.leaf.Raw, target.leaf.Raw) {
			continue
		}
		if e.order.AccountID != target.order.AccountID || !e.leaf.NotBefore.After(target.leaf.NotBefore) {
			continue
		}
		if !slices.Equal(names, sortedNames(e.leaf)) {
			continue
		}
		if !s.isARIRevoked(e.leaf) {
			return true
		}
	}
	return false
}

func sortedNames(cert *x509.Certificate) []string {
	names := slices.Clone(cert.DNSNames)
	slices.Sort(names)
	return names
}
