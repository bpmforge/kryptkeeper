// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/tsa"
)

// W29-14 (D-153): RFC 3161 time-stamp service over HTTP. The TSA key and
// certificate are operator-provisioned files: the hub CA cannot mint a
// spec-valid TSA certificate (it never marks the EKU critical and refuses
// extra id-ce extensions), and openssl ts -verify needs exactly that.

const (
	tsaBodyMax     = 64 * 1024
	tsaAuditAction = "codesign.timestamp"
	tsaQueryType   = "application/timestamp-query"
	tsaReplyType   = "application/timestamp-reply"
)

// WithTSA mounts POST /api/v1/tsa. A nil authority keeps the route mounted
// and answering 503 (audited), so an unconfigured TSA is visible, not a 404.
// With allowAnonymous false (the default) the caller needs a hub principal.
func WithTSA(a *tsa.Authority, auth *Authenticator, audit AuditProvider, allowAnonymous bool) ServerOption {
	return WithExtraHandlers(func(mux *http.ServeMux) {
		registerTSAHandler(mux, a, auth, audit, allowAnonymous)
	})
}

// TSAOptionFromEnv builds the TSA option from KRYPTKEEPER_TSA_* (see
// tsaFromEnv). A misconfigured TSA (bad files) is logged and leaves the
// route answering 503 rather than stopping the hub.
func TSAOptionFromEnv(auth *Authenticator, audit AuditProvider) ServerOption {
	a, err := tsaFromEnv()
	if err != nil {
		logging.Infof("ERROR time-stamp authority disabled: %v", err)
	}
	anon := strings.EqualFold(strings.TrimSpace(os.Getenv("KRYPTKEEPER_TSA_ALLOW_ANONYMOUS")), "true")
	if a != nil {
		logging.Infof("RFC 3161 time-stamp authority: POST /api/v1/tsa")
		if anon {
			logging.Infof("WARNING KRYPTKEEPER_TSA_ALLOW_ANONYMOUS=true: anyone who can reach the hub can obtain timestamps")
		}
	}
	return WithTSA(a, auth, audit, anon)
}

// tsaFromEnv returns nil, nil when KRYPTKEEPER_TSA_CERT_FILE is unset (TSA
// disabled). The key must be a PKCS#8 PEM file with no group/other access.
func tsaFromEnv() (*tsa.Authority, error) {
	certFile := strings.TrimSpace(os.Getenv("KRYPTKEEPER_TSA_CERT_FILE"))
	if certFile == "" {
		return nil, nil
	}
	keyFile := strings.TrimSpace(os.Getenv("KRYPTKEEPER_TSA_KEY_FILE"))
	if keyFile == "" {
		return nil, errors.New("KRYPTKEEPER_TSA_KEY_FILE is required with KRYPTKEEPER_TSA_CERT_FILE")
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		return nil, fmt.Errorf("tsa key: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("tsa key %s must not be accessible by group or others (chmod 600)", keyFile)
	}
	certs, err := readCertsPEM(certFile)
	if err != nil || len(certs) == 0 {
		return nil, fmt.Errorf("tsa cert %s: %v", certFile, err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("tsa key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("tsa key must be a PKCS#8 PEM (BEGIN PRIVATE KEY)")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tsa key: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("tsa key is not a signing key")
	}
	cfg := tsa.Config{Signer: signer, Cert: certs[0]}
	if chainFile := strings.TrimSpace(os.Getenv("KRYPTKEEPER_TSA_CHAIN_FILE")); chainFile != "" {
		if cfg.Chain, err = readCertsPEM(chainFile); err != nil {
			return nil, fmt.Errorf("tsa chain %s: %w", chainFile, err)
		}
	}
	if raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_TSA_POLICY_OID")); raw != "" {
		oid, perr := parseOID(raw)
		if perr != nil {
			return nil, fmt.Errorf("KRYPTKEEPER_TSA_POLICY_OID: %w", perr)
		}
		cfg.PolicyOID = oid
	}
	return tsa.New(cfg)
}

func readCertsPEM(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, perr := x509.ParseCertificate(block.Bytes)
		if perr != nil {
			return nil, perr
		}
		out = append(out, c)
	}
	return out, nil
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	for _, part := range strings.Split(s, ".") {
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err != nil || n < 0 {
			return nil, fmt.Errorf("%q is not a dotted OID", s)
		}
		oid = append(oid, n)
	}
	if len(oid) < 2 {
		return nil, fmt.Errorf("%q is not a dotted OID", s)
	}
	return oid, nil
}

func tsaAlgName(h crypto.Hash) string {
	return strings.ToLower(strings.ReplaceAll(h.String(), "-", ""))
}

func registerTSAHandler(mux *http.ServeMux, a *tsa.Authority, auth *Authenticator, audit AuditProvider, allowAnonymous bool) {
	mux.HandleFunc("/api/v1/tsa", func(w http.ResponseWriter, r *http.Request) {
		emit := func(actor string, outcome AuditOutcome, resourceID, detail string) {
			emitAuditEventDetail(r, audit, actor, tsaAuditAction, "timestamp", resourceID, outcome, detail)
		}
		if r.Method != http.MethodPost {
			emit("", AuditOutcomeFailure, "rejected", "method not allowed")
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		actor := ""
		if !allowAnonymous {
			p, err := auth.AuthenticatePrincipal(r, time.Now())
			if err != nil {
				// No body has been read, so there is no digest to record.
				emit("", AuditOutcomeDenied, "rejected", "authentication required")
				writeUnauthorized(w)
				return
			}
			actor = p
		} else if p, err := auth.AuthenticatePrincipal(r, time.Now()); err == nil {
			actor = p
		}
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != tsaQueryType {
			emit(actor, AuditOutcomeFailure, "rejected", "unsupported media type")
			http.Error(w, "Content-Type must be "+tsaQueryType, http.StatusUnsupportedMediaType)
			return
		}
		if a == nil {
			emit(actor, AuditOutcomeFailure, "rejected", "time-stamp authority not configured")
			writeServiceUnavailable(w, "time-stamp authority not configured")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, tsaBodyMax+1))
		if err != nil || len(body) > tsaBodyMax {
			emit(actor, AuditOutcomeFailure, "rejected", "request body unreadable or too large")
			writeErrorEnvelope(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
			return
		}
		// Only the digest is audited, never the request body.
		digest, alg, nonce := "", "", "absent"
		if req, perr := tsa.ParseRequest(body); perr == nil {
			digest, alg = hex.EncodeToString(req.Digest), tsaAlgName(req.Hash)
			if req.Nonce != nil {
				nonce = "present"
			}
		}
		resp, granted, rerr := a.Respond(body)
		var reject *tsa.RejectError
		switch {
		case rerr == nil:
			emit(actor, AuditOutcomeSuccess, granted.Serial.Text(16),
				fmt.Sprintf("digest=%s alg=%s serial=%s nonce=%s", digest, tsaAlgName(granted.Hash), granted.Serial.Text(16), nonce))
		case errors.As(rerr, &reject):
			// An RFC 3161 rejection is still a 200 reply; the client reads PKIStatus.
			emit(actor, AuditOutcomeDenied, "rejected",
				fmt.Sprintf("digest=%s alg=%s nonce=%s reason=%q", digest, alg, nonce, codesignTruncate(reject.Reason, codesignDetailMax)))
		default:
			logging.Infof("tsa: respond failed: %v", rerr)
			emit(actor, AuditOutcomeFailure, "rejected", fmt.Sprintf("digest=%s alg=%s signing failed", digest, alg))
			writeServiceUnavailable(w, "time-stamp signing failed")
			return
		}
		w.Header().Set("Content-Type", tsaReplyType)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(resp); err != nil {
			logging.Infof("tsa: write reply: %v", err)
		}
	})
}
