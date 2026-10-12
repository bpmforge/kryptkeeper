// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/ca"
)

// W7-01: workload attestation extending the v2.1 REST SVID mint.
// Join-token attestation (SPIRE's bootstrap model): an admin registers
// a SPIFFE ID bound to a single-use, expiring join token; the workload
// redeems the token as its attestation evidence and receives a
// short-lived SVID for the REGISTERED identity — it cannot choose one.
// Registration is the human approval step, so proposer≠approver holds:
// attestation can never mint an identity that was not explicitly
// registered, and each registration mints at most once.
//
// The SPIFFE Workload API's gRPC transport is deliberately absent:
// go.mod carries no grpc/go-spiffe and new dependencies need explicit
// approval. This REST flow is the same contract (attest → SVID); the
// gRPC front-end is additive once the dependency is approved.

// WorkloadEntry is one registered workload identity. Only the SHA-256
// of the join token is kept — the token itself is returned exactly once
// at registration and never persists.
type WorkloadEntry struct {
	ID        string    `json:"id"`
	SPIFFEID  string    `json:"spiffe_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`

	tokenHash [sha256.Size]byte
}

// WorkloadRegistry holds pending and consumed workload registrations.
// In-memory by design: join tokens are short-lived bootstrap artifacts,
// and a hub restart clearing unredeemed ones is safe (re-register).
type WorkloadRegistry struct {
	mu      sync.Mutex
	entries map[string]*WorkloadEntry
}

func NewWorkloadRegistry() *WorkloadRegistry {
	return &WorkloadRegistry{entries: map[string]*WorkloadEntry{}}
}

const (
	workloadEntryDefaultTTL = 24 * time.Hour
	workloadEntryMaxTTL     = 7 * 24 * time.Hour
)

// Register binds a validated SPIFFE ID to a fresh single-use join
// token and returns the token (the only time it is ever visible).
func (reg *WorkloadRegistry) Register(spiffeID, createdBy string, ttl time.Duration, now time.Time) (*WorkloadEntry, string, error) {
	if ttl <= 0 {
		ttl = workloadEntryDefaultTTL
	}
	if ttl > workloadEntryMaxTTL {
		return nil, "", fmt.Errorf("entry ttl exceeds the %s maximum", workloadEntryMaxTTL)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("token generation failed: %w", err)
	}
	token := hex.EncodeToString(raw)
	idRaw := make([]byte, 8)
	if _, err := rand.Read(idRaw); err != nil {
		return nil, "", fmt.Errorf("id generation failed: %w", err)
	}
	e := &WorkloadEntry{
		ID:        "we-" + hex.EncodeToString(idRaw),
		SPIFFEID:  spiffeID,
		ExpiresAt: now.Add(ttl),
		CreatedBy: createdBy,
		CreatedAt: now,
		tokenHash: sha256.Sum256([]byte(token)),
	}
	reg.mu.Lock()
	reg.entries[e.ID] = e
	reg.mu.Unlock()
	return e, token, nil
}

// Attest redeems a join token: on match the token is consumed
// (single-use) and the registered entry returned. Comparison is
// constant-time over the token hash across ALL entries, so a miss does
// not reveal whether any entry exists.
func (reg *WorkloadRegistry) Attest(token string, now time.Time) (*WorkloadEntry, error) {
	presented := sha256.Sum256([]byte(token))
	reg.mu.Lock()
	defer reg.mu.Unlock()
	var match *WorkloadEntry
	for _, e := range reg.entries {
		if subtle.ConstantTimeCompare(presented[:], e.tokenHash[:]) == 1 {
			match = e
		}
	}
	if match == nil {
		return nil, fmt.Errorf("attestation refused: unknown join token")
	}
	if match.Used {
		return nil, fmt.Errorf("attestation refused: join token already redeemed")
	}
	if now.After(match.ExpiresAt) {
		return nil, fmt.Errorf("attestation refused: join token expired")
	}
	match.Used = true
	copyOf := *match
	return &copyOf, nil
}

// List returns entries (token hashes never leave), newest first.
func (reg *WorkloadRegistry) List() []WorkloadEntry {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	out := make([]WorkloadEntry, 0, len(reg.entries))
	for _, e := range reg.entries {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// mintWorkloadSVID mints a short-lived SVID for an attested SPIFFE ID.
// Mirrors the /spiffe/svid mint (same engine, same response contract);
// kept separate so the admin handler's request plumbing stays untouched.
func mintWorkloadSVID(spiffeURI *url.URL, signingCA string) (svidPEM, keyPEM, bundlePEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("key generation failed: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{}, URIs: []*url.URL{spiffeURI},
	}, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("csr generation failed: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("csr parse failed: %w", err)
	}
	issued, err := spiffeEngine.IssueCertificate(signingCA, ca.IssuanceRequest{
		CSR:         csr,
		Validity:    spiffeSVIDTTL(),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:        []*url.URL{spiffeURI},
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("svid issuance failed: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("key encode failed: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if chain, cerr := spiffeEngine.GetCAChain(signingCA); cerr == nil {
		bundlePEM = caChainPEM(chain)
	}
	return issued.CertPEM, keyPEM, bundlePEM, nil
}

type workloadSVIDResponse struct {
	SPIFFEID  string `json:"spiffe_id"`
	SVIDPEM   string `json:"svid_pem"`
	KeyPEM    string `json:"key_pem"`
	BundlePEM string `json:"bundle_pem"`
	ExpiresAt string `json:"expires_at"`
}

// registerSPIFFEWorkloadHandlers mounts the workload-attestation
// endpoints beside the existing /spiffe family.
// defaultSPIFFEWorkloadSVIDLimit is the per-source, per-minute ceiling on
// POST /api/v1/spiffe/workload-svid.
const defaultSPIFFEWorkloadSVIDLimit = 120

func registerSPIFFEWorkloadHandlers(mux *http.ServeMux, auth *Authenticator, registry *WorkloadRegistry, auditProvider AuditProvider) {
	// POST (admin registers) / GET (admin lists) workload entries.
	mux.HandleFunc("/api/v1/spiffe/workload-entries", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if !canApproveActions(pd.Role) {
			writeForbidden(w, "your role is not authorized to manage workload registrations")
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(struct {
				Data []WorkloadEntry `json:"data"`
			}{Data: registry.List()})
		case http.MethodPost:
			td := spiffeTrustDomain()
			if td == "" || spiffeEngine == nil {
				writeServiceUnavailable(w, "SPIFFE not configured (set SPIFFE_TRUST_DOMAIN and run with a CA engine)")
				return
			}
			var req struct {
				SPIFFEID   string `json:"spiffe_id"`
				TTLSeconds int    `json:"ttl_seconds"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeBadRequest(w, "invalid JSON")
				return
			}
			// Identity is fixed at registration — validate here, once.
			spiffeURI, err := validateSPIFFEID(req.SPIFFEID, td)
			if err != nil {
				writeBadRequest(w, err.Error())
				return
			}
			entry, token, err := registry.Register(spiffeURI.String(), pd.ID, time.Duration(req.TTLSeconds)*time.Second, time.Now())
			if err != nil {
				writeBadRequest(w, err.Error())
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "spiffe.workload_entry_create", "spiffe_workload", entry.SPIFFEID, AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(struct {
				Data struct {
					EntryID   string `json:"entry_id"`
					SPIFFEID  string `json:"spiffe_id"`
					JoinToken string `json:"join_token"`
					ExpiresAt string `json:"expires_at"`
				} `json:"data"`
			}{Data: struct {
				EntryID   string `json:"entry_id"`
				SPIFFEID  string `json:"spiffe_id"`
				JoinToken string `json:"join_token"`
				ExpiresAt string `json:"expires_at"`
			}{
				EntryID:   entry.ID,
				SPIFFEID:  entry.SPIFFEID,
				JoinToken: token,
				ExpiresAt: entry.ExpiresAt.UTC().Format(time.RFC3339),
			}})
		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		}
	})

	// POST /api/v1/spiffe/workload-svid — the workload redeems its join
	// token. No principal auth: the single-use, expiring, high-entropy
	// token IS the attestation evidence, and it can only yield the
	// identity an admin registered for it.
	mux.HandleFunc("/api/v1/spiffe/workload-svid", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		// The response carries a private key, and the endpoint takes no
		// principal auth, so it is throttled per source like login. The
		// default is org-wide-safe (many pods redeeming tokens behind one
		// proxy address at rollout); API_RATE_LIMIT_SPIFFE_SVID_PER_MIN
		// tunes it.
		setNoStore(w)
		if !auth.allowRateLimit("spiffe-svid:"+clientIP(r), intFromEnvOrDefault("API_RATE_LIMIT_SPIFFE_SVID_PER_MIN", defaultSPIFFEWorkloadSVIDLimit), time.Minute, time.Now()) {
			writeTooManyRequests(w, "rate limit exceeded")
			return
		}
		td := spiffeTrustDomain()
		signingCA := strings.TrimSpace(os.Getenv("SPIFFE_SIGNING_CA_ID"))
		if td == "" || signingCA == "" || spiffeEngine == nil {
			writeServiceUnavailable(w, "SPIFFE not configured")
			return
		}
		var req struct {
			JoinToken string `json:"join_token"`
		}
		if !decodeJSONBodyOrReject(w, r, &req, maxAuthBodyBytes, "join_token is required") {
			return
		}
		if strings.TrimSpace(req.JoinToken) == "" {
			writeBadRequest(w, "join_token is required")
			return
		}
		entry, err := registry.Attest(strings.TrimSpace(req.JoinToken), time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "workload:unattested", "spiffe.workload_attest", "spiffe_workload", "unknown", AuditOutcomeFailure)
			writeUnauthorized(w)
			return
		}
		spiffeURI, err := url.Parse(entry.SPIFFEID)
		if err != nil {
			writeServiceUnavailable(w, "registered SPIFFE ID unparsable")
			return
		}
		svidPEM, keyPEM, bundlePEM, err := mintWorkloadSVID(spiffeURI, signingCA)
		if err != nil {
			emitAuditEvent(r, auditProvider, entry.ID, "spiffe.workload_attest", "spiffe_workload", entry.SPIFFEID, AuditOutcomeFailure)
			// The CA engine's error text is for the operator's log, not the
			// unauthenticated caller (SPIFFE-L).
			log.Printf("spiffe workload svid issuance failed for %s: %v", entry.SPIFFEID, err)
			writeServiceUnavailable(w, "svid issuance failed")
			return
		}
		emitAuditEvent(r, auditProvider, entry.ID, "spiffe.workload_attest", "spiffe_workload", entry.SPIFFEID, AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(struct {
			Data workloadSVIDResponse `json:"data"`
		}{Data: workloadSVIDResponse{
			SPIFFEID:  entry.SPIFFEID,
			SVIDPEM:   string(svidPEM),
			KeyPEM:    string(keyPEM),
			BundlePEM: string(bundlePEM),
			ExpiresAt: time.Now().UTC().Add(spiffeSVIDTTL()).Format(time.RFC3339),
		}})
	})
}
