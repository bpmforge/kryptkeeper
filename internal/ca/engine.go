// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"sync"
	"time"

	"kryptkeeper/internal/keystore"
)

// Engine is the concrete CA service implementation backed by a KeyStore and a Store.
// The in-memory cache is a read-through layer over the persistent store.
type Engine struct {
	keys  keystore.Store
	store Store
	mu    sync.Mutex
	cache map[string]*CA // read-through cache over store
	// policy, when non-nil, gates every issuance variant (W5-05).
	policy *PolicyEngine
	// pointers supplies CRL/OCSP locations for leaves that carry none
	// (W20-12). Set once at startup, like policy.
	pointers RevocationPointersFunc
	// pointersForSerial, when set, wins over pointers: the resolver sees the
	// serial, so it can point a leaf at its CRL shard (W23-50).
	pointersForSerial RevocationPointersForSerialFunc
	// keyBackend identifies which keystore.Store backend `keys` is, e.g.
	// "software" (default), "pkcs11", "vault", "cloudkms". It is set once
	// via SetKeyBackend at startup (cmd/kryptkeeper/main.go), not derived
	// from `keys` itself, because keystore.Store has no such accessor —
	// adding one would touch every Store implementation for one label.
	// Used both to record CA.KeyStorageType truthfully (W19-08) and to
	// gate PQC key generation against docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md.
	keyBackend string
	// external forwards external-CA issuance to a connector (W36-02).
	external         ExternalIssuer
	onExternalReject ExternalRejectionObserver
	// rotateFault and onRotate are the W23-16 rotation test seam and
	// CRL/OCSP cache-eviction callbacks; both are set once at startup.
	rotateFault func(RotateStep) error
	onRotate    []func(caID string)
}

// SetPolicyEngine attaches the issuance-time policy gate (W5-05). A nil
// engine means no policy — the compatible default.
func (e *Engine) SetPolicyEngine(p *PolicyEngine) { e.policy = p }

// RevocationPointersFunc returns the CRL distribution points and OCSP URLs
// for certificates issued by caID.
type RevocationPointersFunc func(caID string) (crlURLs, ocspURLs []string)

// SetRevocationPointers makes every issuing path (ACME, EST, SCEP, CMP,
// WSTEP, the API) put CRL and OCSP locations in the leaves it issues, from
// one resolver rather than per-protocol copies (W20-12). A caller that sets
// its own CRLDistPoints/OCSPServer keeps them. CA certificates and
// short-lived leaves (7 days or less, the CA/B short-lived threshold the
// risk engine and ShortLived templates already use) get none.
func (e *Engine) SetRevocationPointers(fn RevocationPointersFunc) { e.pointers = fn }

// shortLivedMax is the validity at or below which a leaf needs no
// revocation pointers.
const shortLivedMax = 7 * 24 * time.Hour

// SetKeyBackend records which keystore.Store backend this engine's `keys`
// is. Unset (empty) is treated as "software" — the pre-W19-08 default and
// the only backend that ever existed before HSM/Vault/cloud KMS support.
func (e *Engine) SetKeyBackend(backend string) { e.keyBackend = backend }

// keyBackendLabel returns the effective backend label, defaulting to
// "software" when SetKeyBackend was never called.
func (e *Engine) keyBackendLabel() string {
	// A routing keystore knows which backend the in-flight create targets.
	if bl, ok := e.keys.(keystore.BackendLabeler); ok {
		if l := bl.CurrentBackendLabel(); l != "" {
			return l
		}
	}
	if e.keyBackend == "" {
		return "software"
	}
	return e.keyBackend
}

// checkIssuancePolicy runs the policy gate when attached.
func (e *Engine) checkIssuancePolicy(caID string, req IssuanceRequest) error {
	if e.policy == nil {
		return nil
	}
	return e.policy.Check(caID, req)
}

// NewEngine creates a CA engine. It pre-warms the cache from the store on startup.
// Use NewMemStore() for in-memory-only operation (tests, development).
func NewEngine(keys keystore.Store, store Store) *Engine {
	e := &Engine{
		keys:  keys,
		store: store,
		cache: make(map[string]*CA),
	}
	// Pre-warm cache; non-fatal on failure (cache misses fall back to store).
	if cas, err := store.List(); err == nil {
		for _, ca := range cas {
			e.cache[ca.ID] = ca
		}
	}
	return e
}

// get returns a CA by ID, checking the cache first then falling back to the store.
// Must be called with e.mu held.
func (e *Engine) get(id string) (*CA, bool) {
	if ca, ok := e.cache[id]; ok {
		return ca, true
	}
	ca, err := e.store.Load(id)
	if err != nil {
		return nil, false
	}
	e.cache[ca.ID] = ca
	return ca, true
}

// saveCA writes a CA to both cache and store. Must be called with e.mu held.
func (e *Engine) saveCA(ca *CA) error {
	if err := e.store.Save(ca); err != nil {
		return err
	}
	e.cache[ca.ID] = ca
	return nil
}

// ErrAlgorithmUnsupportedByBackend is returned when the configured key backend
// cannot hold the requested algorithm.
var ErrAlgorithmUnsupportedByBackend = errors.New("algorithm not supported by this key backend")

func checkBackendAlgorithm(backend string, algo keystore.Algorithm) error {
	if algo == keystore.Ed25519 && (backend == "pkcs11" || backend == "cloudkms") {
		return fmt.Errorf("%w: %s cannot hold Ed25519 (supported on software and vault)", ErrAlgorithmUnsupportedByBackend, backend)
	}
	return nil
}

func (e *Engine) CreateRootCA(name string, subject pkix.Name, algo keystore.Algorithm, validity time.Duration) (*CA, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := keystore.CheckHSMPQCSupport(e.keyBackendLabel(), algo); err != nil {
		return nil, err
	}
	if err := checkBackendAlgorithm(e.keyBackendLabel(), algo); err != nil {
		return nil, err
	}

	caID := newCAID()
	keyID := fmt.Sprintf("key-%s", caID)

	if _, err := e.keys.GenerateKey(keyID, algo); err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	signer, err := e.keys.Signer(keyID)
	if err != nil {
		return nil, fmt.Errorf("get signer: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	ski, err := computeSKIAny(signer.Public(), algo)
	if err != nil {
		return nil, fmt.Errorf("compute SKI: %w", err)
	}
	template.SubjectKeyId = ski

	var certDER []byte
	if keystore.IsHybrid(algo) {
		hl, ok := e.keys.(keystore.HybridKeyLoader)
		if !ok {
			return nil, fmt.Errorf("key store does not support hybrid keys")
		}
		pair, err := hl.LoadHybridKeyPair(keyID)
		if err != nil {
			return nil, fmt.Errorf("load hybrid key pair: %w", err)
		}
		certDER, err = createCertDERHybrid(template, template, algo, pair.Primary.Public(), pair.Primary, pair.Secondary)
		if err != nil {
			return nil, fmt.Errorf("create hybrid root certificate: %w", err)
		}
	} else {
		certDER, err = createCertDER(template, template, algo, signer.Public(), signer)
		if err != nil {
			return nil, fmt.Errorf("create root certificate: %w", err)
		}
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse created certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	ca := &CA{
		ID:             caID,
		Name:           name,
		Type:           "root",
		KeyID:          keyID,
		Certificate:    cert,
		CertPEM:        certPEM,
		Status:         "active",
		CreatedAt:      now,
		KeyStorageType: e.keyBackendLabel(),
	}
	if err := e.saveCA(ca); err != nil {
		return nil, fmt.Errorf("persist root CA: %w", err)
	}

	return ca, nil
}

func (e *Engine) CreateIntermediateCA(name string, subject pkix.Name, algo keystore.Algorithm, parentCAID string, validity time.Duration) (*CA, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	parent, ok := e.get(parentCAID)
	if !ok {
		return nil, ErrCANotFound
	}
	if parent.Status != "active" {
		return nil, fmt.Errorf("parent CA %s is not active", parentCAID)
	}

	if err := keystore.CheckHSMPQCSupport(e.keyBackendLabel(), algo); err != nil {
		return nil, err
	}
	if err := checkBackendAlgorithm(e.keyBackendLabel(), algo); err != nil {
		return nil, err
	}

	caID := newCAID()
	keyID := fmt.Sprintf("key-%s", caID)

	if _, err := e.keys.GenerateKey(keyID, algo); err != nil {
		return nil, fmt.Errorf("generate intermediate key: %w", err)
	}

	childSigner, err := e.keys.Signer(keyID)
	if err != nil {
		return nil, fmt.Errorf("get child signer: %w", err)
	}

	parentSigner, err := e.keys.Signer(parent.KeyID)
	if err != nil {
		return nil, fmt.Errorf("get parent signer: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now().UTC()
	notAfter := now.Add(validity)
	if notAfter.After(parent.Certificate.NotAfter) {
		notAfter = parent.Certificate.NotAfter
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		AuthorityKeyId:        parent.Certificate.SubjectKeyId,
	}

	childSKI, err := computeSKIAny(childSigner.Public(), algo)
	if err != nil {
		return nil, fmt.Errorf("compute child SKI: %w", err)
	}
	template.SubjectKeyId = childSKI

	// Parent signs the intermediate cert; use parent's algorithm for signing.
	parentAlgo, err := e.keys.Metadata(parent.KeyID)
	if err != nil {
		return nil, fmt.Errorf("get parent key metadata: %w", err)
	}
	certDER, err := createCertDER(template, parent.Certificate, parentAlgo.Algorithm, childSigner.Public(), parentSigner)
	if err != nil {
		return nil, fmt.Errorf("create intermediate certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse created certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	ca := &CA{
		ID:             caID,
		Name:           name,
		Type:           "intermediate",
		KeyID:          keyID,
		Certificate:    cert,
		CertPEM:        certPEM,
		ParentCAID:     parentCAID,
		Status:         "active",
		CreatedAt:      now,
		KeyStorageType: e.keyBackendLabel(),
	}
	if err := e.saveCA(ca); err != nil {
		return nil, fmt.Errorf("persist intermediate CA: %w", err)
	}

	return ca, nil
}

// CAStatusPendingCertificate parks an issuing CA whose key and CSR exist but
// whose offline-signed certificate has not been uploaded yet (W23-04).
const CAStatusPendingCertificate = "pending_certificate"

var (
	ErrCANotPendingCertificate  = errors.New("ca is not awaiting a signed certificate")
	ErrInvalidIssuedCertificate = errors.New("invalid issuing CA certificate")
)

// pendingCertSkew tolerates clock drift between the offline signer and the hub.
const pendingCertSkew = 5 * time.Minute

// CreateIntermediateCSR is the offline-root flow, hub side: it generates the
// issuing CA key in the keystore and returns a CA parked pending_certificate
// whose CSRPEM the operator takes to the offline root. The parent must be an
// active root or any CA the hub holds no key for.
func (e *Engine) CreateIntermediateCSR(name string, subject pkix.Name, algo keystore.Algorithm, parentCAID string) (*CA, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	parent, ok := e.get(parentCAID)
	if !ok {
		return nil, ErrCANotFound
	}
	if parent.Status != "active" {
		return nil, fmt.Errorf("parent CA %s is not active", parentCAID)
	}
	if parent.Type != "root" && parent.KeyID != "" {
		return nil, fmt.Errorf("parent CA %s holds its own signing key; a CSR is only needed under a root or a keyless CA", parentCAID)
	}
	if keystore.IsMLDSA(algo) || keystore.IsHybrid(algo) {
		return nil, fmt.Errorf("CSR flow supports classical algorithms only (RSA, ECDSA, Ed25519), not %s", algo)
	}
	if err := keystore.CheckHSMPQCSupport(e.keyBackendLabel(), algo); err != nil {
		return nil, err
	}
	if err := checkBackendAlgorithm(e.keyBackendLabel(), algo); err != nil {
		return nil, err
	}

	caID := newCAID()
	keyID := fmt.Sprintf("key-%s", caID)
	if _, err := e.keys.GenerateKey(keyID, algo); err != nil {
		return nil, fmt.Errorf("generate issuing CA key: %w", err)
	}
	signer, err := e.keys.Signer(keyID)
	if err != nil {
		return nil, fmt.Errorf("get issuing CA signer: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject}, signer)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	ca := &CA{
		ID:             caID,
		Name:           name,
		Type:           "intermediate",
		KeyID:          keyID,
		CSRPEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		ParentCAID:     parentCAID,
		Status:         CAStatusPendingCertificate,
		CreatedAt:      time.Now().UTC(),
		KeyStorageType: e.keyBackendLabel(),
	}
	if err := e.saveCA(ca); err != nil {
		return nil, fmt.Errorf("persist pending issuing CA: %w", err)
	}
	return ca, nil
}

// GetCSR returns the CSR of a CA awaiting its signed certificate.
func (e *Engine) GetCSR(caID string) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ca, ok := e.get(caID)
	if !ok {
		return nil, ErrCANotFound
	}
	if ca.Status != CAStatusPendingCertificate || len(ca.CSRPEM) == 0 {
		return nil, ErrCANotPendingCertificate
	}
	return ca.CSRPEM, nil
}

func invalidIssued(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidIssuedCertificate, fmt.Sprintf(format, args...))
}

// CompleteIntermediateCA accepts the offline-signed certificate for a pending
// CA. Nothing is stored unless the certificate (1) parses, (2) certifies
// exactly this CA's keystore key, (3) is a CA certificate, (4) is signed by the
// claimed parent, (5) is currently valid, (6) does not outlive the parent and
// (7) respects the parent's path length. A certificate meant for another
// CA fails (2).
func (e *Engine) CompleteIntermediateCA(caID string, certPEM []byte) (*CA, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	ca, ok := e.get(caID)
	if !ok {
		return nil, ErrCANotFound
	}
	if ca.Status != CAStatusPendingCertificate {
		return nil, ErrCANotPendingCertificate
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, invalidIssued("no PEM CERTIFICATE block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, invalidIssued("certificate does not parse")
	}

	caPub, err := e.keys.PublicKey(ca.KeyID)
	if err != nil {
		return nil, fmt.Errorf("load CA public key: %w", err)
	}
	wantKey, err := x509.MarshalPKIXPublicKey(caPub)
	if err != nil {
		return nil, fmt.Errorf("marshal CA public key: %w", err)
	}
	gotKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil || !bytes.Equal(wantKey, gotKey) {
		return nil, invalidIssued("certificate public key does not match the CA key")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return nil, invalidIssued("not a CA certificate (basic constraints)")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, invalidIssued("key usage does not allow certificate signing")
	}

	parent, ok := e.get(ca.ParentCAID)
	if !ok || parent.Certificate == nil {
		return nil, invalidIssued("parent CA is not available")
	}
	if parent.Status != "active" {
		return nil, invalidIssued("parent CA is not active")
	}
	if !bytes.Equal(cert.RawIssuer, parent.Certificate.RawSubject) || cert.CheckSignatureFrom(parent.Certificate) != nil {
		return nil, invalidIssued("not signed by the parent CA")
	}

	now := time.Now()
	if now.After(cert.NotAfter) {
		return nil, invalidIssued("certificate has expired")
	}
	if cert.NotBefore.After(now.Add(pendingCertSkew)) {
		return nil, invalidIssued("certificate is not yet valid")
	}
	if cert.NotAfter.After(parent.Certificate.NotAfter) {
		return nil, invalidIssued("certificate outlives the parent CA")
	}

	if parent.Certificate.MaxPathLen > 0 || parent.Certificate.MaxPathLenZero {
		if parent.Certificate.MaxPathLenZero && parent.Certificate.MaxPathLen == 0 {
			return nil, invalidIssued("pathlen: the parent CA permits no subordinate CA")
		}
		if cert.MaxPathLen < 0 || cert.MaxPathLen > parent.Certificate.MaxPathLen-1 {
			return nil, invalidIssued("pathlen: exceeds what the parent CA permits (parent allows %d)", parent.Certificate.MaxPathLen)
		}
	}

	// Work on a copy so a failed save leaves the cached CA pending.
	done := *ca
	done.Certificate = cert
	done.CertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	done.Status = "active"
	done.CSRPEM = nil
	if err := e.saveCA(&done); err != nil {
		return nil, fmt.Errorf("persist completed CA: %w", err)
	}
	return &done, nil
}

// Sentinels for external root import and trust-anchor removal (W23-03).
var (
	ErrNotSelfSigned          = errors.New("certificate is not self-signed; use chain import (ImportCAChain) to import an intermediate with its issuer chain")
	ErrCAAlreadyImported      = errors.New("this root certificate is already imported")
	ErrNotTrustAnchor         = errors.New("only an imported keyless root CA can be removed as a trust anchor")
	ErrTrustAnchorHasChildren = errors.New("trust anchor still has child CAs")
)

// ValidateRootImport parses certPEM and checks it is a self-signed CA
// certificate. A non-self-signed input is ErrNotSelfSigned so callers can
// point the operator at chain import.
func ValidateRootImport(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM certificate data")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA certificate")
	}
	// Reject naked intermediate imports: they need ImportCAChain with the issuer chain.
	if cert.CheckSignatureFrom(cert) != nil {
		return nil, ErrNotSelfSigned
	}
	return cert, nil
}

// ImportCA imports a self-signed root without its private key. The CA is
// labelled key_storage_type "external". Re-importing the identical
// certificate reactivates a trust anchor previously removed (status revoked);
// any other duplicate is ErrCAAlreadyImported.
func (e *Engine) ImportCA(name string, certPEM []byte) (*CA, error) {
	cert, err := ValidateRootImport(certPEM)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if existing, err := e.listLocked(); err == nil {
		for _, c := range existing {
			if c.Certificate == nil || !bytes.Equal(c.Certificate.Raw, cert.Raw) {
				continue
			}
			if c.Status == "revoked" && c.KeyID == "" {
				if err := e.store.UpdateStatus(c.ID, "active"); err != nil {
					return nil, fmt.Errorf("reactivate imported CA: %w", err)
				}
				c.Status = "active"
				e.cache[c.ID] = c
				return c, nil
			}
			return nil, ErrCAAlreadyImported
		}
	}

	caID := newCAID()
	ca := &CA{
		ID:             caID,
		Name:           name,
		Type:           "root",
		Certificate:    cert,
		CertPEM:        certPEM,
		Status:         "active",
		KeyStorageType: "external",
		CreatedAt:      time.Now().UTC(),
	}
	if err := e.saveCA(ca); err != nil {
		return nil, fmt.Errorf("persist imported CA: %w", err)
	}

	return ca, nil
}

// listLocked returns every CA; e.mu must be held.
func (e *Engine) listLocked() ([]*CA, error) {
	return e.store.List()
}

// CheckTrustAnchorRemovable reports whether id is an imported keyless root
// with no live child CA.
func (e *Engine) CheckTrustAnchorRemovable(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.checkTrustAnchorRemovableLocked(id)
}

func (e *Engine) checkTrustAnchorRemovableLocked(id string) error {
	c, ok := e.get(id)
	if !ok {
		return ErrCANotFound
	}
	if c.Type != "root" || c.KeyID != "" {
		return ErrNotTrustAnchor
	}
	all, err := e.listLocked()
	if err != nil {
		return fmt.Errorf("list CAs: %w", err)
	}
	for _, child := range all {
		if child.ParentCAID == id && child.Status != "revoked" && child.Status != "expired" {
			return ErrTrustAnchorHasChildren
		}
	}
	return nil
}

// RemoveTrustAnchor soft-removes an imported root by marking it revoked, so
// certificates and child rows that reference it stay valid and a re-import of
// the same certificate reactivates it.
func (e *Engine) RemoveTrustAnchor(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.checkTrustAnchorRemovableLocked(id); err != nil {
		return err
	}
	if err := e.store.UpdateStatus(id, "revoked"); err != nil {
		return err
	}
	if c, ok := e.cache[id]; ok {
		c.Status = "revoked"
	}
	return nil
}

// ImportCAChain imports an intermediate CA with its full issuer chain.
// The PEM must contain one or more certificates: the first is the intermediate
// being imported; each subsequent cert must sign the previous one, ending with
// a self-signed root. Returns an error if the chain is incomplete or invalid.
func (e *Engine) ImportCAChain(name string, chainPEM []byte) (*CA, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var certs []*x509.Certificate
	rest := chainPEM
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
			return nil, fmt.Errorf("parse certificate in chain: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}

	leaf := certs[0]
	if !leaf.IsCA {
		return nil, fmt.Errorf("first certificate is not a CA certificate")
	}
	// Must not be self-signed — that's ImportCA's job.
	if leaf.CheckSignatureFrom(leaf) == nil {
		return nil, fmt.Errorf("first certificate is self-signed; use ImportCA for root CAs")
	}

	// Verify each cert is signed by the next in the chain.
	for i := 0; i < len(certs)-1; i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, fmt.Errorf("chain signature verification failed at position %d→%d: %w", i, i+1, err)
		}
	}
	// The last cert must be self-signed (root).
	root := certs[len(certs)-1]
	if err := root.CheckSignatureFrom(root); err != nil {
		return nil, fmt.Errorf("chain does not end in a self-signed root: %w", err)
	}

	// Build a single-cert PEM for the intermediate itself.
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})

	caID := newCAID()
	ca := &CA{
		ID:          caID,
		Name:        name,
		Type:        "intermediate",
		Certificate: leaf,
		CertPEM:     leafPEM,
		Status:      "active",
		CreatedAt:   time.Now().UTC(),
	}
	if err := e.saveCA(ca); err != nil {
		return nil, fmt.Errorf("persist imported intermediate CA: %w", err)
	}

	return ca, nil
}

// maxCAChainDepth bounds the ancestor walk so a corrupt ParentCAID cycle
// cannot spin.
const maxCAChainDepth = 16

// checkIssuable refuses a CA that is not active, and a CA whose ancestor is
// revoked: a revoked intermediate's children no longer chain to a trusted
// issuer, so issuing from them would mint certificates that cannot validate.
func (e *Engine) checkIssuable(c *CA) error {
	if c.Status == "revoked" {
		return fmt.Errorf("%w: %w: %s", ErrCARevoked, ErrCANotActive, c.ID)
	}
	if c.Status != "active" {
		return fmt.Errorf("%w: %s", ErrCANotActive, c.ID)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	parent := c.ParentCAID
	for depth := 0; parent != "" && depth < maxCAChainDepth; depth++ {
		anc, ok := e.get(parent)
		if !ok {
			return nil
		}
		if anc.Status == "revoked" {
			return fmt.Errorf("%w: %w: %s (ancestor %s)", ErrCARevoked, ErrCANotActive, c.ID, anc.ID)
		}
		parent = anc.ParentCAID
	}
	return nil
}

// DeleteCA removes a revoked or expired CA that has no child CAs. Active
// certificate counts are the caller's concern (the engine has no inventory).
// The store must implement CADeleter.
func (e *Engine) DeleteCA(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.get(id)
	if !ok {
		return ErrCANotFound
	}
	expired := c.Status == "expired" ||
		(c.Status == "active" && c.Certificate != nil && c.Certificate.NotAfter.Before(time.Now()))
	if c.Status != "revoked" && !expired {
		return fmt.Errorf("%w: %s", ErrCANotDeletable, id)
	}
	all, err := e.store.List()
	if err != nil {
		return err
	}
	for _, other := range all {
		if other.ParentCAID == id {
			return fmt.Errorf("%w: %s", ErrCAHasChildren, id)
		}
	}
	d, ok := e.store.(CADeleter)
	if !ok {
		return errors.New("ca store does not support deletion")
	}
	if err := d.Delete(id); err != nil {
		return err
	}
	delete(e.cache, id)
	return nil
}

// lookupActiveCA resolves caID and checks it's active with a signing key,
// the same three checks every IssueCertificate variant needs FIRST -- before
// its own CSR-type-specific verification -- to preserve the original,
// test-depended-on error precedence (a nonexistent CA must report
// ErrCANotFound even when the submitted CSR is also invalid, not the other
// way around). issueLeafCertificate repeats this lookup internally (needed
// there regardless, for the signer/serial/template work) -- a few extra
// map reads, not a correctness concern.
func (e *Engine) lookupActiveCA(caID string) (*CA, error) {
	e.mu.Lock()
	ca, ok := e.get(caID)
	e.mu.Unlock()
	if !ok {
		return nil, ErrCANotFound
	}
	if err := e.checkIssuable(ca); err != nil {
		return nil, err
	}
	if ca.KeyID == "" {
		return nil, fmt.Errorf("%w: %s (imported without private key)", ErrCANoSigningKey, caID)
	}
	return ca, nil
}

func (e *Engine) IssueCertificate(caID string, req IssuanceRequest) (*IssuedCertificate, error) {
	if ext, ok := e.externalCA(caID); ok {
		return e.issueExternal(ext, req)
	}
	if req.PQCCSR != nil {
		return e.issueCertificateFromPQCCSR(caID, req)
	}
	if req.HybridCSR != nil {
		return e.issueCertificateFromHybridCSR(caID, req)
	}

	if _, err := e.lookupActiveCA(caID); err != nil {
		return nil, err
	}

	if req.CSR == nil {
		return nil, ErrInvalidCSR
	}
	if err := req.CSR.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: CSR signature invalid", ErrInvalidCSR)
	}
	if req.Policy != nil {
		if err := ValidateAgainstTemplate(req, *req.Policy); err != nil {
			return nil, err
		}
	}
	// W5-05: the data-driven policy gate — after CA + CSR verification
	// (preserving error precedence), before signing.
	if err := e.checkIssuancePolicy(caID, req); err != nil {
		return nil, err
	}

	return e.issueLeafCertificate(caID, req, leafIssuanceParams{
		subject:     req.CSR.Subject,
		pub:         req.CSR.PublicKey,
		dnsNames:    req.CSR.DNSNames,
		ipAddresses: req.CSR.IPAddresses,
		uris:        req.CSR.URIs,
	})
}

// issueCertificateFromPQCCSR is IssueCertificate's counterpart for a
// hand-rolled ML-DSA CSR (req.PQCCSR set instead of req.CSR). The PQC CSR's
// self-signature was already verified inside ParseCertificateRequestMLDSA at
// parse time, so unlike the classical path there is no CheckSignature() call
// here -- see ca.go's IssuanceRequest.PQCCSR doc comment.
//
// Works with a CA of any signing algorithm (W4-08/G-69) -- createCertDER's
// widened dispatch routes a classical/Ed25519 CA + ML-DSA leaf through
// CreateCertificateMixedLeaf transparently; the old "CA must be ML-DSA"
// guard (W4-07) is gone.
func (e *Engine) issueCertificateFromPQCCSR(caID string, req IssuanceRequest) (*IssuedCertificate, error) {
	if _, err := e.lookupActiveCA(caID); err != nil {
		return nil, err
	}

	if req.Policy != nil {
		if err := ValidateAgainstTemplate(req, *req.Policy); err != nil {
			return nil, err
		}
		// ValidateAgainstTemplate's own algorithm check can't see req.PQCCSR
		// (it only inspects req.CSR) -- enforce the allowlist here instead.
		if len(req.Policy.AllowedAlgorithms) > 0 && !algorithmAllowed(req.Policy.AllowedAlgorithms, string(req.PQCCSR.Algorithm)) {
			return nil, fmt.Errorf("%w: %s", ErrPolicyViolation,
				PolicyViolation{
					Field:   "algorithm",
					Message: fmt.Sprintf("key algorithm %q is not in the allowed list %v for template %s", req.PQCCSR.Algorithm, req.Policy.AllowedAlgorithms, req.Policy.ID),
				})
		}
	}

	// W5-05: the data-driven policy gate.
	if err := e.checkIssuancePolicy(caID, req); err != nil {
		return nil, err
	}

	return e.issueLeafCertificate(caID, req, leafIssuanceParams{
		subject:     req.PQCCSR.Subject,
		pub:         req.PQCCSR.PublicKey,
		dnsNames:    req.PQCCSR.DNSNames,
		ipAddresses: req.PQCCSR.IPAddresses,
	})
}

// issueCertificateFromHybridCSR is IssueCertificate's counterpart for a
// hand-rolled hybrid CSR (req.HybridCSR set). Both the CSR's primary
// (classical) and alt (ML-DSA) self-signatures were already verified inside
// ParseCertificateRequestHybrid at parse time. No new signing-dispatch code
// is needed: the leaf's PRIMARY public key is always classical (per
// keystore.HybridComponents), so createCertDER's existing classical/mixed
// branches already handle it -- the ML-DSA alt-key is carried as an
// ExtraExtensions entry instead (see [DECISION] #1, W4-08 spec: no
// alt-signature is populated on CA-issued hybrid leaves -- see D-104/G-70,
// resolved: leaf-key protection is the accepted product scope, and a
// classical CA couldn't produce a real ML-DSA issuer signature anyway).
func (e *Engine) issueCertificateFromHybridCSR(caID string, req IssuanceRequest) (*IssuedCertificate, error) {
	if _, err := e.lookupActiveCA(caID); err != nil {
		return nil, err
	}

	if req.Policy != nil {
		if err := ValidateAgainstTemplate(req, *req.Policy); err != nil {
			return nil, err
		}
		if len(req.Policy.AllowedAlgorithms) > 0 && !algorithmAllowed(req.Policy.AllowedAlgorithms, string(req.HybridCSR.Algorithm)) {
			return nil, fmt.Errorf("%w: %s", ErrPolicyViolation,
				PolicyViolation{
					Field:   "algorithm",
					Message: fmt.Sprintf("key algorithm %q is not in the allowed list %v for template %s", req.HybridCSR.Algorithm, req.Policy.AllowedAlgorithms, req.Policy.ID),
				})
		}
	}

	// W5-05: the data-driven policy gate.
	if err := e.checkIssuancePolicy(caID, req); err != nil {
		return nil, err
	}

	altOID, ok := keystore.MLDSAOIDForAlgo(func() keystore.Algorithm {
		_, mldsaAlgo, _ := keystore.HybridComponents(req.HybridCSR.Algorithm)
		return mldsaAlgo
	}())
	if !ok {
		return nil, fmt.Errorf("no ML-DSA OID for hybrid algorithm %s", req.HybridCSR.Algorithm)
	}
	altPubBytes, err := req.HybridCSR.AltPublicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal alt public key: %w", err)
	}
	altSPKIDER, err := asn1.Marshal(certSPKI{
		Algorithm: certAlgID{Algorithm: altOID},
		PublicKey: asn1.BitString{Bytes: altPubBytes, BitLength: len(altPubBytes) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal alt SPKI: %w", err)
	}
	// altSignatureAlgorithm (2.5.29.73) identifies the algorithm of the
	// ISSUER's altSignatureValue (2.5.29.74) per draft-ounsworth-x509-alt-
	// sig-alg -- it is not a descriptor for the alt public key. Since this
	// leaf carries no altSignatureValue (D-104: leaf-key protection only,
	// no chain-level issuer alt-signature), emitting altSignatureAlgorithm
	// here would describe a signature that doesn't exist. Only
	// subjectAltPublicKeyInfo (2.5.29.72) is emitted.
	return e.issueLeafCertificate(caID, req, leafIssuanceParams{
		subject:     req.HybridCSR.Subject,
		pub:         req.HybridCSR.PrimaryPublicKey,
		dnsNames:    req.HybridCSR.DNSNames,
		ipAddresses: req.HybridCSR.IPAddresses,
		extraExtensions: []pkix.Extension{
			{Id: oidAltSubjectPublicKeyInfo, Value: altSPKIDER},
		},
	})
}

// leafIssuanceParams is the already-resolved, CSR-type-independent input to
// issueLeafCertificate: whatever each caller's own CSR-type-specific
// verification/parsing produced.
type leafIssuanceParams struct {
	subject         pkix.Name
	pub             crypto.PublicKey
	dnsNames        []string
	ipAddresses     []net.IP
	uris            []*url.URL
	extraExtensions []pkix.Extension
}

// issueLeafCertificate is the shared tail of IssueCertificate/
// issueCertificateFromPQCCSR/issueCertificateFromHybridCSR: CA lookup,
// active/KeyID checks, serial number, validity clamp, template assembly
// (including the caller-vs-CSR DNSNames/IPAddresses/URIs fallback and any
// extraExtensions), SKI computation, signing dispatch via createCertDER, and
// final parse/PEM/fingerprint assembly. Each caller resolves its own
// CSR-type-specific verification and policy algorithm-allowlist check
// BEFORE calling this, since ValidateAgainstTemplate's own req.CSR-based
// check can't see PQCCSR/HybridCSR.
func (e *Engine) issueLeafCertificate(caID string, req IssuanceRequest, params leafIssuanceParams) (*IssuedCertificate, error) {
	e.mu.Lock()
	ca, ok := e.get(caID)
	e.mu.Unlock()
	if !ok {
		return nil, ErrCANotFound
	}
	if err := e.checkIssuable(ca); err != nil {
		return nil, err
	}
	if ca.KeyID == "" {
		return nil, fmt.Errorf("%w: %s (imported without private key)", ErrCANoSigningKey, caID)
	}

	signer, err := e.keys.Signer(ca.KeyID)
	if err != nil {
		return nil, fmt.Errorf("get CA signer: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now().UTC()
	validity := req.Validity
	if validity == 0 {
		validity = 365 * 24 * time.Hour
	}
	if validity < 0 {
		return nil, fmt.Errorf("validity must be positive")
	}
	notAfter := now.Add(validity)
	if notAfter.After(ca.Certificate.NotAfter) {
		notAfter = ca.Certificate.NotAfter
	}
	if req.Backdate < 0 {
		return nil, fmt.Errorf("backdate must not be negative")
	}
	crlDPs, ocspURLs := req.CRLDistPoints, req.OCSPServer
	if (e.pointers != nil || e.pointersForSerial != nil) && len(crlDPs) == 0 && len(ocspURLs) == 0 && !req.IsCA && notAfter.Sub(now) > shortLivedMax {
		if e.pointersForSerial != nil {
			crlDPs, ocspURLs = e.pointersForSerial(caID, serialNumber)
		} else {
			crlDPs, ocspURLs = e.pointers(caID)
		}
	}
	extraExtensions := params.extraExtensions
	for _, ext := range req.ExtraExtensions {
		if isEngineControlledExtension(ext.Id) {
			return nil, fmt.Errorf("extra extension %s is controlled by the CA and cannot be supplied", ext.Id)
		}
		extraExtensions = append(extraExtensions, ext)
	}
	notBefore := now.Add(-req.Backdate)
	if notBefore.Before(ca.Certificate.NotBefore) {
		notBefore = ca.Certificate.NotBefore
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      params.subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     leafKeyUsage(req.KeyUsage, req.ExtKeyUsage, params.pub),
		ExtKeyUsage:  req.ExtKeyUsage,
		DNSNames:     req.DNSNames,
		IPAddresses:  req.IPAddresses,
		URIs:         req.URIs,

		IsCA:                  req.IsCA,
		MaxPathLen:            req.MaxPathLen,
		MaxPathLenZero:        req.MaxPathLenZero,
		BasicConstraintsValid: req.IsCA,

		AuthorityKeyId: ca.Certificate.SubjectKeyId,

		OCSPServer:            ocspURLs,
		CRLDistributionPoints: crlDPs,

		ExtraExtensions: extraExtensions,
	}
	profileExts, clearEKU := leafProfileExtensions(req.ExtKeyUsage)
	for _, ext := range profileExts {
		if !hasExtension(template.ExtraExtensions, ext.Id) {
			template.ExtraExtensions = append(template.ExtraExtensions, ext)
		}
	}
	if clearEKU {
		template.ExtKeyUsage = nil
	}
	// The caller-supplied req.DNSNames/.IPAddresses/.URIs win when set,
	// otherwise fall back to what the CSR itself carries (confirmed
	// necessary for the PQC/hybrid paths: certificate_ca_provider.go never
	// populates req.DNSNames for any CSR type, so without this fallback
	// every ML-DSA/hybrid-issued cert would silently carry zero SANs).
	if !req.CallerNamesOnly {
		if len(req.DNSNames) == 0 {
			template.DNSNames = params.dnsNames
		}
		if len(req.IPAddresses) == 0 {
			template.IPAddresses = params.ipAddresses
		}
		if len(req.URIs) == 0 {
			template.URIs = params.uris
		}
	}
	if req.Subject != nil {
		template.Subject = *req.Subject
	}
	// SUP-A04-3: judge the names actually about to be signed, after the
	// CSR/caller/Subject resolution above, for every CSR type.
	if err := checkNamePolicy(req.Policy, template); err != nil {
		return nil, err
	}
	if len(req.PermanentIdentifiers) > 0 {
		san, err := marshalSANExtension(template.DNSNames, template.IPAddresses, template.URIs, req.PermanentIdentifiers)
		if err != nil {
			return nil, err
		}
		template.ExtraExtensions = append(template.ExtraExtensions, san)
	}

	leafSKI, err := computeSKIAny(params.pub, "")
	if err != nil {
		return nil, fmt.Errorf("compute leaf SKI: %w", err)
	}
	template.SubjectKeyId = leafSKI

	// The CA signs the leaf; use CA's key algorithm to dispatch correctly.
	caMeta, err := e.keys.Metadata(ca.KeyID)
	if err != nil {
		return nil, fmt.Errorf("get CA key metadata: %w", err)
	}
	certDER, err := createCertDER(template, ca.Certificate, caMeta.Algorithm, params.pub, signer)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse issued certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(certDER))

	return &IssuedCertificate{
		Certificate:  cert,
		CertPEM:      certPEM,
		SerialNumber: serialNumber,
		Fingerprint:  fingerprint,
	}, nil
}

func (e *Engine) GetCA(id string) (*CA, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	ca, ok := e.get(id)
	if !ok {
		return nil, ErrCANotFound
	}
	return ca, nil
}

func (e *Engine) GetCAChain(id string) ([]*CA, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var chain []*CA
	visited := make(map[string]bool)
	current := id

	for current != "" {
		if visited[current] {
			return nil, fmt.Errorf("circular CA chain detected at %s", current)
		}
		visited[current] = true

		ca, ok := e.get(current)
		if !ok {
			return nil, fmt.Errorf("CA %s not found in chain", current)
		}
		chain = append(chain, ca)
		current = ca.ParentCAID
	}

	return chain, nil
}

func (e *Engine) ListCAs() ([]*CA, error) {
	// Always load from the authoritative store so restarts are reflected.
	cas, err := e.store.List()
	if err != nil {
		return nil, err
	}
	// Warm the cache with any entries that aren't already there.
	e.mu.Lock()
	for _, ca := range cas {
		if _, ok := e.cache[ca.ID]; !ok {
			e.cache[ca.ID] = ca
		}
	}
	e.mu.Unlock()
	return cas, nil
}

// UpdateCAStatus changes the status of a CA in both the store and the cache.
func (e *Engine) UpdateCAStatus(id, status string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.store.UpdateStatus(id, status); err != nil {
		return err
	}
	if ca, ok := e.cache[id]; ok {
		ca.Status = status
	}
	return nil
}

// createCertDER dispatches certificate creation based on the CA's signing
// algorithm AND the leaf's public-key type (G-69/W4-08: widened from
// signer-algorithm-only, which routed any non-ML-DSA CA straight to stdlib
// x509.CreateCertificate -- and stdlib rejects a non-stdlib (ML-DSA) leaf
// pubkey outright, confirmed empirically during W4-07). pub is the leaf's
// public key; signer is the CA's private key.
func createCertDER(template, parent *x509.Certificate, signerAlgo keystore.Algorithm, pub crypto.PublicKey, signer crypto.Signer) ([]byte, error) {
	switch {
	case keystore.IsMLDSA(signerAlgo):
		return CreateCertificateMLDSA(template, parent, pub, signer, signerAlgo)
	case isNonStdlibPublicKey(pub):
		// Classical or Ed25519 CA, non-stdlib (ML-DSA) leaf pubkey.
		return CreateCertificateMixedLeaf(template, parent, pub, signer, signerAlgo)
	default:
		return x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	}
}

// isNonStdlibPublicKey reports whether pub needs the hand-rolled ASN.1 path
// (stdlib x509 can't encode it into a SubjectPublicKeyInfo at all).
func isNonStdlibPublicKey(pub crypto.PublicKey) bool {
	_, ok := pub.(keystore.MLDSAPublicKey)
	return ok
}

// createCertDERHybrid creates a hybrid certificate when the CA key is a hybrid pair.
func createCertDERHybrid(template, parent *x509.Certificate, algo keystore.Algorithm, pub crypto.PublicKey, classical, mldsa crypto.Signer) ([]byte, error) {
	return CreateCertificateHybrid(template, parent, classical, mldsa, algo)
}

// computeSKIForMLDSA derives a Subject Key Identifier from an ML-DSA public key
// using the raw public key bytes (not PKIX-encoded, since x509.MarshalPKIXPublicKey
// rejects ML-DSA keys).
func computeSKIForMLDSA(pub keystore.MLDSAPublicKey) ([]byte, error) {
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal ML-DSA public key for SKI: %w", err)
	}
	hash := sha256.Sum256(pubBytes)
	return hash[:20], nil
}

// computeSKIAny computes the SKI for classical or ML-DSA public keys.
func computeSKIAny(pub crypto.PublicKey, algo keystore.Algorithm) ([]byte, error) {
	if mlPub, ok := pub.(keystore.MLDSAPublicKey); ok {
		return computeSKIForMLDSA(mlPub)
	}
	return computeSKI(pub)
}

// generateSerialNumber produces a random 128-bit serial number per RFC 5280 §4.1.2.2.
func generateSerialNumber() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("generate random serial: %w", err)
	}
	return serial, nil
}

// newCAID returns a random UUID v4 string suitable for use as a CA primary key.
func newCAID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("ca: crypto/rand unavailable: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}

// computeSKI derives a Subject Key Identifier from a public key using SHA-256.
func computeSKI(pub crypto.PublicKey) ([]byte, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key for SKI: %w", err)
	}
	hash := sha256.Sum256(pubDER)
	return hash[:20], nil // truncate to 20 bytes per common practice
}

var (
	oidCertificateExtension = asn1.ObjectIdentifier{2, 5, 29}
	oidPKIXExtension        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1}
)

// isEngineControlledExtension reports whether id is under id-ce or id-pe,
// the arcs whose extensions the engine sets from validated inputs.
func isEngineControlledExtension(id asn1.ObjectIdentifier) bool {
	for _, arc := range []asn1.ObjectIdentifier{oidCertificateExtension, oidPKIXExtension} {
		if len(id) > len(arc) && id[:len(arc)].Equal(arc) {
			return true
		}
	}
	return false
}

// PolicyEngine returns the attached issuance-policy gate, or nil when the
// engine runs without one. The admin API uses it to manage the same rows the
// issue path reads.
func (e *Engine) PolicyEngine() *PolicyEngine { return e.policy }
