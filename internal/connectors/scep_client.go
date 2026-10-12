// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/smallstep/pkcs7"
)

// W13-03/W19-28: SCEP (RFC 8894) client -- drive any legacy CA speaking SCEP
// as an upstream issuer.
//
// This speaks the real RFC 8894 PKIOperation exchange: the requester's own
// key signs a self-signed throwaway identity certificate, that identity
// signs a CMS SignedData wrapping a CMS EnvelopedData (the CSR, encrypted to
// the CA's RSA public key), and the CA's CertRep is itself encrypted back to
// the requester's identity certificate -- so the client must hold both a
// crypto.Signer (to sign the request) and a crypto.Decrypter (to open the
// reply) for that same key. IssueRequest.Signer/Decrypter carry that handle
// in-process; there is no wire representation for a private key, so only
// in-process callers (the renewal executor, which generates the key
// hub-side -- see internal/bootstrap/renewal_executor.go) can drive this
// connector. Classic SCEP's key-transport envelope is RSA PKCS#1v1.5/OAEP
// only (github.com/smallstep/pkcs7 enforces this: "only RSA keys are
// supported" for Encrypt/Decrypt), so both the upstream CA's key and the
// requester's key must be RSA; an EC upstream CA is rejected with a clear
// error rather than silently failing at the encrypt step.
//
// v1 (pre-W19-15) spoke a simplified raw-CSR profile no real SCEP CA
// accepts, proven only against a fixture double. This version is proven
// against internal/scep.Server, which W19-15 made a real RFC 8894 endpoint.

// SCEPClientConfig locates the SCEP endpoint.
type SCEPClientConfig struct {
	// EndpointURL is the SCEP URL, e.g. https://ca.example.com/scep.
	EndpointURL string
}

// SCEPClient is an IssuerConnector backed by a remote SCEP CA.
type SCEPClient struct {
	id     string
	cfg    SCEPClientConfig
	client *http.Client
}

func NewSCEPClient(id string, cfg SCEPClientConfig, client *http.Client) *SCEPClient {
	if client == nil {
		client = http.DefaultClient
	}
	return &SCEPClient{id: id, cfg: cfg, client: client}
}

func (c *SCEPClient) ID() string     { return c.id }
func (c *SCEPClient) Type() string   { return "scep" }
func (c *SCEPClient) Origin() string { return "synced" }

// Health probes GetCACaps — the mandatory capabilities operation.
func (c *SCEPClient) Health(ctx context.Context) Health {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.EndpointURL+"?operation=GetCACaps", nil)
	if err != nil {
		return Health{Status: "degraded", Detail: err.Error()}
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return Health{Status: "degraded", Detail: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return Health{Status: "degraded", Detail: fmt.Sprintf("GetCACaps HTTP %d", resp.StatusCode)}
	}
	return Health{Status: "healthy"}
}

// scepMessageType / pkiStatus / failInfo values (RFC 8894 §3.2, §3.3,
// §3.3.3). Duplicated from internal/scep rather than imported: that
// package's OIDs and constants are unexported (the server has no reason to
// expose them), and the two implementations independently agreeing on the
// RFC's fixed values is the point, not a maintenance burden.
const (
	scepMsgTypePKCSReq = "19"

	scepPKIStatusSuccess = "0"
	scepPKIStatusFailure = "2"
	scepPKIStatusPending = "3"
)

var (
	oidSCEPMessageType    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPPKIStatus      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidSCEPFailInfo       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	oidSCEPSenderNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPRecipientNonce = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	oidSCEPTransactionID  = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
)

// Issue drives a real RFC 8894 PKIOperation and returns the issued cert.
func (c *SCEPClient) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	if req.Signer == nil || req.Decrypter == nil {
		return IssueResult{}, fmt.Errorf("scep client %s: SCEP requires a Signer and Decrypter bound to the CSR's key (only in-process callers can drive this connector)", c.id)
	}
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		return IssueResult{}, fmt.Errorf("scep client %s: CSRPEM is not a PEM certificate request", c.id)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return IssueResult{}, fmt.Errorf("scep client %s: invalid CSR: %w", c.id, err)
	}

	caCert, err := c.fetchCACert(ctx)
	if err != nil {
		return IssueResult{}, err
	}
	if _, ok := caCert.PublicKey.(*rsa.PublicKey); !ok {
		return IssueResult{}, fmt.Errorf("scep client %s: upstream CA key is %T, not RSA -- classic SCEP's PKCS#7 key-transport envelope has no non-RSA analogue", c.id, caCert.PublicKey)
	}

	identityCN := csr.Subject.CommonName
	if identityCN == "" {
		identityCN = c.id
	}
	clientCert, err := selfSignedSCEPIdentity(req.Signer, identityCN)
	if err != nil {
		return IssueResult{}, fmt.Errorf("scep client %s: building self-signed identity: %w", c.id, err)
	}

	msgDER, txID, nonce, err := buildSCEPPKIOperation(caCert, clientCert, req.Signer, block.Bytes)
	if err != nil {
		return IssueResult{}, fmt.Errorf("scep client %s: building PKIOperation: %w", c.id, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.EndpointURL+"?operation=PKIOperation", bytes.NewReader(msgDER))
	if err != nil {
		return IssueResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/x-pki-message")
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return IssueResult{}, fmt.Errorf("scep client %s: %w", c.id, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // error surfaces via status/parse below
	if resp.StatusCode >= 400 {
		return IssueResult{}, fmt.Errorf("scep client %s: PKIOperation HTTP %d: %s", c.id, resp.StatusCode, truncate(raw))
	}

	return parseSCEPCertRep(c.id, raw, caCert, clientCert, req.Decrypter, txID, nonce)
}

// fetchCACert retrieves and parses the upstream CA certificate — the
// envelopedData recipient every PKIOperation encrypts its CSR to.
func (c *SCEPClient) fetchCACert(ctx context.Context) (*x509.Certificate, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.EndpointURL+"?operation=GetCACert", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("scep client %s: GetCACert: %w", c.id, err)
	}
	defer resp.Body.Close()
	der, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("scep client %s: GetCACert HTTP %d", c.id, resp.StatusCode)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("scep client %s: GetCACert response is not a valid certificate: %w", c.id, err)
	}
	return cert, nil
}

// selfSignedSCEPIdentity builds the throwaway self-signed certificate RFC
// 8894 §3.2.2 requires: there is no issued certificate yet to authenticate
// the enrollment, so the requester vouches for its own freshly generated key
// for the duration of this one transaction.
func selfSignedSCEPIdentity(signer crypto.Signer, cn string) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// buildSCEPPKIOperation wraps csrDER in a CMS EnvelopedData (recipient: the
// CA) inside a CMS SignedData (signer: the requester's throwaway identity),
// exactly as RFC 8894 §3.2 requires.
func buildSCEPPKIOperation(caCert, clientCert *x509.Certificate, signer crypto.Signer, csrDER []byte) (msgDER []byte, txID string, nonce []byte, err error) {
	envelopeDER, err := pkcs7.Encrypt(csrDER, []*x509.Certificate{caCert})
	if err != nil {
		return nil, "", nil, fmt.Errorf("encrypting CSR to CA: %w", err)
	}

	sd, err := pkcs7.NewSignedData(envelopeDER)
	if err != nil {
		return nil, "", nil, err
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)

	txIDBytes := make([]byte, 8)
	if _, err := rand.Read(txIDBytes); err != nil {
		return nil, "", nil, fmt.Errorf("generating transactionID: %w", err)
	}
	txID = hex.EncodeToString(txIDBytes)

	nonce = make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", nil, fmt.Errorf("generating senderNonce: %w", err)
	}

	extra := []pkcs7.Attribute{
		{Type: oidSCEPMessageType, Value: asn1.RawValue{Tag: 19, Bytes: []byte(scepMsgTypePKCSReq)}},
		{Type: oidSCEPTransactionID, Value: asn1.RawValue{Tag: 19, Bytes: []byte(txID)}},
		{Type: oidSCEPSenderNonce, Value: asn1.RawValue{Tag: 4, Bytes: nonce}},
	}
	if err := sd.AddSigner(clientCert, signer, pkcs7.SignerInfoConfig{ExtraSignedAttributes: extra}); err != nil {
		return nil, "", nil, fmt.Errorf("signing pkiMessage: %w", err)
	}
	msgDER, err = sd.Finish()
	if err != nil {
		return nil, "", nil, err
	}
	return msgDER, txID, nonce, nil
}

// parseSCEPCertRep verifies and decodes a CertRep pkiMessage, handling all
// three RFC 8894 §3.3 outcomes.
func parseSCEPCertRep(id string, raw []byte, caCert, clientCert *x509.Certificate, decrypter crypto.Decrypter, wantTxID string, wantNonce []byte) (IssueResult, error) {
	p7, err := pkcs7.Parse(raw)
	if err != nil {
		return IssueResult{}, fmt.Errorf("scep client %s: CertRep does not parse as PKCS#7: %w", id, err)
	}
	if err := p7.Verify(); err != nil {
		return IssueResult{}, fmt.Errorf("scep client %s: CertRep signature verification failed: %w", id, err)
	}
	// The CA's own PKIOperation reply must be signed by the exact CA
	// certificate the CSR was encrypted to (fetched via GetCACert above) --
	// p7.Verify() only proves the embedded signer's signature is valid, not
	// that the embedded signer IS the CA, so a network attacker who could
	// answer PKIOperation with their own self-signed cert must still be
	// caught here.
	signer := p7.GetOnlySigner()
	if signer == nil || !bytes.Equal(signer.Raw, caCert.Raw) {
		return IssueResult{}, fmt.Errorf("scep client %s: CertRep was not signed by the expected CA certificate", id)
	}

	var txID, status, failInfo asn1.RawValue
	var recipientNonce asn1.RawValue
	if err := p7.UnmarshalSignedAttribute(oidSCEPTransactionID, &txID); err != nil {
		return IssueResult{}, fmt.Errorf("scep client %s: CertRep missing transactionID: %w", id, err)
	}
	if string(txID.Bytes) != wantTxID {
		return IssueResult{}, fmt.Errorf("scep client %s: CertRep transactionID mismatch (possible cross-talk or replay)", id)
	}
	if err := p7.UnmarshalSignedAttribute(oidSCEPPKIStatus, &status); err != nil {
		return IssueResult{}, fmt.Errorf("scep client %s: CertRep missing pkiStatus: %w", id, err)
	}
	if err := p7.UnmarshalSignedAttribute(oidSCEPRecipientNonce, &recipientNonce); err == nil {
		if !bytes.Equal(recipientNonce.Bytes, wantNonce) {
			return IssueResult{}, fmt.Errorf("scep client %s: CertRep recipientNonce does not echo our senderNonce", id)
		}
	}
	_ = p7.UnmarshalSignedAttribute(oidSCEPFailInfo, &failInfo) // absent on SUCCESS/PENDING

	switch string(status.Bytes) {
	case scepPKIStatusPending:
		return IssueResult{}, fmt.Errorf("scep client %s: request PENDING (txn %s) -- upstream requires manual approval, retry later", id, wantTxID)
	case scepPKIStatusFailure:
		return IssueResult{}, fmt.Errorf("scep client %s: request FAILED (txn %s, failInfo=%q)", id, wantTxID, string(failInfo.Bytes))
	case scepPKIStatusSuccess:
		// fall through
	default:
		return IssueResult{}, fmt.Errorf("scep client %s: unrecognized pkiStatus %q", id, string(status.Bytes))
	}

	envelope, err := pkcs7.Parse(p7.Content)
	if err != nil {
		return IssueResult{}, fmt.Errorf("scep client %s: CertRep content is not a PKCS#7 envelope: %w", id, err)
	}
	certsOnlyDER, err := envelope.Decrypt(clientCert, decrypter)
	if err != nil {
		return IssueResult{}, fmt.Errorf("scep client %s: decrypting CertRep: %w", id, err)
	}
	degenerate, err := pkcs7.Parse(certsOnlyDER)
	if err != nil || len(degenerate.Certificates) == 0 {
		return IssueResult{}, fmt.Errorf("scep client %s: CertRep did not decrypt to a certs-only PKCS#7 structure: %w", id, err)
	}
	cert := degenerate.Certificates[0]
	sum := sha256.Sum256(cert.Raw)
	return IssueResult{
		FingerprintSHA256: hex.EncodeToString(sum[:]),
		CertificatePEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}, nil
}
