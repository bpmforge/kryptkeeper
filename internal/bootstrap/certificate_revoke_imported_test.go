package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"
)

// CB-02: a certificate with no issuing CA in this hub used to answer 503
// because revStore matches rows by (serial, ca_id) and ca_id is empty.
func TestRevokeImportedCertificateRecordsInventoryRevocation(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, _ := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: mustSerialNumber(),
		Subject:      pkix.Name{CommonName: "external.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := provider.ImportCertificate(ctx, CertificateImportRequest{
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	fp := imported.FingerprintSHA256

	res, err := provider.RevokeCertificate(ctx, fp, CertificateRevokeRequest{ReasonCode: 1})
	if err != nil {
		t.Fatalf("revoke imported: %v", err)
	}
	if res.RenewalStatus != string(RenewalStatusRevoked) {
		t.Fatalf("renewal status = %q", res.RenewalStatus)
	}
	if res.RevocationScope != RevocationScopeInventoryOnly {
		t.Fatalf("revocation_scope = %q, want inventory_only", res.RevocationScope)
	}
	var revokedAt string
	if err := db.QueryRow(`SELECT revoked_at FROM certificates WHERE fingerprint_sha256 = ?`, fp).Scan(&revokedAt); err != nil || revokedAt == "" {
		t.Fatalf("revocation not persisted: %q %v", revokedAt, err)
	}
	if _, err := provider.RevokeCertificate(ctx, fp, CertificateRevokeRequest{ReasonCode: 1}); err != errCertificateConflict {
		t.Fatalf("second revoke = %v, want conflict", err)
	}
}
