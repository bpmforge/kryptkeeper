// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cloudinventory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
)

// W38-05: connectors return the certificate body where the provider offers it.

func testCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

type fakeACM struct {
	pemByARN map[string]string
	failGet  bool
	gets     []string
}

func (f *fakeACM) ListCertificates(context.Context, *acm.ListCertificatesInput, ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	return &acm.ListCertificatesOutput{CertificateSummaryList: []acmtypes.CertificateSummary{
		{CertificateArn: aws.String("arn:aws:acm:us-east-1:111122223333:certificate/issued"), DomainName: aws.String("a.example.com"), Status: acmtypes.CertificateStatusIssued},
		{CertificateArn: aws.String("arn:aws:acm:us-east-1:111122223333:certificate/pending"), DomainName: aws.String("b.example.com"), Status: acmtypes.CertificateStatusPendingValidation},
	}}, nil
}

func (f *fakeACM) GetCertificate(_ context.Context, in *acm.GetCertificateInput, _ ...func(*acm.Options)) (*acm.GetCertificateOutput, error) {
	f.gets = append(f.gets, aws.ToString(in.CertificateArn))
	if f.failGet {
		return nil, errors.New("AccessDeniedException")
	}
	return &acm.GetCertificateOutput{Certificate: aws.String(f.pemByARN[aws.ToString(in.CertificateArn)])}, nil
}

func TestACMFetchesBodyOnlyForIssuedAndToleratesDenial(t *testing.T) {
	want := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCertDER(t, "a.example.com")}))
	f := &fakeACM{pemByARN: map[string]string{"arn:aws:acm:us-east-1:111122223333:certificate/issued": want}}
	c := &ACMConnector{client: f, region: "us-east-1"}
	certs, err := c.ListCertificates(t.Context())
	if err != nil || len(certs) != 2 {
		t.Fatalf("list: %v len=%d", err, len(certs))
	}
	if certs[0].CertificatePEM != want || certs[1].CertificatePEM != "" {
		t.Fatalf("issued must carry the body, pending must not: %q / %q", certs[0].CertificatePEM, certs[1].CertificatePEM)
	}
	if len(f.gets) != 1 {
		t.Fatalf("GetCertificate called for %v, want only the issued ARN", f.gets)
	}

	f2 := &fakeACM{failGet: true}
	certs, err = (&ACMConnector{client: f2, region: "us-east-1"}).ListCertificates(t.Context())
	if err != nil || len(certs) != 2 || certs[0].CertificatePEM != "" {
		t.Fatalf("a denied GetCertificate must leave the row metadata-only, not fail the scan: %v", err)
	}
}

func TestCloudCertificatePEMNeverSerialized(t *testing.T) {
	raw, _ := json.Marshal(CloudCertificate{ResourceID: "r", CertificatePEM: "-----BEGIN CERTIFICATE-----"})
	if strings.Contains(string(raw), "BEGIN") {
		t.Fatalf("PEM leaked into JSON: %s", raw)
	}
}

func TestAzureFetchesCerAndRefusesForeignHosts(t *testing.T) {
	der := testCertDER(t, "web-tls")
	var gotVersion, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if strings.HasPrefix(r.URL.Path, "/certificates/web-tls/abc123") {
			gotVersion = r.URL.Query().Get("api-version")
			_ = json.NewEncoder(w).Encode(map[string]string{"cer": base64.StdEncoding.EncodeToString(der)})
			return
		}
		_ = json.NewEncoder(w).Encode(azureCertListResponse{Value: []azureCertItem{
			{ID: "http://" + r.Host + "/certificates/web-tls/abc123"},
			{ID: "https://evil.example/certificates/x/1"},
		}})
	}))
	defer srv.Close()
	c := &AzureKVConnector{client: srv.Client(), vaultURL: srv.URL, token: "tok", apiVersion: "7.4"}

	// httptest serves http, which the https-only guard must refuse; the guard
	// is what keeps the bearer token on the scope's own vault.
	certs, err := c.ListCertificates(t.Context())
	if err != nil || len(certs) != 2 {
		t.Fatalf("list: %v len=%d", err, len(certs))
	}
	if certs[0].CertificatePEM != "" || certs[1].CertificatePEM != "" {
		t.Fatal("non-https or foreign ids must not be fetched")
	}

	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotVersion = r.URL.Query().Get("api-version")
		_ = json.NewEncoder(w).Encode(map[string]string{"cer": base64.StdEncoding.EncodeToString(der)})
	}))
	defer tls.Close()
	c2 := &AzureKVConnector{client: tls.Client(), vaultURL: tls.URL, token: "tok", apiVersion: "7.4"}
	got := c2.fetchPEM(t.Context(), tls.URL+"/certificates/web-tls/abc123")
	block, _ := pem.Decode([]byte(got))
	if block == nil || block.Type != "CERTIFICATE" || string(block.Bytes) != string(der) {
		t.Fatalf("expected the DER round-tripped as PEM, got %q", got)
	}
	if gotAuth != "Bearer tok" || gotVersion != "7.4" {
		t.Fatalf("auth=%q version=%q", gotAuth, gotVersion)
	}
}

func TestGCPCarriesOutputOnlyPemCertificate(t *testing.T) {
	want := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCertDER(t, "g.example.com")}))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"certificates": []map[string]any{
			{"name": "projects/p/locations/global/certificates/c", "pemCertificate": want, "managed": map[string]any{"state": "ACTIVE", "domains": []string{"g.example.com"}}},
			{"name": "projects/p/locations/global/certificates/provisioning", "managed": map[string]any{"state": "PROVISIONING"}},
		}})
	}))
	defer srv.Close()
	c := &GCPCertManagerConnector{client: srv.Client(), projectID: "p", region: "global", token: "t", apiBase: srv.URL}
	certs, err := c.ListCertificates(t.Context())
	if err != nil || len(certs) != 2 {
		t.Fatalf("list: %v len=%d", err, len(certs))
	}
	if certs[0].CertificatePEM != want || certs[1].CertificatePEM != "" {
		t.Fatalf("active carries the chain, provisioning does not: %q / %q", certs[0].CertificatePEM, certs[1].CertificatePEM)
	}
}
