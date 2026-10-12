// Minimal real-client EST harness using the globalsign/est library (the same
// module cmd/estclient wraps) -- avoids the CLI binary, which fails to build
// because its optional PKCS#11/crypto11 path does not compile against the
// pkcs11 version go install@latest resolves today (unrelated to Kryptkeeper).
//
// W19-14: the hub now serves TLS (previously it had none at all, so this
// harness could never get past the handshake). This follows RFC 7030
// §3.6.1's bootstrap-distribution-of-trust-anchors flow: fetch cacerts once
// over an unverified connection (the only point where that's acceptable --
// the cacerts response itself is what establishes the trust anchor), then
// re-verify with a real x509.CertPool built from that response and use it,
// not InsecureSkipVerify, for every subsequent call.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"

	"github.com/globalsign/est"
)

func main() {
	host := os.Getenv("EST_HOST") // host:port, no scheme
	if host == "" {
		host = "host.containers.internal:8096"
	}

	fmt.Println("== bootstrap: cacerts over an unverified connection ==")
	bootstrapClient := &est.Client{
		Host:               host,
		InsecureSkipVerify: true, // only acceptable here: this response IS the trust anchor
	}
	bootstrapCerts, err := bootstrapClient.CACerts(context.Background())
	if err != nil {
		fmt.Printf("FAIL bootstrap cacerts: %v\n", err)
		os.Exit(1)
	}
	if len(bootstrapCerts) == 0 {
		fmt.Println("FAIL bootstrap cacerts: server returned zero certificates")
		os.Exit(1)
	}
	fmt.Printf("PASS bootstrap cacerts: %d certs\n", len(bootstrapCerts))

	anchors := x509.NewCertPool()
	for _, c := range bootstrapCerts {
		anchors.AddCert(c)
	}

	// W20-14: enrollment needs a credential. Basic for the first
	// certificate, then that certificate as the TLS client credential for
	// re-enrollment.
	client := &est.Client{
		Host:           host,
		ExplicitAnchor: anchors, // real chain verification from here on, no bypass
		Username:       os.Getenv("EST_USER"),
		Password:       os.Getenv("EST_PASS"),
	}

	fmt.Println("== cacerts (verified) ==")
	certs, err := client.CACerts(context.Background())
	if err != nil {
		fmt.Printf("FAIL cacerts: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS cacerts: %d certs\n", len(certs))
	for _, c := range certs {
		fmt.Printf("  subject=%s\n", c.Subject)
	}

	fmt.Println("== enroll ==")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "uat-est-leaf.est.uat.example"}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		fmt.Printf("FAIL build CSR: %v\n", err)
		os.Exit(1)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		fmt.Printf("FAIL parse CSR: %v\n", err)
		os.Exit(1)
	}
	cert, err := client.Enroll(context.Background(), csr)
	if err != nil {
		fmt.Printf("FAIL enroll: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS enroll: got cert subject=%s serial=%s\n", cert.Subject, cert.SerialNumber)

	fmt.Println("== reenroll ==")
	renewKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	renewTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "uat-est-leaf.est.uat.example"}}
	renewCSRDER, err := x509.CreateCertificateRequest(rand.Reader, renewTmpl, renewKey)
	if err != nil {
		fmt.Printf("FAIL build renewal CSR: %v\n", err)
		os.Exit(1)
	}
	renewCSR, err := x509.ParseCertificateRequest(renewCSRDER)
	if err != nil {
		fmt.Printf("FAIL parse renewal CSR: %v\n", err)
		os.Exit(1)
	}
	holder := &est.Client{
		Host:           host,
		ExplicitAnchor: anchors,
		Certificates:   []*x509.Certificate{cert},
		PrivateKey:     key,
	}
	renewedCert, err := holder.Reenroll(context.Background(), renewCSR)
	if err != nil {
		fmt.Printf("FAIL reenroll: %v\n", err)
		os.Exit(1)
	}
	if renewedCert.Subject.String() != cert.Subject.String() || renewedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
		fmt.Printf("FAIL reenroll: subject %s serial %s, want a new serial for %s\n", renewedCert.Subject, renewedCert.SerialNumber, cert.Subject)
		os.Exit(1)
	}
	fmt.Printf("PASS reenroll: got cert subject=%s serial=%s\n", renewedCert.Subject, renewedCert.SerialNumber)
}
