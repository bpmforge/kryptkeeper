package connectors

import (
	"crypto/tls"
	"net/http"
)

// testClient stands in for the hub-built egress client: the loopback httptest
// servers would be refused by the real guard, so the tests build the
// transport themselves (as the hub does, from TLSMaterial).
func testClient(clientCertPEM, clientKeyPEM, caCertPEM string) *http.Client {
	certs, pool, _ := TLSMaterial(clientCertPEM, clientKeyPEM, caCertPEM)
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: certs, RootCAs: pool, MinVersion: tls.VersionTLS12,
	}}}
}
