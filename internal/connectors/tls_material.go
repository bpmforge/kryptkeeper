package connectors

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// TLSMaterial parses the optional mTLS client pair and private-root PEMs a
// connector config carries. The connectors never build transports from it:
// the hub builds the egress-guarded *http.Client from this material (see
// upstreamConnectorMTLSClient) and hands it to the constructor, so every
// upstream CA call stays behind the egress guard. Connectors may call it to
// validate their PEM fields. Empty inputs yield nil results. Errors never
// echo PEM bytes.
func TLSMaterial(clientCertPEM, clientKeyPEM, caCertPEM string) ([]tls.Certificate, *x509.CertPool, error) {
	var certs []tls.Certificate
	if clientCertPEM != "" || clientKeyPEM != "" {
		pair, err := tls.X509KeyPair([]byte(clientCertPEM), []byte(clientKeyPEM))
		if err != nil {
			// Deliberately not wrapping err: parse errors must never echo key material.
			return nil, nil, errors.New("client certificate/key PEM is invalid")
		}
		certs = []tls.Certificate{pair}
	}
	var pool *x509.CertPool
	if caCertPEM != "" {
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caCertPEM)) {
			return nil, nil, errors.New("ca_cert_pem contains no certificates")
		}
	}
	return certs, pool, nil
}
