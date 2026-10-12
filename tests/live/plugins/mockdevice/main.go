// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command mockdevice is a stand-in for an appliance with an HTTPS management
// API, for tests/live/plugins/run.sh. It speaks the API plugins/example
// drives, and serves whatever certificate is bound to its listener on a
// separate TLS port, so the hub's verify step dials something real.
//
// Its management certificate comes from its own throwaway CA, written to
// -ca-out, the way real devices often use an internal CA.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type device struct {
	token   string
	mu      sync.Mutex
	certs   map[string][2]string // name -> cert PEM, key PEM
	binding string
}

func selfSigned(cn string, dns []string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	if isCA {
		tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, x509.KeyUsageCertSign
	} else {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tmpl.DNSNames = dns
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	parent, signer := tmpl, key
	if ca != nil {
		parent, signer = ca, caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		log.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func main() {
	mgmt := flag.String("mgmt", "127.0.0.1:18443", "management API address")
	service := flag.String("service", "127.0.0.1:18444", "TLS service address serving the bound certificate")
	token := flag.String("token", "", "bearer token the API requires")
	caOut := flag.String("ca-out", "", "write the management CA certificate (PEM) here")
	san := flag.String("san", "", "comma-separated DNS names for the leaf certificates (the container name the hub dials)")
	flag.Parse()
	var sans []string
	for _, n := range strings.Split(*san, ",") {
		if n != "" {
			sans = append(sans, n)
		}
	}

	ca, caKey, caPEM, _ := selfSigned("Mock Device Internal CA", nil, nil, nil, true)
	if err := os.WriteFile(*caOut, caPEM, 0o600); err != nil {
		log.Fatal(err)
	}
	_, _, mgmtCert, mgmtKey := selfSigned("mock-device-mgmt", sans, ca, caKey, false)
	_, _, initCert, initKey := selfSigned("factory-default", sans, nil, nil, false)
	d := &device{token: *token, certs: map[string][2]string{"factory": {string(initCert), string(initKey)}}, binding: "factory"}

	mgmtPair, err := tls.X509KeyPair(mgmtCert, mgmtKey)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		srv := &http.Server{Addr: *mgmt, Handler: http.HandlerFunc(d.api), ReadHeaderTimeout: 5 * time.Second,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{mgmtPair}, MinVersion: tls.VersionTLS12}}
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}()
	ln, err := tls.Listen("tcp", *service, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		d.mu.Lock()
		pair := d.certs[d.binding]
		d.mu.Unlock()
		c, err := tls.X509KeyPair([]byte(pair[0]), []byte(pair[1]))
		return &c, err
	}})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("mock device: management https://%s, service %s", *mgmt, *service)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer conn.Close()
			_ = conn.(*tls.Conn).Handshake() // only the certificate it presents matters; a client that hangs up is fine
		}()
	}
}

func (d *device) api(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+d.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body) // GETs have no body; a bad body fails the per-route checks below
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case r.URL.Path == "/api/status":
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodPost && r.URL.Path == "/api/certs":
		if body["key_pem"] == "" {
			http.Error(w, "this device needs the private key", http.StatusBadRequest)
			return
		}
		d.certs[body["name"]] = [2]string{body["cert_pem"], body["key_pem"]}
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodGet && r.URL.Path == "/api/binding":
		_ = json.NewEncoder(w).Encode(map[string]string{"cert": d.binding})
	case r.Method == http.MethodPut && r.URL.Path == "/api/binding":
		if _, ok := d.certs[body["cert"]]; !ok {
			http.Error(w, "no such certificate", http.StatusNotFound)
			return
		}
		d.binding = body["cert"]
		log.Printf("mock device: listener %s now serves %s", body["listener"], body["cert"])
	default:
		http.NotFound(w, r)
	}
}
