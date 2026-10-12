// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// tlsecho is a fixture-only TLS listener for W19-03's kind UAT: it re-reads
// its certificate/key from disk on every handshake (no caching, no reload
// signal needed) so the fixture can prove "a workload picks up the pushed
// Secret" without building a config-reload sidecar. This is test scaffolding,
// never shipped, and carries no product logic.
package main

import (
	"crypto/tls"
	"log"
	"net"
	"os"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatalf("usage: %s listen-addr cert-path key-path", os.Args[0])
	}
	addr, certPath, keyPath := os.Args[1], os.Args[2], os.Args[3]

	cfg := &tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
	}
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	log.Printf("tlsecho listening on %s (cert=%s key=%s)", addr, certPath, keyPath)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		// crypto/tls defers the handshake to the first Read/Write -- Accept
		// alone never sends the certificate. Force it explicitly so a bare
		// "dial and disconnect" verifier (agentinstall.defaultVerifier)
		// actually observes the leaf instead of a bare EOF.
		go func(c net.Conn) {
			defer c.Close()
			if tc, ok := c.(*tls.Conn); ok {
				if hsErr := tc.Handshake(); hsErr != nil {
					log.Printf("handshake: %v", hsErr)
				}
			}
		}(conn)
	}
}
