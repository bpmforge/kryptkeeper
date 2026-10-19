// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command hybridcsr writes a hybrid (ECDSA + ML-DSA) certificate request for the W31-04
// live interop drill: PREFIX.csr is valid, PREFIX.bad.csr has one byte flipped inside the
// classical self-signature so proof-of-possession must fail. The throwaway keys live in a
// temp directory that is removed on exit; only the CSRs are written.
package main

import (
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "hybridcsr:", err)
		os.Exit(1)
	}
}

func run() error {
	algo := flag.String("algo", "Hybrid-ECDSA-P256-ML-DSA-65", "hybrid algorithm")
	cn := flag.String("cn", "", "subject CN, also used as the DNS SAN")
	out := flag.String("out", "", "output path prefix")
	flag.Parse()
	if *cn == "" || *out == "" {
		return fmt.Errorf("-cn and -out are required")
	}

	dir, err := os.MkdirTemp("", "hybridcsr-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	store, err := keystore.NewSoftwareStore(dir, []byte("live-drill-throwaway-passphrase"))
	if err != nil {
		return err
	}
	a := keystore.Algorithm(*algo)
	if _, err := store.GenerateKey("drill", a); err != nil {
		return fmt.Errorf("generate %s key: %w", a, err)
	}
	pair, err := store.LoadHybridKeyPair("drill")
	if err != nil {
		return err
	}
	der, err := ca.CreateCertificateRequestHybrid(pkix.Name{CommonName: *cn}, []string{*cn}, nil, pair.Primary, pair.Secondary, a)
	if err != nil {
		return err
	}
	if _, err := ca.ParseCertificateRequestHybrid(der); err != nil {
		return fmt.Errorf("self-check of the valid CSR failed: %w", err)
	}
	bad := append([]byte(nil), der...)
	bad[len(bad)-8] ^= 0xFF
	if _, err := ca.ParseCertificateRequestHybrid(bad); err == nil {
		return fmt.Errorf("corrupted CSR still parses; the drill would prove nothing")
	}
	for suffix, b := range map[string][]byte{".csr": der, ".bad.csr": bad} {
		blk := pem.EncodeToMemory(&pem.Block{Type: "HYBRID CERTIFICATE REQUEST", Bytes: b})
		if err := os.WriteFile(*out+suffix, blk, 0o600); err != nil {
			return err
		}
	}
	return nil
}
