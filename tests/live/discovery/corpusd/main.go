// corpusd serves the W24-01 TLS discovery corpus: one listener per ground-truth
// endpoint, each on its own address of the fixture /24. All keys and
// certificates are generated in memory at start; nothing is persisted except
// the SHA-256 of each served leaf (served.json), which the harness compares
// against what discovery recorded.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

type endpoint struct {
	ID      string `json:"id"`
	IPIndex int    `json:"ip_index"`
	Port    int    `json:"port"`
	Class   string `json:"class"`
	TLSMin  string `json:"tls_min"`
	TLSMax  string `json:"tls_max"`
	Cert    string `json:"cert"`
	Key     string `json:"key"`
	Hybrid  bool   `json:"hybrid"`
	SNIOnly bool   `json:"sni_only"`
	CloneOf string `json:"clone_of"`
}

type truth struct {
	Start     int        `json:"subnet_octet4_start"`
	Endpoints []endpoint `json:"endpoints"`
	Extras    []endpoint `json:"extra_port_endpoints"`
}

var versions = map[string]uint16{
	"TLSv1.0": tls.VersionTLS10, "TLSv1.1": tls.VersionTLS11,
	"TLSv1.2": tls.VersionTLS12, "TLSv1.3": tls.VersionTLS13,
}

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}

func serial() *big.Int {
	return must(rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100)))
}

func genKey(kind string) crypto.Signer {
	if kind == "rsa2048" {
		return must(rsa.GenerateKey(rand.Reader, 2048))
	}
	return must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
}

func main() {
	truthPath := flag.String("truth", "/ground-truth.json", "ground truth file")
	outPath := flag.String("out", "/out/served.json", "served fingerprints output")
	flag.Parse()
	prefix := os.Getenv("CORPUS_PREFIX")
	if prefix == "" {
		log.Fatal("CORPUS_PREFIX required")
	}
	var gt truth
	if err := json.Unmarshal(must(os.ReadFile(*truthPath)), &gt); err != nil {
		log.Fatal(err)
	}

	caKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	caTmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "corpus throwaway CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caCert := must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey))))

	mk := func(e endpoint, host, cn string) (tls.Certificate, string) {
		key := genKey(e.Key)
		now := time.Now()
		tmpl := &x509.Certificate{
			SerialNumber: serial(), Subject: pkix.Name{CommonName: cn},
			DNSNames: []string{cn}, IPAddresses: []net.IP{net.ParseIP(host)},
			NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		parent, signer := caCert, crypto.Signer(caKey)
		switch e.Cert {
		case "expired":
			tmpl.NotBefore, tmpl.NotAfter = now.Add(-72*time.Hour), now.Add(-24*time.Hour)
		case "self_signed":
			parent, signer = tmpl, key
		}
		der := must(x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signer))
		sum := sha256.Sum256(der)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:])
	}

	byID := map[string]endpoint{}
	all := append([]endpoint{}, gt.Endpoints...)
	for _, e := range gt.Endpoints {
		byID[e.ID] = e
	}
	for _, x := range gt.Extras {
		c := byID[x.CloneOf]
		c.ID, c.IPIndex, c.Port = x.ID, x.IPIndex, x.Port
		all = append(all, c)
	}

	served := map[string]map[string]string{}
	for _, e := range all {
		host := fmt.Sprintf("%s.%d", prefix, gt.Start+e.IPIndex)
		addr := net.JoinHostPort(host, fmt.Sprint(e.Port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("listen %s (%s): %v", addr, e.ID, err)
		}
		if e.Cert == "none" { // not_tls: plaintext HTTP on a TLS port
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func() {
						defer c.Close()
						_ = c.SetDeadline(time.Now().Add(5 * time.Second))
						buf := make([]byte, 512)
						_, _ = c.Read(buf)
						_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
					}()
				}
			}()
			served[e.ID] = map[string]string{}
			continue
		}
		def, fp := mk(e, host, strings.ReplaceAll(e.ID, "_", "-")+".corpus.test")
		served[e.ID] = map[string]string{"leaf_sha256": fp}
		cfg := &tls.Config{
			MinVersion: versions[e.TLSMin], MaxVersion: versions[e.TLSMax],
			CurvePreferences: []tls.CurveID{tls.X25519},
			Certificates:     []tls.Certificate{def},
		}
		if e.Hybrid {
			cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.X25519}
		}
		if e.SNIOnly {
			sni := strings.ReplaceAll(e.ID, "_", "-") + ".app.corp.test"
			sniCert, _ := mk(e, host, sni)
			cfg.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if h.ServerName == sni {
					return &sniCert, nil
				}
				return &def, nil // scanning by IP carries no SNI: default cert
			}
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(10 * time.Second))
					tc := tls.Server(c, cfg)
					if tc.Handshake() == nil {
						_, _ = tc.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
					}
				}()
			}
		}()
	}
	out := must(json.Marshal(served))
	if err := os.WriteFile(*outPath, out, 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("serving %d endpoints", len(all))
	select {}
}
