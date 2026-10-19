// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command fakeidp is a tiny CI OIDC issuer for the W29 code-signing live test:
// discovery, a JWKS, and GET /token?repo=&ref=&aud=&provider= which mints an
// RS256 token shaped like GitHub Actions (repository/ref) or GitLab CI
// (project_path/ref). The signing key is generated per process and never
// leaves it. It is a test fixture, not a product binary.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"math/big"
	"net/http"
	"time"
)

const kid = "fakeidp-1"

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func main() {
	addr := flag.String("addr", ":9443", "listen address")
	issuer := flag.String("issuer", "", "issuer URL placed in iss (must match the trust rule)")
	cert := flag.String("cert", "", "TLS certificate PEM")
	key := flag.String("key", "", "TLS key PEM")
	flag.Parse()
	if *issuer == "" || *cert == "" || *key == "" {
		log.Fatal("-issuer, -cert and -key are required")
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": *issuer, "jwks_uri": *issuer + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
			"n": b64(priv.N.Bytes()), "e": b64(big.NewInt(int64(priv.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		repo, ref, aud := q.Get("repo"), q.Get("ref"), q.Get("aud")
		if repo == "" || ref == "" || aud == "" {
			http.Error(w, "repo, ref and aud are required", http.StatusBadRequest)
			return
		}
		jti := make([]byte, 16)
		_, _ = rand.Read(jti)
		now := time.Now()
		claims := map[string]any{
			"iss": *issuer, "aud": aud, "sub": "repo:" + repo + ":ref:" + ref,
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			"jti": hex.EncodeToString(jti), "ref": ref,
		}
		if q.Get("provider") == "gitlab" {
			claims["project_path"] = repo
		} else {
			claims["repository"] = repo
		}
		hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
		body, _ := json.Marshal(claims)
		in := b64(hdr) + "." + b64(body)
		sum := sha256.Sum256([]byte(in))
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
		if err != nil {
			http.Error(w, "sign failed", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": in + "." + b64(sig)})
	})
	log.Printf("fakeidp issuer=%s listening on %s", *issuer, *addr)
	log.Fatal(http.ListenAndServeTLS(*addr, *cert, *key, mux))
}
