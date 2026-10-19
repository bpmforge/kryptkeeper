// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command emulator is a wire-format-only Cloud KMS REST emulator for the
// W23-14 live harness. Google ships no official Cloud KMS emulator, so this
// generates real keys and real signatures behind the four routes Kryptkeeper
// calls (create key, getPublicKey, asymmetricSign, destroy). It proves request
// and response shapes, NOT IAM, quotas, key states or HSM behaviour.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"sync"
)

type key struct {
	priv      crypto.Signer
	destroyed bool
}

type server struct {
	mu   sync.Mutex
	keys map[string]*key // by full cryptoKey resource name
}

// Handler returns the emulator's HTTP handler.
func Handler() http.Handler {
	s := &server{keys: map[string]*key{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/", s.serve)
	return mux
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": msg}})
}

func (s *server) serve(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		fail(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v1/")

	if r.Method == http.MethodPost && strings.HasSuffix(path, "/cryptoKeys") {
		s.create(w, r, path)
		return
	}
	name, tail, ok := strings.Cut(path, "/cryptoKeyVersions/1")
	k := s.keys[name]
	if !ok || k == nil {
		fail(w, http.StatusNotFound, "key not found")
		return
	}
	switch {
	case r.Method == http.MethodGet && tail == "/publicKey":
		der, err := x509.MarshalPKIXPublicKey(k.priv.Public())
		if err != nil {
			fail(w, http.StatusInternalServerError, "marshal public key")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"pem": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	case r.Method == http.MethodPost && tail == ":asymmetricSign":
		s.sign(w, r, k)
	case r.Method == http.MethodPost && tail == ":destroy":
		k.destroyed = true
		_ = json.NewEncoder(w).Encode(map[string]string{"state": "DESTROY_SCHEDULED"})
	default:
		fail(w, http.StatusNotFound, "no route")
	}
}

func (s *server) create(w http.ResponseWriter, r *http.Request, path string) {
	var body struct {
		VersionTemplate struct {
			Algorithm string `json:"algorithm"`
		} `json:"versionTemplate"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "bad json")
		return
	}
	name := path + "/" + r.URL.Query().Get("cryptoKeyId")
	if r.URL.Query().Get("cryptoKeyId") == "" {
		fail(w, http.StatusBadRequest, "cryptoKeyId required")
		return
	}
	if _, dup := s.keys[name]; dup {
		fail(w, http.StatusConflict, "already exists")
		return
	}
	var priv crypto.Signer
	var err error
	switch body.VersionTemplate.Algorithm {
	case "EC_SIGN_P256_SHA256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "EC_SIGN_P384_SHA384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "RSA_SIGN_PKCS1_2048_SHA256":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case "RSA_SIGN_PKCS1_3072_SHA256":
		priv, err = rsa.GenerateKey(rand.Reader, 3072)
	default:
		fail(w, http.StatusBadRequest, "unsupported algorithm")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "keygen")
		return
	}
	s.keys[name] = &key{priv: priv}
	_ = json.NewEncoder(w).Encode(map[string]string{"name": name})
}

func (s *server) sign(w http.ResponseWriter, r *http.Request, k *key) {
	if k.destroyed {
		fail(w, http.StatusBadRequest, "key version destroyed")
		return
	}
	var in struct {
		Digest map[string]string `json:"digest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, "bad json")
		return
	}
	hashes := map[string]crypto.Hash{"sha256": crypto.SHA256, "sha384": crypto.SHA384, "sha512": crypto.SHA512}
	for field, h := range hashes {
		b64, ok := in.Digest[field]
		if !ok {
			continue
		}
		digest, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(digest) != h.Size() {
			fail(w, http.StatusBadRequest, "bad digest")
			return
		}
		var sig []byte
		switch pk := k.priv.(type) {
		case *ecdsa.PrivateKey:
			sig, err = ecdsa.SignASN1(rand.Reader, pk, digest)
		case *rsa.PrivateKey:
			sig, err = rsa.SignPKCS1v15(rand.Reader, pk, h, digest)
		}
		if err != nil {
			fail(w, http.StatusInternalServerError, "sign")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"signature": base64.StdEncoding.EncodeToString(sig)})
		return
	}
	fail(w, http.StatusBadRequest, "digest required")
}
