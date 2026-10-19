// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const fakeGCPKeyRing = "projects/p/locations/global/keyRings/r"

type fakeGCPKey struct {
	priv      crypto.Signer
	destroyed bool
}

// fakeGCPKMS is an in-process Cloud KMS: it generates real keys and signs for
// real, so signatures can be verified against the public key the store holds.
// It is installed by transport, never by URL (gcpKMSBase is a const).
type fakeGCPKMS struct {
	mu        sync.Mutex
	keys      map[string]*fakeGCPKey // by key name suffix after cryptoKeys/
	destroyed []string
	signCode  int // non-zero: asymmetricSign answers with this status
	signCalls int
}

// installFakeGCPKMS swaps gcpHTTPClient for the fake and points the GCP env at
// it, restoring everything on cleanup. GOOGLE_ACCESS_TOKEN keeps the metadata
// server out of the picture.
func installFakeGCPKMS(t *testing.T) *fakeGCPKMS {
	t.Helper()
	f := &fakeGCPKMS{keys: map[string]*fakeGCPKey{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	prev := gcpHTTPClient
	gcpHTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		// Rewrite only the Cloud KMS host; anything else must fail loudly.
		if r.URL.Host != "cloudkms.googleapis.com" {
			t.Errorf("unexpected GCP request to %s", r.URL.Host)
		}
		u := *r.URL
		u.Scheme, u.Host = "http", strings.TrimPrefix(srv.URL, "http://")
		r2 := r.Clone(r.Context())
		r2.URL, r2.Host, r2.RequestURI = &u, u.Host, ""
		return http.DefaultTransport.RoundTrip(r2)
	})}
	t.Cleanup(func() { gcpHTTPClient = prev })
	t.Setenv("GOOGLE_ACCESS_TOKEN", "tok")
	t.Setenv("KRYPTKEEPER_GCP_PROJECT", "p")
	t.Setenv("KRYPTKEEPER_GCP_KEYRING", "r")
	t.Setenv(envGCPProtection, "software")
	return f
}

func (f *fakeGCPKMS) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer tok" {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}
	path := r.URL.Path
	base := "/v1/" + fakeGCPKeyRing + "/cryptoKeys"
	switch {
	case r.Method == http.MethodPost && path == base:
		id := r.URL.Query().Get("cryptoKeyId")
		var body struct {
			VersionTemplate struct {
				Algorithm string `json:"algorithm"`
			} `json:"versionTemplate"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if _, dup := f.keys[id]; dup {
			http.Error(w, `{"error":"already exists"}`, http.StatusConflict)
			return
		}
		var priv crypto.Signer
		var err error
		switch body.VersionTemplate.Algorithm {
		case "EC_SIGN_P256_SHA256":
			priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "RSA_SIGN_PKCS1_2048_SHA256":
			priv, err = rsa.GenerateKey(rand.Reader, 2048)
		case "RSA_SIGN_PKCS1_3072_SHA256":
			priv, err = rsa.GenerateKey(rand.Reader, 3072)
		default:
			http.Error(w, `{"error":"unsupported fake algorithm"}`, http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		f.keys[id] = &fakeGCPKey{priv: priv}
		_ = json.NewEncoder(w).Encode(map[string]string{"name": fakeGCPKeyRing + "/cryptoKeys/" + id})
	case strings.HasPrefix(path, base+"/"):
		rest := strings.TrimPrefix(path, base+"/")
		id, tail, _ := strings.Cut(rest, "/cryptoKeyVersions/1")
		k, ok := f.keys[id]
		if !ok {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		switch {
		case r.Method == http.MethodGet && tail == "/publicKey":
			der, _ := x509.MarshalPKIXPublicKey(k.priv.Public())
			_ = json.NewEncoder(w).Encode(map[string]string{"pem": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
		case r.Method == http.MethodPost && tail == ":asymmetricSign":
			f.signCalls++
			if f.signCode != 0 {
				http.Error(w, `{"error":"injected"}`, f.signCode)
				return
			}
			if k.destroyed {
				http.Error(w, `{"error":"version destroyed"}`, http.StatusBadRequest)
				return
			}
			var in struct {
				Digest struct {
					SHA256 string `json:"sha256"`
				} `json:"digest"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			digest, err := base64.StdEncoding.DecodeString(in.Digest.SHA256)
			if err != nil || len(digest) != sha256.Size {
				http.Error(w, `{"error":"bad digest"}`, http.StatusBadRequest)
				return
			}
			var sig []byte
			switch pk := k.priv.(type) {
			case *ecdsa.PrivateKey:
				sig, err = ecdsa.SignASN1(rand.Reader, pk, digest)
			case *rsa.PrivateKey:
				sig, err = rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, digest)
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"signature": base64.StdEncoding.EncodeToString(sig)})
		case r.Method == http.MethodPost && tail == ":destroy":
			k.destroyed = true
			f.destroyed = append(f.destroyed, id)
			_, _ = io.WriteString(w, "{}")
		default:
			http.Error(w, `{"error":"no route"}`, http.StatusNotFound)
		}
	default:
		http.Error(w, `{"error":"no route"}`, http.StatusNotFound)
	}
}

// gcpConformanceStore returns a CloudKMSStore wired to a fresh fake.
func gcpConformanceStore(t *testing.T) Store {
	t.Helper()
	installFakeGCPKMS(t)
	s, err := NewCloudKMSStore("gcp")
	if err != nil {
		t.Fatalf("NewCloudKMSStore: %v", err)
	}
	return s
}

func TestGCPKMS_CreateSignVerifyDelete(t *testing.T) {
	fake := installFakeGCPKMS(t)
	store, err := NewCloudKMSStore("gcp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GenerateKey("gcp-ca-key", ECDSAP256); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := store.PublicKey("gcp-ca-key")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := store.Signer("gcp-ca-key")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("gcp kms sign"))
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("signature from the KMS did not verify against the stored public key")
	}
	// The fake answered the sign over the wire; the private key never reached us.
	if fake.signCalls != 1 {
		t.Fatalf("asymmetricSign calls = %d, want 1", fake.signCalls)
	}

	if err := store.Delete("gcp-ca-key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(fake.destroyed) != 1 || fake.destroyed[0] != "gcp-ca-key" {
		t.Fatalf("provider :destroy calls = %v, want [gcp-ca-key]", fake.destroyed)
	}
	if _, err := store.Metadata("gcp-ca-key"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Metadata after Delete = %v, want ErrKeyNotFound", err)
	}
}

func TestGCPKMS_SignPropagatesHTTPError(t *testing.T) {
	fake := installFakeGCPKMS(t)
	store, _ := NewCloudKMSStore("gcp")
	if _, err := store.GenerateKey("gcp-err-key", ECDSAP256); err != nil {
		t.Fatal(err)
	}
	signer, _ := store.Signer("gcp-err-key")
	fake.signCode = http.StatusServiceUnavailable
	digest := sha256.Sum256([]byte("x"))
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err == nil || !strings.Contains(err.Error(), "asymmetricSign returned 503") {
		t.Fatalf("Sign = %x, %v; want an asymmetricSign 503 error", sig, err)
	}
	if len(sig) != 0 {
		t.Fatal("a failed sign must not return a signature")
	}
}

// Regression: destroyGCPKey used a private http.Client, so destruction
// bypassed the transport every other GCP call goes through. With the fake
// installed an un-routed destroy would have dialled the real Cloud KMS.
func TestGCPKMS_DestroyUsesSharedHTTPClient(t *testing.T) {
	fake := installFakeGCPKMS(t)
	store, _ := NewCloudKMSStore("gcp")
	if _, err := store.GenerateKey("gcp-destroy-key", RSA2048); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete("gcp-destroy-key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(fake.destroyed) != 1 {
		t.Fatalf("destroy never reached the shared GCP client: %v", fake.destroyed)
	}
}

func TestConformance_GCP(t *testing.T) {
	runStoreConformance(t, gcpConformanceStore, withUnsupported(Ed25519))
}
