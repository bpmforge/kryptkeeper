// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const fakeVaultToken = "t-fake-token"

// fakeVault is an in-process Vault transit engine for /v1/transit. It makes
// real keys and real signatures. Ed25519 mirrors OSS Vault: raw-message
// signing only, prehashed input is rejected.
type fakeVault struct {
	mu        sync.Mutex
	keys      map[string]crypto.Signer   // latest version
	older     map[string][]crypto.Signer // versions 1..n-1, oldest first
	types     map[string]string
	delOK     map[string]bool // deletion_allowed, as on real Vault (default false)
	namespace string          // last X-Vault-Namespace seen
	signCode  int             // non-zero: sign answers with this status
	signCalls int
}

func newFakeVaultStore(t *testing.T) (*VaultStore, *fakeVault) {
	t.Helper()
	f := &fakeVault{keys: map[string]crypto.Signer{}, older: map[string][]crypto.Signer{}, types: map[string]string{}, delOK: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return &VaultStore{addr: srv.URL, token: fakeVaultToken, mount: "transit", httpClient: srv.Client()}, f
}

// vaultConformanceStore returns a VaultStore wired to a fresh fake.
func vaultConformanceStore(t *testing.T) Store {
	s, _ := newFakeVaultStore(t)
	return s
}

func (f *fakeVault) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("X-Vault-Token") != fakeVaultToken {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		return
	}
	f.namespace = r.Header.Get("X-Vault-Namespace")
	const keys = "/v1/transit/keys"
	path := r.URL.Path
	reply := func(data any) { _ = json.NewEncoder(w).Encode(map[string]any{"data": data}) }

	switch {
	case r.Method == "LIST" && path == keys:
		names := make([]string, 0, len(f.keys))
		for n := range f.keys {
			names = append(names, n)
		}
		if len(names) == 0 {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		sort.Strings(names)
		reply(map[string]any{"keys": names})
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/rotate") && strings.HasPrefix(path, keys+"/"):
		name := strings.TrimSuffix(strings.TrimPrefix(path, keys+"/"), "/rotate")
		old, ok := f.keys[name]
		if !ok {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		k, err := genFakeVaultKey(f.types[name])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		f.older[name] = append(f.older[name], old)
		f.keys[name] = k
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/config") && strings.HasPrefix(path, keys+"/"):
		name := strings.TrimSuffix(strings.TrimPrefix(path, keys+"/"), "/config")
		var in struct {
			DeletionAllowed bool `json:"deletion_allowed"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if _, ok := f.keys[name]; !ok {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		f.delOK[name] = in.DeletionAllowed
		reply(map[string]any{})
	case strings.HasPrefix(path, keys+"/"):
		name := strings.TrimPrefix(path, keys+"/")
		switch r.Method {
		case http.MethodPost:
			// Real transit key creation is idempotent: an existing name answers
			// 204 and keeps the old key (no "already exists" error).
			if _, dup := f.keys[name]; dup {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			var in struct {
				Type       string `json:"type"`
				Exportable bool   `json:"exportable"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in.Exportable {
				http.Error(w, `{"errors":["keys must not be exportable"]}`, http.StatusBadRequest)
				return
			}
			k, err := genFakeVaultKey(in.Type)
			if errors.Is(err, errFakeVaultType) {
				http.Error(w, `{"errors":["unsupported key type"]}`, http.StatusBadRequest)
				return
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			f.keys[name], f.types[name] = k, in.Type
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			k, ok := f.keys[name]
			if !ok {
				http.Error(w, `{"errors":[]}`, http.StatusNotFound)
				return
			}
			versions := map[string]any{}
			all := append(append([]crypto.Signer{}, f.older[name]...), k)
			for i, vk := range all {
				versions[strconv.Itoa(i+1)] = map[string]string{"public_key": fakeVaultPublicKey(vk)}
			}
			reply(map[string]any{
				"type":           f.types[name],
				"creation_time":  "2026-10-15T00:00:00Z",
				"latest_version": len(all),
				"keys":           versions,
			})
		case http.MethodDelete:
			if _, ok := f.keys[name]; !ok {
				http.Error(w, `{"errors":[]}`, http.StatusNotFound)
				return
			}
			if !f.delOK[name] {
				http.Error(w, `{"errors":["deletion is not allowed for this key"]}`, http.StatusBadRequest)
				return
			}
			delete(f.keys, name)
			delete(f.older, name)
			delete(f.types, name)
			delete(f.delOK, name)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "no route", http.StatusMethodNotAllowed)
		}
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/v1/transit/sign/"):
		f.signCalls++
		if f.signCode != 0 {
			http.Error(w, `{"errors":["injected"]}`, f.signCode)
			return
		}
		k, ok := f.keys[strings.TrimPrefix(path, "/v1/transit/sign/")]
		if !ok {
			http.Error(w, `{"errors":["no such key"]}`, http.StatusNotFound)
			return
		}
		var in struct {
			Input     string `json:"input"`
			Prehashed bool   `json:"prehashed"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		input, err := base64.StdEncoding.DecodeString(in.Input)
		if err != nil {
			http.Error(w, `{"errors":["bad input"]}`, http.StatusBadRequest)
			return
		}
		var sig []byte
		switch pk := k.(type) {
		case *ecdsa.PrivateKey:
			if !in.Prehashed {
				http.Error(w, `{"errors":["fake only signs prehashed ecdsa"]}`, http.StatusBadRequest)
				return
			}
			sig, err = ecdsa.SignASN1(rand.Reader, pk, input)
		case *rsa.PrivateKey:
			if !in.Prehashed {
				http.Error(w, `{"errors":["fake only signs prehashed rsa"]}`, http.StatusBadRequest)
				return
			}
			sig, err = rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, input)
		case ed25519.PrivateKey:
			if in.Prehashed {
				http.Error(w, `{"errors":["prehashed is not supported for ed25519"]}`, http.StatusBadRequest)
				return
			}
			sig = ed25519.Sign(pk, input)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		reply(map[string]string{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig)})
	default:
		http.Error(w, "no route", http.StatusNotFound)
	}
}

var errFakeVaultType = errors.New("unsupported fake vault key type")

func genFakeVaultKey(typ string) (crypto.Signer, error) {
	switch typ {
	case "ecdsa-p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-3072":
		return rsa.GenerateKey(rand.Reader, 3072)
	case "ed25519":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	}
	return nil, errFakeVaultType
}

// fakeVaultPublicKey mirrors real transit: PEM for ECDSA/RSA, base64 of the
// raw 32 bytes for Ed25519 (verified against Vault 1.17).
func fakeVaultPublicKey(k crypto.Signer) string {
	if ek, ok := k.Public().(ed25519.PublicKey); ok {
		return base64.StdEncoding.EncodeToString(ek)
	}
	der, _ := x509.MarshalPKIXPublicKey(k.Public())
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestVault_CreateSignVerifyDelete(t *testing.T) {
	store, fake := newFakeVaultStore(t)
	if _, err := store.GenerateKey("vault-ca-key", ECDSAP256); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := store.PublicKey("vault-ca-key")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := store.Signer("vault-ca-key")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("vault transit sign"))
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("transit signature did not verify against the key's public key")
	}
	if fake.signCalls != 1 {
		t.Fatalf("sign calls = %d, want 1", fake.signCalls)
	}
	if err := store.Delete("vault-ca-key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Metadata("vault-ca-key"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Metadata after Delete = %v, want ErrKeyNotFound", err)
	}
}

func TestVault_DuplicateKeyIsErrKeyExists(t *testing.T) {
	store, _ := newFakeVaultStore(t)
	if _, err := store.GenerateKey("dup", ECDSAP256); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GenerateKey("dup", ECDSAP256); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("duplicate = %v, want ErrKeyExists", err)
	}
}

func TestVault_SignHTTPErrorIsError(t *testing.T) {
	store, fake := newFakeVaultStore(t)
	if _, err := store.GenerateKey("sign-err", ECDSAP256); err != nil {
		t.Fatal(err)
	}
	signer, _ := store.Signer("sign-err")
	fake.signCode = http.StatusInternalServerError
	digest := sha256.Sum256([]byte("x"))
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") || len(sig) != 0 {
		t.Fatalf("Sign = %x, %v; want an HTTP 500 error and no signature", sig, err)
	}
}

func TestVault_MissingKeyIsErrKeyNotFound(t *testing.T) {
	store, _ := newFakeVaultStore(t)
	if _, err := store.Signer("nope"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Signer = %v", err)
	}
	if _, err := store.Metadata("nope"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Metadata = %v", err)
	}
	if err := store.Delete("nope"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Delete = %v", err)
	}
	if got, err := store.List(); err != nil || len(got) != 0 {
		t.Fatalf("List on empty mount = %v, %v", got, err)
	}
}

func TestVault_SendsTokenAndNamespaceHeaders(t *testing.T) {
	store, fake := newFakeVaultStore(t)
	store.namespace = "team-a"
	if _, err := store.GenerateKey("hdr", ECDSAP256); err != nil {
		t.Fatalf("token header not sent: %v", err)
	}
	if fake.namespace != "team-a" {
		t.Fatalf("X-Vault-Namespace = %q, want team-a", fake.namespace)
	}
	store.token = "wrong"
	if _, err := store.GenerateKey("hdr2", ECDSAP256); err == nil {
		t.Fatal("a wrong token must fail")
	}
}

// The fake refuses exportable keys, so every create here also proves keys are
// requested non-exportable; transit has no ML-DSA, which must be a typed refusal.
func TestVault_RefusesUnsupportedAlgorithm(t *testing.T) {
	store, _ := newFakeVaultStore(t)
	if _, err := store.GenerateKey("pq", MLDSA65); !errors.Is(err, ErrUnsupportedAlgo) {
		t.Fatalf("ML-DSA on transit = %v, want ErrUnsupportedAlgo", err)
	}
}

// Regression: Ed25519 signing sent prehashed:true, which transit rejects for
// Ed25519, so a Vault-held Ed25519 CA could never sign.
func TestVault_Ed25519SignsRawMessage(t *testing.T) {
	store, _ := newFakeVaultStore(t)
	if _, err := store.GenerateKey("ed", Ed25519); err != nil {
		t.Fatal(err)
	}
	pub, _ := store.PublicKey("ed")
	signer, _ := store.Signer("ed")
	msg := []byte("vault ed25519 message")
	sig, err := signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(pub.(ed25519.PublicKey), msg, sig) {
		t.Fatal("Ed25519 signature did not verify")
	}
}

// Vault returns key versions as a JSON object; Go map iteration is random, so
// "latest" must be chosen numerically (not by range order, not lexically: 10 < 9
// as strings). Repeat to make a random pick fail with near certainty.
func TestVault_PublicKeyIsLatestVersion(t *testing.T) {
	for _, algo := range []Algorithm{ECDSAP256, Ed25519} {
		t.Run(string(algo), func(t *testing.T) {
			store, fake := newFakeVaultStore(t)
			if _, err := store.GenerateKey("rot", algo); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 10; i++ { // reaches version 11 so "9" > "11" lexically
				if _, err := store.RotateKey("rot", algo); err != nil {
					t.Fatal(err)
				}
			}
			want := fake.keys["rot"].Public()
			for i := 0; i < 40; i++ {
				got, err := store.PublicKey("rot")
				if err != nil {
					t.Fatal(err)
				}
				if !publicKeysEqual(got, want) {
					t.Fatalf("iteration %d: PublicKey is not the latest version", i)
				}
			}
		})
	}
}

func TestVault_PublicKeyRejectsMalformed(t *testing.T) {
	for name, pk := range map[string]string{
		"not pem or base64": "!!!",
		"short raw key":     base64.StdEncoding.EncodeToString([]byte("too short")),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseVaultPublicKey(pk); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestConformance_Vault(t *testing.T) {
	runStoreConformance(t, vaultConformanceStore)
}
