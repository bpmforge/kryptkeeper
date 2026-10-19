// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// conformanceAlgos is every algorithm the suite probes. A backend either
// round-trips it or must refuse it with ErrUnsupportedAlgo and create nothing.
var conformanceAlgos = []Algorithm{ECDSAP256, RSA2048, RSA3072, Ed25519}

type conformanceConfig struct {
	unsupported map[Algorithm]bool
	// doubleHash: the emulator hashes the digest a second time (moto KMS), so
	// signatures verify over sha256(digest). Proves wiring only.
	doubleHash bool
}

type conformanceOpt func(*conformanceConfig)

// withUnsupported declares the algorithms a backend must refuse.
func withUnsupported(algos ...Algorithm) conformanceOpt {
	return func(c *conformanceConfig) {
		for _, a := range algos {
			c.unsupported[a] = true
		}
	}
}

func withDoubleHash() conformanceOpt { return func(c *conformanceConfig) { c.doubleHash = true } }

var conformanceSeq atomic.Int64

// confKeyID is unique per process run so persistent emulators never collide.
func confKeyID(algo Algorithm) string {
	return fmt.Sprintf("conf-%s-%d-%d", strings.ToLower(string(algo)), time.Now().UnixNano()%1_000_000_000, conformanceSeq.Add(1))
}

// runStoreConformance is the shared Store contract every backend must satisfy.
func runStoreConformance(t *testing.T, newStore func(t *testing.T) Store, opts ...conformanceOpt) {
	t.Helper()
	cfg := &conformanceConfig{unsupported: map[Algorithm]bool{}}
	for _, o := range opts {
		o(cfg)
	}
	for _, algo := range conformanceAlgos {
		t.Run(string(algo), func(t *testing.T) {
			store := newStore(t)
			id := confKeyID(algo)

			if cfg.unsupported[algo] {
				_, err := store.GenerateKey(id, algo)
				if !errors.Is(err, ErrUnsupportedAlgo) {
					t.Fatalf("GenerateKey(%s) = %v, want ErrUnsupportedAlgo refusal", algo, err)
				}
				if _, err := store.Metadata(id); !errors.Is(err, ErrKeyNotFound) {
					t.Fatalf("refused %s left a key behind: Metadata err = %v", algo, err)
				}
				return
			}

			meta, err := store.GenerateKey(id, algo)
			if errors.Is(err, ErrUnsupportedAlgo) {
				t.Fatalf("backend refused %s but the suite lists it as supported: %v", algo, err)
			}
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if meta.ID != id || meta.Algorithm != algo {
				t.Fatalf("meta = %+v, want id %q algo %q", meta, id, algo)
			}
			if _, err := store.GenerateKey(id, algo); !errors.Is(err, ErrKeyExists) {
				t.Fatalf("duplicate GenerateKey = %v, want ErrKeyExists", err)
			}

			pub, err := store.PublicKey(id)
			if err != nil || pub == nil {
				t.Fatalf("PublicKey = %v, %v", pub, err)
			}
			if rk, ok := pub.(*rsa.PublicKey); ok {
				want := map[Algorithm]int{RSA2048: 2048, RSA3072: 3072}[algo]
				if want != 0 && rk.N.BitLen() != want {
					t.Fatalf("RSA modulus = %d bits, want %d", rk.N.BitLen(), want)
				}
			}

			signer, err := store.Signer(id)
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			conformanceSignVerify(t, signer, pub, cfg.doubleHash)

			if got, err := store.Metadata(id); err != nil || got.ID != id {
				t.Fatalf("Metadata = %+v, %v", got, err)
			}
			list, err := store.List()
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			found := false
			for _, m := range list {
				found = found || m.ID == id
			}
			if !found {
				t.Fatalf("List does not contain %q", id)
			}

			if _, err := store.Signer("conf-missing-" + id); !errors.Is(err, ErrKeyNotFound) {
				t.Fatalf("Signer(missing) = %v, want ErrKeyNotFound", err)
			}
			if err := store.Delete(id); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, err := store.Metadata(id); !errors.Is(err, ErrKeyNotFound) {
				t.Fatalf("Metadata after Delete = %v, want ErrKeyNotFound", err)
			}
			if err := store.Delete("conf-missing-" + id); !errors.Is(err, ErrKeyNotFound) {
				t.Fatalf("Delete(missing) = %v, want ErrKeyNotFound", err)
			}
		})
	}
}

func conformanceSignVerify(t *testing.T, signer crypto.Signer, pub crypto.PublicKey, doubleHash bool) {
	t.Helper()
	msg := []byte("kryptkeeper conformance message")
	digest := sha256.Sum256(msg)
	switch pk := pub.(type) {
	case ed25519.PublicKey:
		sig, err := signer.Sign(nil, msg, crypto.Hash(0))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if !ed25519.Verify(pk, msg, sig) {
			t.Fatal("Ed25519 signature did not verify")
		}
		if ed25519.Verify(pk, append([]byte("x"), msg...), sig) {
			t.Fatal("Ed25519 signature verified over a different message")
		}
	case *ecdsa.PublicKey:
		sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		v := digest[:]
		if doubleHash {
			h := sha256.Sum256(v)
			v = h[:]
		}
		if !ecdsa.VerifyASN1(pk, v, sig) {
			t.Fatal("ECDSA signature did not verify")
		}
		bad := append([]byte(nil), v...)
		bad[0] ^= 1
		if ecdsa.VerifyASN1(pk, bad, sig) {
			t.Fatal("ECDSA signature verified over a different digest")
		}
	case *rsa.PublicKey:
		sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		v := digest[:]
		if doubleHash {
			h := sha256.Sum256(v)
			v = h[:]
		}
		if err := rsa.VerifyPKCS1v15(pk, crypto.SHA256, v, sig); err != nil {
			t.Fatalf("RSA signature did not verify: %v", err)
		}
		bad := append([]byte(nil), v...)
		bad[0] ^= 1
		if rsa.VerifyPKCS1v15(pk, crypto.SHA256, bad, sig) == nil {
			t.Fatal("RSA signature verified over a different digest")
		}
	default:
		t.Fatalf("unexpected public key type %T", pub)
	}
}

func TestConformance_Software(t *testing.T) {
	runStoreConformance(t, func(t *testing.T) Store {
		s, err := NewSoftwareStore(t.TempDir(), []byte("conformance-passphrase-32bytes!!"))
		if err != nil {
			t.Fatalf("NewSoftwareStore: %v", err)
		}
		return s
	})
}

// AWS KMS has no Ed25519 signing key spec in this backend. Skips (naming
// AWS_ENDPOINT_URL) unless an emulator is configured.
func TestConformance_AWS(t *testing.T) {
	opts := []conformanceOpt{withUnsupported(Ed25519)}
	if os.Getenv("KK_KMS_EMULATOR_MOTO") == "1" {
		opts = append(opts, withDoubleHash())
	}
	runStoreConformance(t, awsConformanceStore, opts...)
}

// Azure runs only against the Lowkey Vault emulator (tests/live/kms-azure/run.sh
// env); it refuses to touch a real vault.
func TestConformance_Azure(t *testing.T) {
	runStoreConformance(t, func(t *testing.T) Store {
		if os.Getenv("KK_LIVE_KMS_AZURE") != "1" {
			t.Skip("KK_LIVE_KMS_AZURE not set — skipping Azure (Lowkey Vault) conformance")
		}
		if !strings.HasPrefix(os.Getenv("AZURE_KEYVAULT_URL"), "https://localhost") {
			t.Fatal("AZURE_KEYVAULT_URL must be the local emulator; refusing to touch a real vault")
		}
		s, err := NewCloudKMSStore("azure")
		if err != nil {
			t.Fatalf("NewCloudKMSStore: %v", err)
		}
		return s
	}, withUnsupported(Ed25519))
}

// Offline: backends that cannot make a key type say so with the typed error,
// before any network call.
func TestUnsupportedAlgorithmIsTypedRefusal(t *testing.T) {
	_, awsErr := awsKeySpec(Ed25519)
	_, gcpErr := gcpKeyAlgorithm(Ed25519)
	_, _, _, azErr := azureKeyParams(Ed25519)
	for name, err := range map[string]error{"aws": awsErr, "gcp": gcpErr, "azure": azErr} {
		if !errors.Is(err, ErrUnsupportedAlgo) {
			t.Errorf("%s Ed25519 refusal = %v, want ErrUnsupportedAlgo", name, err)
		}
	}
	for _, algo := range []Algorithm{RSA3072} {
		if _, err := awsKeySpec(algo); err != nil {
			t.Errorf("aws %s: %v", algo, err)
		}
		if _, err := gcpKeyAlgorithm(algo); err != nil {
			t.Errorf("gcp %s: %v", algo, err)
		}
		if _, _, _, err := azureKeyParams(algo); err != nil {
			t.Errorf("azure %s: %v", algo, err)
		}
	}
}

// --- sign-path no-export assertion -----------------------------------------

// exportIdentifiers are calls that would read or export private key material.
var exportIdentifiers = []string{"GetAttributeValue", "ExportEncryptedKey", "ExportKey", "GetKeyMaterial", "Decrypt", "ExportPrivate"}

// signBody returns the names (identifiers, selectors, string literals) used in
// the body of fn (method of recv when recv != "") in src. Parsed with go/ast so
// comments and unrelated functions never count.
func signBody(t *testing.T, filename string, src []byte, recv, fn string) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filename, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn || fd.Body == nil {
			continue
		}
		if recv != "" {
			if fd.Recv == nil || len(fd.Recv.List) == 0 {
				continue
			}
			rt := fd.Recv.List[0].Type
			if st, ok := rt.(*ast.StarExpr); ok {
				rt = st.X
			}
			if id, ok := rt.(*ast.Ident); !ok || id.Name != recv {
				continue
			}
		}
		names := map[string]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				names[x.Name] = true
			case *ast.BasicLit:
				if x.Kind == token.STRING {
					if s, err := strconv.Unquote(x.Value); err == nil {
						names[s] = true
					}
				}
			}
			return true
		})
		return names
	}
	t.Fatalf("%s: func %s.%s not found", filename, recv, fn)
	return nil
}

// exportViolations lists forbidden names present in a sign body, including
// string literals that embed one inside a URL/path.
func exportViolations(names map[string]bool) []string {
	var bad []string
	for n := range names {
		for _, f := range exportIdentifiers {
			if n == f || (len(n) > len(f) && strings.Contains(n, f) && strings.ContainsAny(n, "/:?")) {
				bad = append(bad, f)
			}
		}
	}
	return bad
}

func TestSignPathNeverExportsPrivateKey(t *testing.T) {
	cases := []struct {
		file, recv, fn string
		mustCall       string // the single signing call the path is expected to make
	}{
		// crypto11's FindKeyPair returns a crypto.Signer whose Sign runs C_Sign
		// in the token; the store itself must do nothing else with the key.
		{"pkcs11.go", "PKCS11Store", "Signer", "FindKeyPair"},
		{"cloudkms.go", "CloudKMSSigner", "Sign", "signAWS"},
		{"cloudkms.go", "CloudKMSSigner", "Sign", "signGCP"},
		{"cloudkms.go", "CloudKMSSigner", "Sign", "signAzure"},
		{"cloudkms_aws.go", "CloudKMSSigner", "signAWS", "Sign"},
		{"cloudkms_gcp.go", "CloudKMSSigner", "signGCP", ":asymmetricSign"},
		{"cloudkms_azure.go", "CloudKMSSigner", "signAzure", "/sign?api-version=%s"},
	}
	for _, c := range cases {
		t.Run(c.file+"/"+c.fn+"/"+c.mustCall, func(t *testing.T) {
			src, err := os.ReadFile(c.file)
			if err != nil {
				t.Fatal(err)
			}
			names := signBody(t, c.file, src, c.recv, c.fn)
			if bad := exportViolations(names); len(bad) > 0 {
				t.Fatalf("%s.%s touches private-key export APIs: %v", c.recv, c.fn, bad)
			}
			found := false
			for n := range names {
				found = found || n == c.mustCall || strings.HasSuffix(n, c.mustCall)
			}
			if !found {
				t.Fatalf("%s.%s no longer makes its expected signing call %q", c.recv, c.fn, c.mustCall)
			}
		})
	}
}

// The scanner must be able to fail: feed it a body that exports key material.
func TestSignPathScannerFlagsExport(t *testing.T) {
	src := []byte(`package p
type S struct{}
func (s *S) Signer(id string) {
	ctx.GetAttributeValue(obj)
	s.keys.ExportEncryptedKey(id, nil)
}
`)
	bad := exportViolations(signBody(t, "synthetic.go", src, "S", "Signer"))
	if len(bad) != 2 {
		t.Fatalf("scanner flagged %v, want GetAttributeValue and ExportEncryptedKey", bad)
	}
	clean := []byte("package p\ntype S struct{}\nfunc (s *S) Signer() { x.Sign() } // GetAttributeValue only in a comment\n")
	if bad := exportViolations(signBody(t, "clean.go", clean, "S", "Signer")); len(bad) != 0 {
		t.Fatalf("comment tripped the scanner: %v", bad)
	}
}
