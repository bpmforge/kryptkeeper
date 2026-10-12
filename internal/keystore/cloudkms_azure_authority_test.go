package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestAzureAuthorityHost(t *testing.T) {
	for env, want := range map[string]string{
		"":                          "https://login.microsoftonline.com",
		"https://login.example.cn/": "https://login.example.cn",
		"http://127.0.0.1:9000":     "http://127.0.0.1:9000",
		"http://localhost:9000":     "http://localhost:9000",
	} {
		t.Setenv("AZURE_AUTHORITY_HOST", env)
		got, err := azureAuthorityHost()
		if err != nil || got != want {
			t.Errorf("env %q: got %q, %v; want %q", env, got, err, want)
		}
	}
	for _, env := range []string{"http://evil.example.com", "ftp://x", "not a url", "https://"} {
		t.Setenv("AZURE_AUTHORITY_HOST", env)
		if got, err := azureAuthorityHost(); err == nil {
			t.Errorf("env %q accepted as %q", env, got)
		}
	}
}

func TestAzureRawECDSAToASN1(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("m"))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	der, err := azureRawECDSAToASN1(raw, &key.PublicKey)
	if err != nil || !ecdsa.VerifyASN1(&key.PublicKey, digest[:], der) {
		t.Fatalf("converted signature does not verify: %v", err)
	}
	if _, err := azureRawECDSAToASN1(raw[:63], &key.PublicKey); err == nil {
		t.Fatal("short signature accepted")
	}
}
