// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cmp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// plainOpen treats the "sealed" value as the secret itself; the real sealing
// lives in bootstrap and is exercised by its handler tests.
func plainOpen(s string) ([]byte, error) { return []byte(s), nil }

func newCredStore(t *testing.T) *DBCredentialStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "cmp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st := NewDBCredentialStore(db, false, plainOpen)
	if err := st.EnsureSchema(); err != nil {
		t.Fatal(err)
	}
	return st
}

func mintPBM(t *testing.T, st *DBCredentialStore, kid, secret string, suffixes ...string) Credential {
	t.Helper()
	c := Credential{ID: "id-" + kid, Kind: KindPBM, Label: "t", SenderKID: kid, AllowedDNSSuffixes: suffixes, CreatedBy: "tester", CreatedAt: time.Now().UTC()}
	if err := st.CreatePBM(context.Background(), c, secret); err != nil {
		t.Fatal(err)
	}
	return c
}

func irTag(t *testing.T, h http.Handler, secret, kid string) (*httptest.ResponseRecorder, int) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	body := buildCRMFIRBody(t, priv, "cred-test")
	rr := postCMP(h, buildProtectedPKIMessage(t, PKIBodyIR, body, pbmOptions{secretForMAC: secret, kid: kid}))
	return rr, decodeResponse(t, rr.Body.Bytes()).Body.Tag
}

func credServer(t *testing.T, st CredentialStore) http.Handler {
	t.Helper()
	engine, caID := newCMPTestEngine(t)
	return newServerForTest(engine, caID).WithCredentials(st).Handler()
}

func TestMintedSecretAuthenticatesIR(t *testing.T) {
	st := newCredStore(t)
	mintPBM(t, st, "kk-cmp-aaaa", "minted-secret-1")
	h := credServer(t, st)
	rr, tag := irTag(t, h, "minted-secret-1", "kk-cmp-aaaa")
	if rr.Code != http.StatusOK || tag != PKIBodyIP {
		t.Fatalf("code %d tag %d, want 200 ip", rr.Code, tag)
	}
	// The response is protected with the minted secret and names its reference.
	msg := decodeResponse(t, rr.Body.Bytes())
	hdr, err := parseHeader(msg.Header)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPBMProtection(&hdr, msg.Protection, msg.Body.FullBytes, []byte("minted-secret-1")); err != nil {
		t.Fatalf("response not protected with the minted secret: %v", err)
	}
	if string(hdr.SenderKID) != "kk-cmp-aaaa" {
		t.Fatalf("response senderKID %q", hdr.SenderKID)
	}
}

func failText(t *testing.T, body []byte) (int, string) {
	t.Helper()
	_, bit := decodeFail(t, body)
	msg := decodeResponse(t, body)
	var content struct{ Info pkiStatusInfo }
	if _, err := asn1.Unmarshal(msg.Body.Bytes, &content); err != nil {
		t.Fatal(err)
	}
	var text string
	for _, s := range content.Info.StatusString {
		text += string(s.Bytes)
	}
	return bit, text
}

func TestRevokedSecretIsBadMessageCheck(t *testing.T) {
	st := newCredStore(t)
	c := mintPBM(t, st, "kk-cmp-bbbb", "secret-b")
	h := credServer(t, st)
	if _, tag := irTag(t, h, "secret-b", "kk-cmp-bbbb"); tag != PKIBodyIP {
		t.Fatalf("active secret: tag %d", tag)
	}
	if err := st.Revoke(context.Background(), c.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	revoked, tag := irTag(t, h, "secret-b", "kk-cmp-bbbb")
	if tag != PKIBodyError {
		t.Fatalf("revoked secret: tag %d, want error", tag)
	}
	bit, text := failText(t, revoked.Body.Bytes())
	if bit != failBadMessageCheck {
		t.Fatalf("failInfo bit %d, want badMessageCheck", bit)
	}
	// Indistinguishable from a wrong secret and from an unknown reference.
	for _, other := range []struct{ secret, kid string }{{"wrong", "kk-cmp-bbbb"}, {"secret-b", "kk-cmp-never"}} {
		rr, _ := irTag(t, h, other.secret, other.kid)
		obit, otext := failText(t, rr.Body.Bytes())
		if obit != bit || otext != text {
			t.Fatalf("revoked (%d %q) differs from %v (%d %q)", bit, text, other, obit, otext)
		}
	}
}

func TestRotateInvalidatesOldSecret(t *testing.T) {
	st := newCredStore(t)
	c := mintPBM(t, st, "kk-cmp-cccc", "old-secret")
	h := credServer(t, st)
	if _, tag := irTag(t, h, "old-secret", "kk-cmp-cccc"); tag != PKIBodyIP {
		t.Fatalf("old secret before rotate: tag %d", tag)
	}
	if err := st.Rotate(context.Background(), c.ID, "new-secret", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, tag := irTag(t, h, "old-secret", "kk-cmp-cccc"); tag != PKIBodyError {
		t.Fatalf("old secret after rotate: tag %d, want error", tag)
	}
	if _, tag := irTag(t, h, "new-secret", "kk-cmp-cccc"); tag != PKIBodyIP {
		t.Fatalf("new secret: tag %d, want ip", tag)
	}
	got, _ := st.Get(context.Background(), c.ID)
	if got.RotatedAt == nil {
		t.Fatal("rotated_at not set")
	}
}

func TestRevokeBeatsCacheOnSameNode(t *testing.T) {
	st := newCredStore(t)
	c := mintPBM(t, st, "kk-cmp-dddd", "secret-d")
	ctx := context.Background()
	if _, _, ok := st.LookupPBM(ctx, []byte("kk-cmp-dddd")); !ok {
		t.Fatal("first lookup missed")
	}
	// Remove the row's backing so only the cache could answer: a hit proves caching.
	st.mu.Lock()
	hit := len(st.cache)
	st.mu.Unlock()
	if hit != 1 {
		t.Fatalf("cache entries = %d, want 1", hit)
	}
	if err := st.Revoke(ctx, c.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := st.LookupPBM(ctx, []byte("kk-cmp-dddd")); ok {
		t.Fatal("revoked secret still answered from the cache")
	}
}

func TestCacheExpiresAfterTTL(t *testing.T) {
	st := newCredStore(t)
	mintPBM(t, st, "kk-cmp-eeee", "secret-e")
	ctx := context.Background()
	base := time.Now()
	st.now = func() time.Time { return base }
	if _, _, ok := st.LookupPBM(ctx, []byte("kk-cmp-eeee")); !ok {
		t.Fatal("miss")
	}
	// Another node revoked it directly in the database.
	if _, err := st.db.Exec(`UPDATE cmp_credentials SET revoked_at = ?`, credTime(base)); err != nil {
		t.Fatal(err)
	}
	st.now = func() time.Time { return base.Add(credCacheTTL - time.Second) }
	if _, _, ok := st.LookupPBM(ctx, []byte("kk-cmp-eeee")); !ok {
		t.Fatal("expected a cache hit inside the TTL")
	}
	st.now = func() time.Time { return base.Add(credCacheTTL + time.Second) }
	if _, _, ok := st.LookupPBM(ctx, []byte("kk-cmp-eeee")); ok {
		t.Fatal("secret revoked elsewhere still answered after the TTL")
	}
}

func TestEnvSecretStillWorks(t *testing.T) {
	st := newCredStore(t)
	mintPBM(t, st, "kk-cmp-ffff", "secret-f")
	h := credServer(t, st)
	if _, tag := irTag(t, h, testSecret, testReference); tag != PKIBodyIP {
		t.Fatalf("env secret beside a credential store: tag %d", tag)
	}
	// A stored secret presented under the env reference is not accepted.
	if _, tag := irTag(t, h, "secret-f", testReference); tag != PKIBodyError {
		t.Fatalf("stored secret under env reference: tag %d, want error", tag)
	}
}

func TestCredentialsOnlyModeRejectsUnknownKid(t *testing.T) {
	st := newCredStore(t)
	engine, caID := newCMPTestEngine(t)
	h := NewServer(engine, caID, "", "").WithCredentials(st).Handler()
	// An empty secret must never authenticate.
	if _, tag := irTag(t, h, "", ""); tag != PKIBodyError {
		t.Fatalf("empty secret accepted: tag %d", tag)
	}
	mintPBM(t, st, "kk-cmp-gggg", "secret-g")
	if _, tag := irTag(t, h, "secret-g", "kk-cmp-gggg"); tag != PKIBodyIP {
		t.Fatalf("credentials-only server rejected a minted secret: tag %d", tag)
	}
}

func TestPerCredentialSuffixesOverrideGlobal(t *testing.T) {
	st := newCredStore(t)
	mintPBM(t, st, "kk-cmp-hhhh", "secret-h", ".corp.example")
	mintPBM(t, st, "kk-cmp-iiii", "secret-i") // no list: inherits the global binding
	engine, caID := newCMPTestEngine(t)
	h := newServerForTest(engine, caID).WithCredentials(st).WithAllowedDNSSuffixes([]string{".global.example"}).Handler()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	build := func(secret, kid, name string) int {
		body := buildCRMFBodySANs(t, &priv.PublicKey, oidECDSAWithSHA256,
			func(d []byte) ([]byte, error) { return ecdsa.SignASN1(rand.Reader, priv, d) }, name, []string{name})
		return bodyTag(t, postCMP(h, buildProtectedPKIMessage(t, PKIBodyIR, body, pbmOptions{secretForMAC: secret, kid: kid})))
	}
	if got := build("secret-h", "kk-cmp-hhhh", "a.corp.example"); got != PKIBodyIP {
		t.Fatalf("own zone: tag %d", got)
	}
	if got := build("secret-h", "kk-cmp-hhhh", "a.global.example"); got != PKIBodyError {
		t.Fatalf("global zone under a per-credential list: tag %d, want error", got)
	}
	if got := build("secret-i", "kk-cmp-iiii", "a.global.example"); got != PKIBodyIP {
		t.Fatalf("inherited global zone: tag %d", got)
	}
	if got := build("secret-i", "kk-cmp-iiii", "a.corp.example"); got != PKIBodyError {
		t.Fatalf("outside the inherited zone: tag %d, want error", got)
	}
}

func selfSigned(t *testing.T, notAfter time.Time) string {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "anchor " + serial.String()},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAnchorRegister(t *testing.T) {
	st := newCredStore(t)
	ctx := context.Background()
	now := time.Now()
	good := selfSigned(t, now.Add(24*time.Hour))
	cert, sum, err := ParseAnchorPEM(good, now)
	if err != nil || cert == nil || len(sum) != 64 {
		t.Fatalf("valid anchor: %v %q", err, sum)
	}
	for name, in := range map[string]string{
		"garbage":    "not a pem",
		"expired":    selfSigned(t, now.Add(-time.Hour)),
		"two certs":  good + selfSigned(t, now.Add(time.Hour)),
		"wrong type": strings.ReplaceAll(good, "CERTIFICATE", "PRIVATE KEY"),
	} {
		if _, _, err := ParseAnchorPEM(in, now); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	c := Credential{ID: "a1", Kind: KindTrustAnchor, Label: "root", CertSHA256: sum, CreatedBy: "tester", CreatedAt: now.UTC()}
	if err := st.RegisterAnchor(ctx, c, good); err != nil {
		t.Fatal(err)
	}
	c.ID = "a2"
	if err := st.RegisterAnchor(ctx, c, good); !errors.Is(err, ErrDuplicateAnchor) {
		t.Fatalf("duplicate: %v, want ErrDuplicateAnchor", err)
	}
	anchors, err := st.TrustAnchors(ctx)
	if err != nil || len(anchors) != 1 {
		t.Fatalf("anchors %d err %v", len(anchors), err)
	}
	// Revoking frees the fingerprint and drops it from TrustAnchors.
	if err := st.Revoke(ctx, "a1", now); err != nil {
		t.Fatal(err)
	}
	if anchors, _ = st.TrustAnchors(ctx); len(anchors) != 0 {
		t.Fatalf("revoked anchor still active")
	}
	if err := st.RegisterAnchor(ctx, c, good); err != nil {
		t.Fatalf("re-register after revoke: %v", err)
	}
	if err := st.Rotate(ctx, "a2", "x", now); !errors.Is(err, ErrNotPBM) {
		t.Fatalf("rotate anchor: %v, want ErrNotPBM", err)
	}
	if err := st.Revoke(ctx, "a1", now); !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("second revoke: %v", err)
	}
	if err := st.Revoke(ctx, "nope", now); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("unknown revoke: %v", err)
	}
}

func TestListHasNoSecretMaterial(t *testing.T) {
	st := newCredStore(t)
	mintPBM(t, st, "kk-cmp-jjjj", "SECRET-MARKER-j")
	pemText := selfSigned(t, time.Now().Add(time.Hour))
	_, sum, _ := ParseAnchorPEM(pemText, time.Now())
	if err := st.RegisterAnchor(context.Background(), Credential{ID: "a", Kind: KindTrustAnchor, CertSHA256: sum, CreatedBy: "t", CreatedAt: time.Now()}, pemText); err != nil {
		t.Fatal(err)
	}
	list, err := st.List(context.Background())
	if err != nil || len(list) != 2 {
		t.Fatalf("list %d %v", len(list), err)
	}
	dump := strings.ToLower(strings.Join([]string{list[0].Label, list[0].SenderKID, list[0].CertSHA256, list[1].Label, list[1].SenderKID, list[1].CertSHA256}, " "))
	if strings.Contains(dump, "secret-marker") || strings.Contains(dump, "begin certificate") {
		t.Fatal("list leaks secret or PEM material")
	}
}

func TestLookupTouchesLastUsed(t *testing.T) {
	st := newCredStore(t)
	c := mintPBM(t, st, "kk-cmp-kkkk", "secret-k")
	if got, _ := st.Get(context.Background(), c.ID); got.LastUsedAt != nil {
		t.Fatal("last_used_at set before any use")
	}
	if _, _, ok := st.LookupPBM(context.Background(), []byte("kk-cmp-kkkk")); !ok {
		t.Fatal("miss")
	}
	if got, _ := st.Get(context.Background(), c.ID); got.LastUsedAt == nil {
		t.Fatal("last_used_at not set by lookup")
	}
}
