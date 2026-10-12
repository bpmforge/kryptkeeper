// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package wstep

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// writeKeytab builds a throwaway keytab in-test (never a committed fixture)
// holding a random key for principal.
func writeKeytab(t *testing.T, principal string) string {
	t.Helper()
	pw := make([]byte, 24)
	if _, err := rand.Read(pw); err != nil {
		t.Fatal(err)
	}
	kt := keytab.New()
	if err := kt.AddEntry(principal, "CORP.EXAMPLE", hex.EncodeToString(pw), time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	b, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "hub.keytab")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestKerberosFromEnvFailsClosed(t *testing.T) {
	good := writeKeytab(t, "HTTP/hub.corp.example")
	garbage := filepath.Join(t.TempDir(), "garbage.keytab")
	if err := os.WriteFile(garbage, []byte("not a keytab"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, keytab, spn, want string }{
		{"nothing set", "", "", "must both be set"},
		{"no SPN", good, "", "must both be set"},
		{"no keytab", "", "HTTP/hub.corp.example", "must both be set"},
		{"missing file", filepath.Join(t.TempDir(), "absent"), "HTTP/hub.corp.example", "loading keytab"},
		{"garbage file", garbage, "HTTP/hub.corp.example", "loading keytab"},
		{"SPN not in keytab", good, "HTTP/other.corp.example", "no entry for"},
		{"SPN differs only in case", good, "http/HUB.corp.example", "no entry for"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvKeytabFile, tc.keytab)
			t.Setenv(EnvSPN, tc.spn)
			auth, err := KerberosFromEnv()
			if auth != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got auth=%v err=%v, want nil and %q", auth != nil, err, tc.want)
			}
			if EnabledFromEnv() {
				t.Fatal("EnabledFromEnv must agree with KerberosFromEnv")
			}
		})
	}
}

func TestKerberosFromEnvChallengesWithNegotiate(t *testing.T) {
	t.Setenv(EnvKeytabFile, writeKeytab(t, "HTTP/hub.corp.example"))
	t.Setenv(EnvSPN, "HTTP/hub.corp.example")
	auth, err := KerberosFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !EnabledFromEnv() {
		t.Fatal("EnabledFromEnv must agree with KerberosFromEnv")
	}
	reached := false
	h := auth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	for _, authz := range []string{"", "Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAKAGFKAAAADw==", "Basic YWxpY2U6aHVudGVyMg=="} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/wstep", nil)
		if authz != "" {
			r.Header.Set("Authorization", authz)
		}
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Negotiate") {
			t.Fatalf("Authorization %.12q: got %d %q, want 401 Negotiate", authz, w.Code, w.Header().Get("WWW-Authenticate"))
		}
	}
	if reached {
		t.Fatal("an unauthenticated request reached the handler")
	}
}
