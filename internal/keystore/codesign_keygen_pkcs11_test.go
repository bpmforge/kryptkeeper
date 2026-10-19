// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build pkcs11

package keystore

import (
	"os"
	"testing"

	"github.com/miekg/pkcs11"
)

// TestProtectedKeyIsNonExtractable proves FR-P91: a key made through
// GenerateProtectedKey on a real token cannot be exported and the token
// itself reports CKA_EXTRACTABLE=false.
func TestProtectedKeyIsNonExtractable(t *testing.T) {
	pkcs11Token(t)
	store, err := NewPKCS11StoreFromEnv()
	if err != nil {
		t.Fatalf("NewPKCS11StoreFromEnv: %v", err)
	}
	const id = "codesign-nonextractable-test"
	if _, label, err := GenerateProtectedKey(store, id, ECDSAP256); err != nil || label != "pkcs11" {
		t.Fatalf("GenerateProtectedKey: label=%q err=%v", label, err)
	}
	t.Cleanup(func() { _ = store.Delete(id) })

	if _, err := store.ExportEncryptedKey(id, []byte("export-passphrase-0123456789abcd")); err == nil {
		t.Fatal("ExportEncryptedKey succeeded on a protected key")
	}

	p := pkcs11.New(os.Getenv("KRYPTKEEPER_PKCS11_LIB"))
	if p == nil {
		t.Fatal("cannot load PKCS#11 library")
	}
	if err := p.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	defer p.Finalize()
	slots, err := p.GetSlotList(true)
	if err != nil {
		t.Fatalf("GetSlotList: %v", err)
	}
	var found bool
	for _, slot := range slots {
		ti, err := p.GetTokenInfo(slot)
		if err != nil || ti.Label != os.Getenv("KRYPTKEEPER_PKCS11_TOKEN_LABEL") {
			continue
		}
		sess, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		defer p.CloseSession(sess)
		if err := p.Login(sess, pkcs11.CKU_USER, os.Getenv("KRYPTKEEPER_PKCS11_PIN")); err != nil {
			t.Fatalf("Login: %v", err)
		}
		tmpl := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, id),
		}
		if err := p.FindObjectsInit(sess, tmpl); err != nil {
			t.Fatalf("FindObjectsInit: %v", err)
		}
		objs, _, err := p.FindObjects(sess, 4)
		_ = p.FindObjectsFinal(sess)
		if err != nil || len(objs) == 0 {
			t.Fatalf("private key %q not found on token: %v", id, err)
		}
		for _, o := range objs {
			attrs, err := p.GetAttributeValue(sess, o, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil)})
			if err != nil {
				t.Fatalf("GetAttributeValue: %v", err)
			}
			if len(attrs) != 1 || len(attrs[0].Value) == 0 || attrs[0].Value[0] != 0 {
				t.Fatalf("CKA_EXTRACTABLE = %v, want false", attrs[0].Value)
			}
		}
		found = true
		break
	}
	if !found {
		t.Fatal("token not found by label")
	}
}
