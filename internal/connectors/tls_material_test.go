package connectors

import (
	"strings"
	"testing"
)

func TestTLSMaterialEmpty(t *testing.T) {
	certs, pool, err := TLSMaterial("", "", "")
	if err != nil || certs != nil || pool != nil {
		t.Fatalf("got %v %v %v", certs, pool, err)
	}
}

func TestTLSMaterialErrorsDoNotEchoPEM(t *testing.T) {
	const secret = "TOPSECRETKEYMATERIAL"
	if _, _, err := TLSMaterial(secret, secret, ""); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("bad pair error = %v", err)
	}
	if _, _, err := TLSMaterial("", secret, ""); err == nil {
		t.Fatal("key without cert must fail")
	}
	if _, _, err := TLSMaterial("", "", secret); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("bad ca error = %v", err)
	}
}
