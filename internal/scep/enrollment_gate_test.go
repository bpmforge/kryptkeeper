// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scep

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"kryptkeeper/internal/ca"
)

func (f *scepFixture) enrollOnce(t *testing.T, cn, challenge string) certRepResult {
	t.Helper()
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	clientCert := selfSignedRSACert(t, clientKey, cn)
	csrDER := buildCSRWithChallenge(t, clientKey, cn, challenge)
	msgDER, _, _ := buildPKIOperation(t, f.caObj.Certificate, clientKey, clientCert, csrDER)
	resp := postPKIOperation(t, f.ts, msgDER)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	return parseCertRep(t, body)
}

// A denied template gate is a protocol-level FAILURE CertRep, audited, with
// nothing recorded; and the one-time challenge is not burned by the denial.
func TestSCEPEnrollDeniedByTemplateRoles(t *testing.T) {
	f := newSCEPFixture(t)
	defer f.Close()
	recorder := &fakeIssuedRecorder{}
	denied := true
	f.srv.WithIssuedRecorder(recorder).WithEnrollmentGate(func(context.Context, string) error {
		if denied {
			return fmt.Errorf("%w: template tpl-x", ca.ErrEnrollmentDenied)
		}
		return nil
	})
	secret := f.mint(t, "gated.example.com", "gated.example.com")

	rep := f.enrollOnce(t, "gated.example.com", secret)
	if rep.pkiStatus != pkiStatusFailure {
		t.Fatalf("denied enrollment pkiStatus = %q, want FAILURE", rep.pkiStatus)
	}
	if len(f.audited) != 1 || f.audited[0].Outcome != "denied" || !strings.Contains(f.audited[0].Detail, "enrollment_permissions") {
		t.Fatalf("audit rows = %+v, want one denied row naming the template permission", f.audited)
	}
	recorder.mu.Lock()
	calls := recorder.calls
	recorder.mu.Unlock()
	if calls != 0 {
		t.Errorf("recorder saw %d certificates from a denied enrollment", calls)
	}

	// Gate order: the challenge was not consumed, so it still enrolls.
	denied = false
	if rep := f.enrollOnce(t, "gated.example.com", secret); rep.pkiStatus != pkiStatusSuccess {
		t.Fatalf("challenge burned by a gate denial: pkiStatus %q", rep.pkiStatus)
	}
}

func TestSCEPEnrollBlockedWhenGateErrors(t *testing.T) {
	f := newSCEPFixture(t)
	defer f.Close()
	f.srv.WithEnrollmentGate(func(context.Context, string) error { return errors.New("template store down") })
	rep := f.enrollOnce(t, "x.example.com", f.mint(t, "x.example.com", "x.example.com"))
	if rep.pkiStatus != pkiStatusFailure {
		t.Fatalf("gate error must block issuance, got pkiStatus %q", rep.pkiStatus)
	}
}
