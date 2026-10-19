// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"

	"kryptkeeper/internal/migration"
)

// liveTestImporter records the bind secret a live read was given.
type liveTestImporter struct {
	testMigrationImporter
	gotSecret *string
}

func (l liveTestImporter) Read(_ context.Context, o migration.ReadOptions) ([]migration.SourceObject, error) {
	*l.gotSecret = o.Secret
	return []migration.SourceObject{{Kind: "template", SourceKey: "k1", Name: "Web"}}, nil
}

// fixedCredStore resolves every reference to one stored payload.
type fixedCredStore struct {
	OutboundCredentialStore
	payload string
}

func (f fixedCredStore) Resolve(context.Context, string) ([]byte, error) {
	return []byte(f.payload), nil
}

// B1 (ADCS cutover rehearsal): the live template read must bind with the
// plaintext password, unwrapped the same way adcs_live unwraps it, not with
// the stored payload as-is (LDAP 52e, answered as 503).
func TestMigrationLiveReadUnwrapsStoredCredential(t *testing.T) {
	for name, payload := range map[string]string{
		"object payload": `{"password":"Plain-Pass1"}`,
		"string payload": `"Plain-Pass1"`,
		"bare secret":    "Plain-Pass1\n",
	} {
		t.Run(name, func(t *testing.T) {
			var got string
			im := liveTestImporter{gotSecret: &got}
			svc := migration.NewService(templateSink{}, nil, im)
			h := &migrationHandlers{svc: svc, creds: fixedCredStore{payload: payload}}
			in, err := h.input(context.Background(), "testsrc", "", "cred-1", map[string]string{"ldap_url": "ldaps://dc", "base_dn": "CN=x"})
			if err != nil {
				t.Fatalf("input: %v", err)
			}
			if got != "Plain-Pass1" {
				t.Fatalf("bind secret = %q, want the unwrapped plaintext", got)
			}
			if len(in.Objects) != 1 {
				t.Fatalf("objects: %+v", in.Objects)
			}
		})
	}
}
