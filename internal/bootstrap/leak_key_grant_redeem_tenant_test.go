// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
)

// A key grant is stamped with the key's owner at proposal time. Redemption must
// re-check ownership: if the CA backing the key has since moved to another
// tenant, the approval (given by the old owner's approvers) must not release it.
// An unscoped super-admin skips the endpoint's own tenant gate, so this is the
// check that stops it.
func TestKeyGrantRedemptionRechecksOwnerTenant(t *testing.T) {
	e := setupKeysLeakEnv(t)
	ctx := context.Background()
	auth := NewAuthenticatorFromEnv()
	dc := NewKeyDualControlFromEnv(e.pendingStore)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	pd, err := auth.AuthenticatePrincipalDetails(req, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	approvedGrant := func() PendingAction {
		t.Helper()
		a, err := dc.ProposeGrant(ctx, auth, keyActionExport, e.acmeCAKey, "", pd)
		if err != nil {
			t.Fatalf("propose: %v", err)
		}
		if a.Tenant != "acme" {
			t.Fatalf("grant stamped %q, want acme", a.Tenant)
		}
		if err := e.pendingStore.Decide(ctx, a.ID, "approved", "second-approver", nil); err != nil {
			t.Fatalf("approve: %v", err)
		}
		return a
	}

	// Ownership unchanged: redemption works.
	ok := approvedGrant()
	if err := dc.AuthorizeGrant(ctx, auth, keyActionExport, e.acmeCAKey, "", pd, ok.ID); err != nil {
		t.Fatalf("redeem with unchanged owner: %v", err)
	}

	// The CA backing the key is re-homed to globex after the grant was approved.
	stale := approvedGrant()
	caID, found, err := ca.KeyInUseByCA(activeCAStore, e.acmeCAKey)
	if err != nil || !found {
		t.Fatalf("key->CA lookup: %v %v", found, err)
	}
	if err := activeTenantStore.SetCATenant(ctx, caID, "globex"); err != nil {
		t.Fatal(err)
	}
	err = dc.AuthorizeGrant(ctx, auth, keyActionExport, e.acmeCAKey, "", pd, stale.ID)
	if err == nil || !strings.Contains(err.Error(), "different tenant") {
		t.Fatalf("redeeming a grant stamped for the previous owner must be refused, got %v", err)
	}
}
