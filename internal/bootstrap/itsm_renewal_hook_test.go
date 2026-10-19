// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"

	"kryptkeeper/internal/agentinstall"
)

func TestNotifyRenewalVerified_OnlyVerifiedInstalledRenewals(t *testing.T) {
	var got []string
	SetRenewalVerifiedHook(func(_ context.Context, pred, succ string) { got = append(got, pred+">"+succ) })
	t.Cleanup(func() { SetRenewalVerifiedHook(nil) })

	ok := RenewalExecuteResult{PredecessorFingerprint: "old", NewFingerprint: "new", Renewed: true, Verified: true, InstallOutcome: agentinstall.OutcomeInstalledVerified}
	notifyRenewalVerified(context.Background(), ok)
	if len(got) != 1 || got[0] != "old>new" {
		t.Fatalf("verified renewal: %v", got)
	}

	for name, r := range map[string]RenewalExecuteResult{
		"not renewed":    {PredecessorFingerprint: "old", Verified: true, InstallOutcome: agentinstall.OutcomeInstalledVerified},
		"not verified":   {PredecessorFingerprint: "old", Renewed: true, InstallOutcome: agentinstall.OutcomeInstalled},
		"install failed": {PredecessorFingerprint: "old", Renewed: true, Verified: true, InstallOutcome: "install_failed"},
		"no predecessor": {Renewed: true, Verified: true, InstallOutcome: agentinstall.OutcomeInstalledVerified},
	} {
		notifyRenewalVerified(context.Background(), r)
		if len(got) != 1 {
			t.Fatalf("%s must not fire the hook: %v", name, got)
		}
	}

	SetRenewalVerifiedHook(nil)
	notifyRenewalVerified(context.Background(), ok) // no hook: no panic
}
