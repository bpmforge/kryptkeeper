// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/agentinstall"
)

// fakeClock advances only when slept on, so a 20-minute window is instant.
type fakeClock struct {
	t      time.Time
	slept  []time.Duration
	onTick func()
}

func (f *fakeClock) clock() verifyClock {
	return verifyClock{
		now: func() time.Time { return f.t },
		sleep: func(ctx context.Context, d time.Duration) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			f.slept = append(f.slept, d)
			f.t = f.t.Add(d)
			if f.onTick != nil {
				f.onTick()
			}
			return nil
		},
	}
}

func windowPlugin(window int, fc *fakeClock) *readbackPlugin {
	rp := newReadbackPlugin("readback")
	rp.manifest.VerifyPropagationSeconds = window
	rp.clock = fc.clock()
	return rp
}

func TestWindowDelayedMatchSucceeds(t *testing.T) {
	oldPEM, _ := testLeaf(t, "old")
	newPEM, newFP := testLeaf(t, "new")
	fc := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rp := windowPlugin(600, fc)
	// 6 quick attempts + 3 polls see the old leaf; the 4th poll sees the new one.
	rp.verifyFn = func() (abi.VerifyResult, error) {
		if rp.verifyN > verifyAttempts+3 {
			return abi.VerifyResult{CertPEM: newPEM}, nil
		}
		return abi.VerifyResult{CertPEM: oldPEM}, nil
	}
	res := rp.Deliver(context.Background(), Env{}, readbackReq(newFP), nil)
	if !res.Verified || res.Outcome != agentinstall.OutcomeInstalledVerified || res.RolledBack || rp.rolledBack() {
		t.Fatalf("expected verified after delayed propagation: %+v", res)
	}
	if rp.verifyN != verifyAttempts+4 {
		t.Errorf("verify calls %d, want %d", rp.verifyN, verifyAttempts+4)
	}
	var polls int
	for _, d := range fc.slept {
		if d == verifyPollInterval {
			polls++
		}
	}
	if polls != 4 {
		t.Errorf("polls at %s: %d, want 4", verifyPollInterval, polls)
	}
}

func TestWindowExpiryFailsAndRollsBack(t *testing.T) {
	oldPEM, _ := testLeaf(t, "old")
	_, newFP := testLeaf(t, "new")
	fc := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rp := windowPlugin(60, fc)
	rp.verifyFn = func() (abi.VerifyResult, error) { return abi.VerifyResult{CertPEM: oldPEM}, nil }
	res := rp.Deliver(context.Background(), Env{}, readbackReq(newFP), nil)
	if res.Verified || res.Outcome != agentinstall.OutcomeVerifyFailed || !res.RolledBack || !rp.rolledBack() {
		t.Fatalf("expected verify_failed + rollback: %+v", res)
	}
	if want := verifyAttempts + 4; rp.verifyN != want { // 60s / 15s polls
		t.Errorf("verify calls %d, want %d", rp.verifyN, want)
	}
}

func TestWindowZeroKeepsQuickAttemptsOnly(t *testing.T) {
	oldPEM, _ := testLeaf(t, "old")
	_, newFP := testLeaf(t, "new")
	fc := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rp := windowPlugin(0, fc)
	rp.verifyFn = func() (abi.VerifyResult, error) { return abi.VerifyResult{CertPEM: oldPEM}, nil }
	res := rp.Deliver(context.Background(), Env{}, readbackReq(newFP), nil)
	if res.Outcome != agentinstall.OutcomeVerifyFailed || rp.verifyN != verifyAttempts {
		t.Fatalf("zero window: %+v calls=%d", res, rp.verifyN)
	}
	for _, d := range fc.slept {
		if d == verifyPollInterval {
			t.Error("polled with a zero window")
		}
	}
}

func TestWindowPollsTLSPathAndStopsOnCancel(t *testing.T) {
	_, newFP := testLeaf(t, "new")
	fc := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rp := windowPlugin(1200, fc)
	rp.manifest.Verification = ""
	ctx, cancel := context.WithCancel(context.Background())
	dials := 0
	fc.onTick = func() {
		if dials >= verifyAttempts+2 {
			cancel()
		}
	}
	res := rp.Deliver(ctx, Env{}, DeliverRequest{Name: "n", CertPEM: []byte("x"), VerifyHostPort: "h:443", ExpectedFingerprint: newFP},
		func(context.Context, string) (string, error) { dials++; return "00", nil })
	if res.Outcome != agentinstall.OutcomeVerifyFailed || !res.RolledBack {
		t.Fatalf("cancelled window must fail closed and still roll back: %+v", res)
	}
	if dials > verifyAttempts+3 {
		t.Errorf("kept polling after cancel: %d dials", dials)
	}
}
