// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

func notifyPlugin(kind string, reply abi.NotifySendResult) (*Plugin, *[]string) {
	var ops []string
	p := &Plugin{manifest: abi.Manifest{Kind: kind}, granted: abi.Capabilities{}}
	p.invokeHook = func(_ context.Context, op string, _ []byte) ([]byte, error) {
		ops = append(ops, op)
		res, _ := json.Marshal(reply)
		return json.Marshal(abi.Response{Result: res})
	}
	return p, &ops
}

func TestInvokeRefusesOpsOutsideTheKind(t *testing.T) {
	// A notify plugin is never asked to push, and the refusal happens before
	// any instance (here: before the hook) runs.
	p, ops := notifyPlugin(abi.KindNotify, abi.NotifySendResult{Delivered: true})
	err := p.Validate(context.Background(), Env{})
	if !errors.Is(err, ErrOpNotForKind) || len(*ops) != 0 {
		t.Fatalf("validate on notify plugin: err %v ops %v", err, *ops)
	}
	res := p.Deliver(context.Background(), Env{}, DeliverRequest{Name: "x"}, nil)
	if res.Outcome != abi.OutcomeWriteFailed || !strings.Contains(res.Detail, "not defined for this plugin's kind") || len(*ops) != 0 {
		t.Fatalf("deliver on notify plugin: %+v ops %v", res, *ops)
	}

	// And a delivery plugin is never asked to send an alert.
	d, dops := notifyPlugin("", abi.NotifySendResult{Delivered: true})
	if _, err := d.Notify(context.Background(), Env{}, abi.NotifySendRequest{}); !errors.Is(err, ErrOpNotForKind) || len(*dops) != 0 {
		t.Fatalf("notify on delivery plugin: err %v ops %v", err, *dops)
	}
}

func TestNotifyResultHandling(t *testing.T) {
	p, ops := notifyPlugin(abi.KindNotify, abi.NotifySendResult{Delivered: true, ProviderID: "abc\n" + strings.Repeat("x", 300)})
	res, err := p.Notify(context.Background(), Env{}, abi.NotifySendRequest{DedupeKey: "k"})
	if err != nil || !res.Delivered || len(res.ProviderID) > maxProviderID || strings.Contains(res.ProviderID, "\n") {
		t.Fatalf("delivered: %+v err %v", res, err)
	}
	if len(*ops) != 1 || (*ops)[0] != abi.OpNotifySend {
		t.Fatalf("ops %v", *ops)
	}

	secret := "super-secret-token-value"
	p, _ = notifyPlugin(abi.KindNotify, abi.NotifySendResult{Detail: "rejected token " + secret, RetryAfterSeconds: 30})
	env := Env{Credential: map[string]string{"token": secret}, Secrets: []string{"token"}}
	_, err = p.Notify(context.Background(), env, abi.NotifySendRequest{})
	var ne *NotifyError
	if !errors.As(err, &ne) || ne.RetryAfterSeconds != 30 {
		t.Fatalf("failure should be a NotifyError with the retry hint: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks the credential: %v", err)
	}

	p, _ = notifyPlugin(abi.KindNotify, abi.NotifySendResult{})
	if _, err := p.Notify(context.Background(), Env{}, abi.NotifySendRequest{}); err == nil {
		t.Fatal("delivered=false must be an error")
	}
}
