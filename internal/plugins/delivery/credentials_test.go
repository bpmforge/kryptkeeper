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

func credentialsPlugin(kind string, reply abi.CredentialsGetResult) (*Plugin, *[]abi.CredentialsGetRequest) {
	var seen []abi.CredentialsGetRequest
	p := &Plugin{manifest: abi.Manifest{Kind: kind}, granted: abi.Capabilities{ProvideCredentials: true}}
	p.invokeHook = func(_ context.Context, op string, in []byte) ([]byte, error) {
		if op == abi.OpCredentialsGet {
			var r abi.CredentialsGetRequest
			_ = json.Unmarshal(in, &r)
			seen = append(seen, r)
		}
		res, _ := json.Marshal(reply)
		return json.Marshal(abi.Response{Result: res})
	}
	return p, &seen
}

func TestCredentialsGetPassesReferenceAndReturnsFields(t *testing.T) {
	p, seen := credentialsPlugin(abi.KindCredentials, abi.CredentialsGetResult{Fields: map[string]string{"password": "p4ss-word"}, LeaseSeconds: 60})
	env := Env{Credential: map[string]string{"app_id": "kk"}}
	res, err := p.CredentialsGet(context.Background(), env, map[string]string{"object": "web1"})
	if err != nil || res.Fields["password"] != "p4ss-word" || res.LeaseSeconds != 60 {
		t.Fatalf("result %+v err %v", res, err)
	}
	if len(*seen) != 1 || (*seen)[0].Reference["object"] != "web1" || (*seen)[0].Credential["app_id"] != "kk" {
		t.Fatalf("the plugin saw %+v", *seen)
	}
}

func TestCredentialsGetIsOnlyForTheCredentialsKind(t *testing.T) {
	for _, kind := range []string{"", abi.KindNotify} {
		p, seen := credentialsPlugin(kind, abi.CredentialsGetResult{Fields: map[string]string{"a": "b"}})
		if _, err := p.CredentialsGet(context.Background(), Env{}, nil); !errors.Is(err, ErrOpNotForKind) || len(*seen) != 0 {
			t.Fatalf("kind %q: err %v seen %v", kind, err, *seen)
		}
	}
	// The other direction: a credentials plugin is never asked to push or notify.
	p, _ := credentialsPlugin(abi.KindCredentials, abi.CredentialsGetResult{})
	if err := p.Validate(context.Background(), Env{}); !errors.Is(err, ErrOpNotForKind) {
		t.Fatalf("validate on a credentials plugin: %v", err)
	}
	if _, err := p.Notify(context.Background(), Env{}, abi.NotifySendRequest{}); !errors.Is(err, ErrOpNotForKind) {
		t.Fatalf("notify on a credentials plugin: %v", err)
	}
}

func TestCredentialsGetBoundsTheResult(t *testing.T) {
	many := map[string]string{}
	for i := range abi.MaxCredentialFields + 1 {
		many[strings.Repeat("k", i+1)] = "v"
	}
	for name, fields := range map[string]map[string]string{
		"empty":     {},
		"too many":  many,
		"too large": {"blob": strings.Repeat("x", abi.MaxCredentialFieldBytes+1)},
		"no name":   {"": "v"},
	} {
		p, _ := credentialsPlugin(abi.KindCredentials, abi.CredentialsGetResult{Fields: fields})
		res, err := p.CredentialsGet(context.Background(), Env{}, nil)
		if !errors.Is(err, ErrCredentialResult) || len(res.Fields) != 0 {
			t.Errorf("%s: result %+v err %v", name, res, err)
		}
	}
	p, _ := credentialsPlugin(abi.KindCredentials, abi.CredentialsGetResult{Fields: map[string]string{"a": "b"}, LeaseSeconds: -5})
	if res, err := p.CredentialsGet(context.Background(), Env{}, nil); err != nil || res.LeaseSeconds != 0 {
		t.Fatalf("negative lease: %+v %v", res, err)
	}
}

// A plugin that logs the secret it is fetching speaks before the result
// exists, so the hub holds events and removes every returned value.
func TestHeldEventsLoseTheSecretValues(t *testing.T) {
	var got []Event
	flushRedacted(func(e Event) { got = append(got, e) },
		[]Event{{Kind: "log", Detail: "fetched password hunter2-secret for web1"}, {Kind: "http", Detail: "GET https://ccp.example.com -> 200"}},
		[]string{"hunter2-secret"})
	if len(got) != 2 || strings.Contains(got[0].Detail, "hunter2-secret") || !strings.Contains(got[0].Detail, "[redacted]") || got[1].Detail != "GET https://ccp.example.com -> 200" {
		t.Fatalf("events %+v", got)
	}
	flushRedacted(nil, []Event{{Detail: "x"}}, nil) // a nil sink drops them, it does not panic
}
