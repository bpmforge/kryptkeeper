// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

type fake struct{}

func (fake) Get(_ *delivery.Host, req abi.CredentialsGetRequest) (abi.CredentialsGetResult, error) {
	return abi.CredentialsGetResult{Fields: map[string]string{"user": req.Reference["who"]}, LeaseSeconds: 30}, nil
}

func TestHandle(t *testing.T) {
	out, err := Handle(fake{}, delivery.NewHost(nil), abi.OpCredentialsGet, []byte(`{"reference":{"who":"root"}}`))
	if err != nil {
		t.Fatal(err)
	}
	var res abi.CredentialsGetResult
	if err := json.Unmarshal(out, &res); err != nil || res.Fields["user"] != "root" || res.LeaseSeconds != 30 {
		t.Fatalf("result %s err %v", out, err)
	}
	if _, err := Handle(fake{}, delivery.NewHost(nil), abi.OpPush, []byte(`{}`)); err == nil {
		t.Fatal("a credentials plugin must refuse a delivery op")
	}
}

func TestFieldMap(t *testing.T) {
	def := map[string]string{"Content": "password"}
	if got, err := FieldMap("", def); err != nil || got["Content"] != "password" {
		t.Fatalf("defaults: %v %v", got, err)
	}
	got, err := FieldMap(" Content:private_key_pem , UserName:user", def)
	if err != nil || got["Content"] != "private_key_pem" || got["UserName"] != "user" || len(got) != 2 {
		t.Fatalf("map: %v %v", got, err)
	}
	for _, bad := range []string{"Content", "Content:", ":user", "a:b,c"} {
		if _, err := FieldMap(bad, def); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestFailedNeverCarriesABody(t *testing.T) {
	err := Failed(abi.HTTPResponse{Status: 404, Body: []byte("secret-in-body")}, "no such account")
	if strings.Contains(err.Error(), "secret-in-body") || !strings.Contains(err.Error(), "404") {
		t.Fatalf("error %q", err)
	}
}
