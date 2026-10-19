// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

type fake struct{}

func (fake) Validate(h *Host, _ abi.ValidateRequest) error {
	_, err := h.HTTP(abi.HTTPRequest{Method: "GET", URL: "https://device.example/api"})
	return err
}
func (fake) Push(_ *Host, req abi.PushRequest) (abi.PushResult, error) {
	if req.Name == "fail" {
		return abi.PushResult{Outcome: abi.OutcomeBindingFailed}, errors.New("locked")
	}
	return abi.PushResult{Installed: true, Outcome: abi.OutcomeInstalled, RollbackHandle: "old"}, nil
}
func (fake) Rollback(*Host, abi.RollbackRequest) (abi.RollbackResult, error) {
	return abi.RollbackResult{RolledBack: true}, nil
}

func TestDispatch(t *testing.T) {
	refuse := func(op string, _ []byte) ([]byte, error) {
		return json.Marshal(abi.HostReply{Error: "refused: " + op})
	}
	var resp abi.Response
	_ = json.Unmarshal(DispatchTo(fake{}, refuse, abi.OpValidate, []byte(`{}`)), &resp)
	if resp.Error != "host http.do: refused: http.do" {
		t.Errorf("validate error %q", resp.Error)
	}

	_ = json.Unmarshal(DispatchTo(fake{}, refuse, abi.OpPush, []byte(`{"name":"fail"}`)), &resp)
	var pr abi.PushResult
	_ = json.Unmarshal(resp.Result, &pr)
	if pr.Outcome != abi.OutcomeBindingFailed || pr.Detail != "locked" {
		t.Errorf("a push error with an outcome must keep the outcome and carry the error: %+v", pr)
	}

	resp = abi.Response{}
	_ = json.Unmarshal(DispatchTo(fake{}, refuse, "format_disk", []byte(`{}`)), &resp)
	if resp.Error == "" {
		t.Error("unknown operation accepted")
	}
	resp = abi.Response{}
	_ = json.Unmarshal(DispatchTo(nil, refuse, abi.OpPush, []byte(`{}`)), &resp)
	if resp.Error == "" {
		t.Error("no registered plugin, no error")
	}
}

type readbackFake struct{ fake }

func (readbackFake) Verify(_ *Host, req abi.VerifyRequest) (abi.VerifyResult, error) {
	if req.Handle == "boom" {
		return abi.VerifyResult{}, errors.New("store unreachable")
	}
	return abi.VerifyResult{CertPEM: "pem-for-" + req.Handle}, nil
}

func TestDispatchVerify(t *testing.T) {
	noHost := func(string, []byte) ([]byte, error) { return nil, errors.New("no host") }
	var resp abi.Response
	_ = json.Unmarshal(DispatchTo(readbackFake{}, noHost, abi.OpVerify, []byte(`{"name":"n","handle":"v3"}`)), &resp)
	var vr abi.VerifyResult
	_ = json.Unmarshal(resp.Result, &vr)
	if resp.Error != "" || vr.CertPEM != "pem-for-v3" {
		t.Errorf("verify: %+v %+v", resp, vr)
	}
	resp = abi.Response{}
	_ = json.Unmarshal(DispatchTo(readbackFake{}, noHost, abi.OpVerify, []byte(`{"handle":"boom"}`)), &resp)
	if resp.Error != "store unreachable" {
		t.Errorf("verify error not surfaced: %+v", resp)
	}
	// A plugin without the hook fails closed.
	resp = abi.Response{}
	_ = json.Unmarshal(DispatchTo(fake{}, noHost, abi.OpVerify, []byte(`{}`)), &resp)
	if resp.Error == "" || len(resp.Result) != 0 {
		t.Errorf("a plugin without verify must error: %+v", resp)
	}
}
