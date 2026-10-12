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
