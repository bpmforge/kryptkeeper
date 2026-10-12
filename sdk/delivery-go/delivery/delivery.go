// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package delivery is the Go SDK for Kryptkeeper certificate delivery
// plugins. A plugin implements Plugin, registers it in init, and is built
// for wasip1 as a reactor:
//
//	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o plugin.wasm .
//
// Everything a plugin does outside its own memory goes through Host, and
// the hub checks each call against the capabilities the operator approved.
package delivery

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

// Plugin is one delivery target. Push should leave the device as it found
// it when it fails part-way, and return a RollbackHandle that Rollback can
// use to undo a completed push the hub could not verify.
type Plugin interface {
	Validate(h *Host, req abi.ValidateRequest) error
	Push(h *Host, req abi.PushRequest) (abi.PushResult, error)
	Rollback(h *Host, req abi.RollbackRequest) (abi.RollbackResult, error)
}

var registered Plugin

// Register sets the plugin this module serves. Call it from init.
func Register(p Plugin) { registered = p }

// HostCall performs one host operation: op and a JSON input, a JSON
// HostReply back. The wasip1 build wires it to the kk_host import; tests
// can supply their own.
type HostCall func(op string, in []byte) ([]byte, error)

// Host is the plugin's only way out of its sandbox.
type Host struct{ call HostCall }

// NewHost wraps call. Plugins get a Host from the SDK; tests use this.
func NewHost(call HostCall) *Host { return &Host{call: call} }

func (h *Host) do(op string, in, out any) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	replyRaw, err := h.call(op, raw)
	if err != nil {
		return err
	}
	var reply abi.HostReply
	if err := json.Unmarshal(replyRaw, &reply); err != nil {
		return fmt.Errorf("host %s: bad reply: %w", op, err)
	}
	if reply.Error != "" {
		return fmt.Errorf("host %s: %s", op, reply.Error)
	}
	if out == nil || len(reply.Result) == 0 {
		return nil
	}
	return json.Unmarshal(reply.Result, out)
}

// HTTP sends an HTTPS request to the device. The host allows only hosts the
// manifest declared, verifies TLS itself, and caps the response body.
func (h *Host) HTTP(req abi.HTTPRequest) (abi.HTTPResponse, error) {
	var resp abi.HTTPResponse
	err := h.do(abi.HostHTTP, req, &resp)
	return resp, err
}

// Run runs a command on the target host (remote_exec). Escalation tools
// (sudo, doas, su, pkexec, ...) and shells or interpreters with an inline
// command (sh -c, python -c, ...) need elevated_exec; otherwise pass a
// concrete program and argv.
func (h *Host) Run(argv ...string) ([]byte, error) {
	var resp abi.ExecRunResponse
	err := h.do(abi.HostExecRun, abi.ExecRunRequest{Argv: argv}, &resp)
	return resp.Output, err
}

// WriteFile places content on the target host under a declared path.
func (h *Host) WriteFile(path string, content []byte, mode uint32) error {
	return h.do(abi.HostExecWrite, abi.ExecFileRequest{Path: path, Content: content, Mode: mode}, nil)
}

// ReadFile reads a file on the target host under a declared path.
func (h *Host) ReadFile(path string) ([]byte, error) {
	var resp abi.ExecFileResponse
	err := h.do(abi.HostExecRead, abi.ExecFileRequest{Path: path}, &resp)
	return resp.Content, err
}

// Exists reports whether a path under a declared path exists on the host.
func (h *Host) Exists(path string) (bool, error) {
	var resp abi.ExecFileResponse
	err := h.do(abi.HostExecExists, abi.ExecFileRequest{Path: path}, &resp)
	return resp.Exists, err
}

// Logf writes one log line to the hub. Never log key material: the host
// refuses lines carrying PEM blocks and redacts credential secrets.
func (h *Host) Logf(format string, args ...any) {
	_ = h.do(abi.HostLog, abi.LogRequest{Level: "info", Message: fmt.Sprintf(format, args...)}, nil)
}

// Dispatch runs one operation on the registered plugin and returns the
// JSON Response. It is what kk_invoke calls; it is exported for tests that
// drive a plugin without WebAssembly.
func Dispatch(call HostCall, op string, in []byte) []byte {
	return DispatchTo(registered, call, op, in)
}

// DispatchTo is Dispatch for a given plugin.
func DispatchTo(p Plugin, call HostCall, op string, in []byte) []byte {
	result, err := dispatch(p, NewHost(call), op, in)
	resp := abi.Response{Result: result}
	if err != nil {
		resp.Error = err.Error()
	}
	out, mErr := json.Marshal(resp)
	if mErr != nil {
		out, _ = json.Marshal(abi.Response{Error: "marshal response: " + mErr.Error()})
	}
	return out
}

func dispatch(p Plugin, h *Host, op string, in []byte) (json.RawMessage, error) {
	if p == nil {
		return nil, errors.New("no plugin registered (call delivery.Register in init)")
	}
	switch op {
	case abi.OpValidate:
		var req abi.ValidateRequest
		if err := json.Unmarshal(in, &req); err != nil {
			return nil, err
		}
		return nil, p.Validate(h, req)
	case abi.OpPush:
		var req abi.PushRequest
		if err := json.Unmarshal(in, &req); err != nil {
			return nil, err
		}
		res, err := p.Push(h, req)
		if err != nil && res.Outcome == "" {
			return nil, err
		}
		if err != nil && res.Detail == "" {
			res.Detail = err.Error()
		}
		return json.Marshal(res)
	case abi.OpRollback:
		var req abi.RollbackRequest
		if err := json.Unmarshal(in, &req); err != nil {
			return nil, err
		}
		res, err := p.Rollback(h, req)
		if err != nil && res.Detail == "" {
			res.Detail = err.Error()
		}
		return json.Marshal(res)
	}
	return nil, fmt.Errorf("unknown operation %q", op)
}
