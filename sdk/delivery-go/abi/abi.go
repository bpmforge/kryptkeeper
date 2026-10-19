// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package abi is the contract between the Kryptkeeper hub and a certificate
// delivery plugin (api_version kryptkeeper.delivery/v1, D-120). The hub and
// the Go SDK both use these types, so there is one definition of every
// message.
//
// A plugin is a WebAssembly module (wasip1, built as a reactor) that
// exports:
//
//	kk_alloc(size u32) -> ptr u32
//	kk_invoke(op_ptr, op_len, in_ptr, in_len u32) -> u64   // ptr<<32 | len
//
// and imports one host function, module "kryptkeeper":
//
//	kk_host(op_ptr, op_len, in_ptr, in_len u32) -> u64     // ptr<<32 | len
//
// Every payload is JSON. kk_invoke's op is one of OpValidate, OpPush,
// OpVerify or OpRollback, its input the matching request and its output a Response.
// kk_host's op is one of the Host* operations, its output a HostReply, and
// the host writes the reply into memory it gets from kk_alloc.
package abi

import "encoding/json"

// APIVersion is the only manifest api_version this package speaks.
const APIVersion = "kryptkeeper.delivery/v1"

// Operations the hub invokes on a plugin.
const (
	OpValidate = "validate"
	OpPush     = "push"
	OpRollback = "rollback"
	// OpVerify fetches what a secret store now holds for a pushed object, so
	// the hub can fingerprint it itself. Only plugins whose manifest declares
	// verification "readback" are asked.
	OpVerify = "verify"
)

// Operations a plugin may ask of the host. Each is checked against the
// capabilities the plugin was granted; an ungranted call gets an error.
const (
	HostHTTP       = "http.do"
	HostExecRun    = "exec.run"
	HostExecWrite  = "exec.write_file"
	HostExecRead   = "exec.read_file"
	HostExecExists = "exec.exists"
	HostLog        = "log"
)

// Outcomes a plugin may report from push. The hub alone decides
// installed_verified and verify_failed, after its own check of what the
// device serves.
const (
	OutcomeInstalled        = "installed"
	OutcomeWriteFailed      = "write_failed"
	OutcomeCertImportFailed = "cert_import_failed"
	OutcomeBindingFailed    = "binding_failed"
	OutcomeConfigTestFailed = "config_test_failed"
	OutcomeReloadFailed     = "reload_failed"
	OutcomeTrustFailed      = "trust_failed"
)

// PluginOutcomes is the set push may return.
var PluginOutcomes = map[string]bool{
	OutcomeInstalled: true, OutcomeWriteFailed: true, OutcomeCertImportFailed: true,
	OutcomeBindingFailed: true, OutcomeConfigTestFailed: true, OutcomeReloadFailed: true,
	OutcomeTrustFailed: true,
}

// Invocation is what every operation receives: the decrypted fields of the
// target's credential that the manifest's credential_schema names, and the
// target's non-secret settings (target_schema).
type Invocation struct {
	Credential map[string]string `json:"credential"`
	Target     map[string]string `json:"target"`
}

// ValidateRequest checks reachability and permissions without changing the
// device ("test connection").
type ValidateRequest struct {
	Invocation
}

// PushRequest delivers a certificate. KeyPEM is present only when the
// plugin was granted receive_private_key.
type PushRequest struct {
	Invocation
	// Name is the object name to use on the device.
	Name    string `json:"name"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem,omitempty"`
}

// PushResult is what a plugin reports. It has no Verified field: only the
// hub can say a delivery is verified.
type PushResult struct {
	Installed bool   `json:"installed"`
	Reloaded  bool   `json:"reloaded"`
	Outcome   string `json:"outcome"`
	Detail    string `json:"detail,omitempty"`
	// RollbackHandle is opaque to the hub and handed back to rollback, e.g.
	// the profile's previous certificate name.
	RollbackHandle string `json:"rollback_handle,omitempty"`
}

// VerifyRequest asks a read-back plugin for the certificate its store holds
// for the object push wrote. Handle is the push's RollbackHandle, so the
// plugin can read the exact version it wrote rather than "latest".
type VerifyRequest struct {
	Invocation
	Name   string `json:"name"`
	Handle string `json:"handle"`
}

// VerifyResult carries the stored certificate PEM. The hub parses it and
// compares the leaf's SHA-256 itself; the plugin never says "verified".
type VerifyResult struct {
	CertPEM string `json:"cert_pem"`
}

// RollbackRequest asks the plugin to restore the state before push.
type RollbackRequest struct {
	Invocation
	Handle string `json:"handle"`
}

// RollbackResult says whether the restore actually succeeded. A false
// "rolled back" is worse than none: the hub reports it to the operator.
type RollbackResult struct {
	RolledBack bool   `json:"rolled_back"`
	Detail     string `json:"detail,omitempty"`
}

// Response wraps every kk_invoke result.
type Response struct {
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// HostReply wraps every kk_host result.
type HostReply struct {
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// HTTPRequest is an HTTPS request to the device's management plane.
type HTTPRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
}

// HTTPResponse is the device's answer; the body is capped by the host.
type HTTPResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
}

// ExecRunRequest runs a command on the target host (remote_exec;
// elevated_exec when it escalates privilege (sudo, doas, su, pkexec, runuser,
// setpriv, chroot, nsenter, also via env or other wrappers) or hands a shell
// or interpreter an inline command (sh -c, python -c, perl -e, node -e, ...)).
type ExecRunRequest struct {
	Argv []string `json:"argv"`
}

// ExecRunResponse is the command's combined output.
type ExecRunResponse struct {
	Output []byte `json:"output"`
}

// ExecFileRequest names a file on the target host, under a declared path.
type ExecFileRequest struct {
	Path    string `json:"path"`
	Content []byte `json:"content,omitempty"` // write_file only
	Mode    uint32 `json:"mode,omitempty"`    // write_file only
}

// ExecFileResponse is a read_file or exists answer.
type ExecFileResponse struct {
	Content []byte `json:"content,omitempty"`
	Exists  bool   `json:"exists,omitempty"`
}

// LogRequest is one log line. The host caps it, refuses PEM blocks and
// redacts the secrets it handed the plugin.
type LogRequest struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}
