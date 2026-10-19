// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package delivery runs certificate delivery plugins (W20-19, D-113..D-120):
// WebAssembly modules that speak the ABI in
// github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi.
//
// The sandbox is what makes a plugin's capabilities enforced rather than
// declared. A plugin gets:
//   - no WASI filesystem, environment or arguments;
//   - no sockets (wazero's preview1 has none), so its only network is the
//     host's http.do, scoped to the hosts it was granted;
//   - stdout and stderr routed through the same capped, PEM-refusing,
//     secret-redacting logger as its log calls;
//   - a memory cap and a deadline that closes the instance (wazero has no
//     instruction metering, so CPU is bounded by time).
//
// Each operation gets a fresh instance, so no state, and no key, survives
// from one push to the next.
package delivery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

// memoryLimitPages caps a plugin instance at 128 MiB of linear memory.
const memoryLimitPages = 2048

// Runtime compiles and runs plugins. One per process; safe for concurrent use.
type Runtime struct {
	rt  wazero.Runtime
	seq atomic.Uint64
}

// NewRuntime starts the WebAssembly runtime with the host module bound.
func NewRuntime(ctx context.Context) (*Runtime, error) {
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
		WithMemoryLimitPages(memoryLimitPages).
		WithCloseOnContextDone(true))
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("wasi: %w", err)
	}
	if _, err := rt.NewHostModuleBuilder("kryptkeeper").
		NewFunctionBuilder().WithFunc(hostCall).Export("kk_host").
		Instantiate(ctx); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("host module: %w", err)
	}
	return &Runtime{rt: rt}, nil
}

// Close releases every compiled plugin.
func (r *Runtime) Close(ctx context.Context) error { return r.rt.Close(ctx) }

// Plugin is a loaded, granted plugin.
type Plugin struct {
	rt       *Runtime
	compiled wazero.CompiledModule
	manifest abi.Manifest
	granted  abi.Capabilities
	// invokeHook replaces the WebAssembly call in package tests so the hub's
	// verify/rollback logic can be driven without compiling a plugin.
	invokeHook func(ctx context.Context, op string, in []byte) ([]byte, error)
	clock      verifyClock
}

// Manifest returns the plugin's manifest.
func (p *Plugin) Manifest() abi.Manifest { return p.manifest }

// Granted returns the capabilities the plugin runs with.
func (p *Plugin) Granted() abi.Capabilities { return p.granted }

var (
	// ErrHashMismatch means the module is not the one the manifest pins.
	ErrHashMismatch = errors.New("plugin module does not match the manifest's sha256")
	// ErrGrantExceedsManifest means a grant wider than what was declared.
	ErrGrantExceedsManifest = errors.New("granted capabilities exceed the manifest's")
)

// Load checks the manifest and the module against it and compiles the
// module. granted is what the operator approved, never wider than the
// manifest; the plugin runs with exactly that.
func (r *Runtime) Load(ctx context.Context, manifestJSON, wasm []byte, granted abi.Capabilities) (*Plugin, error) {
	m, err := abi.ParseManifest(manifestJSON)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(wasm)
	if hex.EncodeToString(sum[:]) != m.Artifact.SHA256 {
		return nil, ErrHashMismatch
	}
	if !granted.Within(m.Capabilities) {
		return nil, ErrGrantExceedsManifest
	}
	compiled, err := r.rt.CompileModule(ctx, wasm)
	if err != nil {
		return nil, fmt.Errorf("compile plugin %s: %w", m.ID, err)
	}
	for _, name := range []string{"kk_alloc", "kk_invoke"} {
		if _, ok := compiled.ExportedFunctions()[name]; !ok {
			_ = compiled.Close(ctx)
			return nil, fmt.Errorf("plugin %s does not export %s", m.ID, name)
		}
	}
	return &Plugin{rt: r, compiled: compiled, manifest: m, granted: granted}, nil
}

// Close releases the compiled module.
func (p *Plugin) Close(ctx context.Context) error { return p.compiled.Close(ctx) }

// invoke runs one operation in a fresh instance and returns the plugin's
// Response result.
func (p *Plugin) invoke(ctx context.Context, st *callState, op string, in []byte) ([]byte, error) {
	if p.invokeHook != nil {
		return p.invokeHook(ctx, op, in)
	}
	ctx = context.WithValue(ctx, callStateKey{}, st)
	logw := &lineWriter{st: st}
	cfg := wazero.NewModuleConfig().
		WithName(fmt.Sprintf("%s#%d", p.manifest.ID, p.rt.seq.Add(1))).
		WithStartFunctions("_initialize").
		WithStdout(logw).WithStderr(logw).
		WithSysWalltime().WithSysNanotime().
		WithRandSource(rand.Reader)
	mod, err := p.rt.rt.InstantiateModule(ctx, p.compiled, cfg)
	if err != nil {
		return nil, wrapCallErr(ctx, err)
	}
	defer func() { _ = mod.Close(context.WithoutCancel(ctx)) }()

	opPtr, err := writeIn(ctx, mod, []byte(op))
	if err != nil {
		return nil, wrapCallErr(ctx, err)
	}
	inPtr, err := writeIn(ctx, mod, in)
	if err != nil {
		return nil, wrapCallErr(ctx, err)
	}
	res, err := mod.ExportedFunction("kk_invoke").Call(ctx, uint64(opPtr), uint64(len(op)), uint64(inPtr), uint64(len(in)))
	if err != nil {
		return nil, wrapCallErr(ctx, err)
	}
	out, ok := mod.Memory().Read(uint32(res[0]>>32), uint32(res[0]))
	if !ok {
		return nil, errors.New("plugin returned an out-of-range result")
	}
	return append([]byte(nil), out...), nil
}

// writeIn copies b into memory the plugin allocates.
func writeIn(ctx context.Context, mod api.Module, b []byte) (uint32, error) {
	res, err := mod.ExportedFunction("kk_alloc").Call(ctx, uint64(len(b)))
	if err != nil {
		return 0, err
	}
	ptr := uint32(res[0])
	if !mod.Memory().Write(ptr, b) {
		return 0, errors.New("plugin allocation out of range")
	}
	return ptr, nil
}

// ErrDeadline means the plugin ran past its time limit and was stopped.
var ErrDeadline = errors.New("plugin exceeded its time limit and was stopped")

func wrapCallErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ErrDeadline
	}
	return fmt.Errorf("plugin: %w", err)
}
