// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build wasip1

package delivery

// The WebAssembly side of the ABI (see package abi). Pointers cross the
// boundary as 32-bit linear-memory offsets, which is why this file converts
// uintptr to unsafe.Pointer: vet's unsafeptr check cannot know the host
// owns those offsets, so the SDK is vetted with -unsafeptr=false.

import "unsafe"

//go:wasmimport kryptkeeper kk_host
func kkHost(opPtr, opLen, inPtr, inLen uint32) uint64

// pinned keeps buffers the host or the plugin still points into alive for
// the life of the instance. The hub makes a fresh instance per operation,
// so this never grows past one call.
var pinned [][]byte

//go:wasmexport kk_alloc
func kkAlloc(size uint32) uint32 {
	if size == 0 {
		size = 1
	}
	b := make([]byte, size)
	pinned = append(pinned, b)
	return uint32(uintptr(unsafe.Pointer(&b[0])))
}

//go:wasmexport kk_invoke
func kkInvoke(opPtr, opLen, inPtr, inLen uint32) uint64 {
	op := string(view(opPtr, opLen))
	in := append([]byte(nil), view(inPtr, inLen)...)
	return export(Dispatch(wasmHostCall, op, in))
}

func wasmHostCall(op string, in []byte) ([]byte, error) {
	opBuf, inBuf := []byte(op), in
	if len(inBuf) == 0 {
		inBuf = []byte("{}")
	}
	pinned = append(pinned, opBuf, inBuf)
	r := kkHost(addr(opBuf), uint32(len(opBuf)), addr(inBuf), uint32(len(inBuf)))
	return append([]byte(nil), view(uint32(r>>32), uint32(r))...), nil
}

func addr(b []byte) uint32 { return uint32(uintptr(unsafe.Pointer(&b[0]))) }

func view(ptr, n uint32) []byte {
	if n == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), n)
}

func export(b []byte) uint64 {
	if len(b) == 0 {
		return 0
	}
	pinned = append(pinned, b)
	return uint64(addr(b))<<32 | uint64(len(b))
}
