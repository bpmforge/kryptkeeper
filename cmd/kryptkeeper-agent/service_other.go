// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import "context"

// runAsWindowsService is the default-build stub for service_windows.go.
func runAsWindowsService(func(context.Context)) bool { return false }
