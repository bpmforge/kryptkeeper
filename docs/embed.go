// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package docs embeds the OpenAPI contract so the hub can serve the exact
// spec it was built from.
package docs

import _ "embed"

// OpenAPI is the raw bytes of docs/openapi.yaml at build time.
//
//go:embed openapi.yaml
var OpenAPI []byte
