// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Body caps for the routes that decode JSON before (or without) a session:
// login/refresh, agent enrollment and SCIM provisioning. The server's 15s
// ReadTimeout bounds slow bodies but not fast ones, so without a cap any
// caller could make the hub buffer an arbitrarily large document.
const (
	// maxAuthBodyBytes covers login, refresh and API-key create: a few short
	// strings. 16 KiB leaves room for a long passphrase and a scopes list.
	maxAuthBodyBytes = 16 << 10
	// maxAgentSmallBodyBytes covers agent register (name, type, secret).
	maxAgentSmallBodyBytes = 16 << 10
	// maxAgentResultBodyBytes covers a single renewal-result report.
	maxAgentResultBodyBytes = 64 << 10
	// maxAgentInventoryBodyBytes is larger because one push carries every
	// certificate a host found (~600 B each, so roughly 3000 per push).
	maxAgentInventoryBodyBytes = 2 << 20
	// maxSCIMBodyBytes covers SCIM user/group documents and PATCH bodies,
	// including group member lists.
	maxSCIMBodyBytes = 1 << 20
)

// errBodyTooLarge is what decodeJSONBody returns when the cap was exceeded, so
// callers can answer 413 instead of the generic 400.
var errBodyTooLarge = errors.New("request body too large")

// capBody installs the size cap on r.Body. Handlers that read the body some
// other way than decodeJSONBody (io.ReadAll) call it first.
func capBody(w http.ResponseWriter, r *http.Request, maxBytes int64) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
}

// isBodyTooLarge reports whether err came from exceeding a body cap, either
// from decodeJSONBody or directly from a MaxBytesReader read.
func isBodyTooLarge(err error) bool {
	var tooBig *http.MaxBytesError
	return errors.Is(err, errBodyTooLarge) || errors.As(err, &tooBig)
}

// decodeJSONBody decodes one JSON document of at most maxBytes into dst.
// Unknown fields stay accepted (the surrounding handlers never rejected them
// and clients may send newer fields). Excess size yields errBodyTooLarge.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	capBody(w, r, maxBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		if isBodyTooLarge(err) {
			return fmt.Errorf("%w (limit %d bytes)", errBodyTooLarge, maxBytes)
		}
		return err
	}
	return nil
}

// decodeJSONBodyOrReject is decodeJSONBody for handlers that answer with the
// standard error envelope: it writes 413 or 400 itself and returns false.
func decodeJSONBodyOrReject(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64, badMessage string) bool {
	err := decodeJSONBody(w, r, dst, maxBytes)
	if err == nil {
		return true
	}
	if isBodyTooLarge(err) {
		writeErrorEnvelope(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
		return false
	}
	writeBadRequest(w, badMessage)
	return false
}

// rejectOversizeBody answers 413 with the standard envelope when err came from
// exceeding a body cap and reports whether it did. Handlers that read the body
// themselves (io.ReadAll, json.Decoder over a MaxBytesReader) call it first in
// their error branch so an oversized body is not reported as a generic 400.
func rejectOversizeBody(w http.ResponseWriter, err error) bool {
	if !isBodyTooLarge(err) {
		return false
	}
	writeErrorEnvelope(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
	return true
}
