// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package credentials is the Go SDK for Kryptkeeper credentials plugins (kind
// "credentials", D-321, D-324): a plugin that fetches one credential from a
// secret manager (CyberArk, Delinea, ...) at the moment the hub needs it. It
// shares the sandbox, Host and ABI of delivery plugins; only the operation
// differs (abi.OpCredentialsGet). A plugin implements Plugin, registers it in
// init, and builds for wasip1 exactly like a delivery plugin.
package credentials

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

// Plugin fetches credentials. Get returns the fields named for the payload
// the consuming credential type expects, and the lease the manager reports
// (0 when it reports none). It returns an error, never empty fields, when the
// manager denies the request or the secret does not exist, and the error text
// must not repeat the response body: managers reflect request parameters.
type Plugin interface {
	Get(h *delivery.Host, req abi.CredentialsGetRequest) (abi.CredentialsGetResult, error)
}

// Register sets the plugin this module serves. Call it from init.
func Register(p Plugin) {
	delivery.RegisterHandler(func(h *delivery.Host, op string, in []byte) (json.RawMessage, error) {
		return Handle(p, h, op, in)
	})
}

// Handle runs one operation on p. It is exported for plugin tests that drive
// a plugin without WebAssembly.
func Handle(p Plugin, h *delivery.Host, op string, in []byte) (json.RawMessage, error) {
	if op != abi.OpCredentialsGet {
		return nil, fmt.Errorf("unknown operation %q for a credentials plugin", op)
	}
	var req abi.CredentialsGetRequest
	if err := json.Unmarshal(in, &req); err != nil {
		return nil, err
	}
	res, err := p.Get(h, req)
	if err != nil {
		return nil, err
	}
	return json.Marshal(res)
}

// FieldMap says which payload field each field of the manager's record fills,
// from a reference's "map" value: "Content:private_key_pem,UserName:user".
// Names are the manager's on the left and the consuming credential type's on
// the right. An empty spec yields defaults.
func FieldMap(spec string, defaults map[string]string) (map[string]string, error) {
	if strings.TrimSpace(spec) == "" {
		return defaults, nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(spec, ",") {
		from, to, ok := strings.Cut(strings.TrimSpace(pair), ":")
		from, to = strings.TrimSpace(from), strings.TrimSpace(to)
		if !ok || from == "" || to == "" {
			return nil, fmt.Errorf("reference map %q must be pairs like SourceField:payload_field", spec)
		}
		out[from] = to
	}
	return out, nil
}

// Failed builds the error for a manager that answered but gave no credential:
// the status and the caller's short reason, never the response body.
func Failed(resp abi.HTTPResponse, why string) error {
	return fmt.Errorf("secret manager answered %d: %s", resp.Status, why)
}
