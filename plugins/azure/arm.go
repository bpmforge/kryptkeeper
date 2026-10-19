// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

// sleep is injectable so provisioning polls are instant in tests.
var sleep = time.Sleep

const (
	pollEvery = 5 * time.Second
	maxPolls  = 20
	armBase   = "https://management.azure.com"
)

// doc is an ARM resource kept as a generic map; a typed struct would drop
// the fields it does not know on PUT.
type doc = map[string]any

func (z *az) arm(method, path string, body doc) (abi.HTTPResponse, error) {
	tok, err := z.token(armScope)
	if err != nil {
		return abi.HTTPResponse{}, err
	}
	headers := map[string]string{"Authorization": "Bearer " + tok}
	var raw []byte
	if body != nil {
		if raw, err = json.Marshal(body); err != nil {
			return abi.HTTPResponse{}, err
		}
		headers["Content-Type"] = "application/json"
	}
	resp, err := z.h.HTTP(abi.HTTPRequest{Method: method, URL: armBase + path, Headers: headers, Body: raw})
	if err != nil {
		return resp, fmt.Errorf("ARM %s: %w", method, err)
	}
	return resp, nil
}

// armGet reads the resource at path (which includes ?api-version=).
func (z *az) armGet(path string) (doc, error) {
	resp, err := z.arm("GET", path, nil)
	if err != nil {
		return nil, err
	}
	if resp.Status != 200 {
		return nil, fmt.Errorf("ARM GET: HTTP %d%s", resp.Status, errCode(resp.Body))
	}
	dec := json.NewDecoder(bytes.NewReader(resp.Body))
	dec.UseNumber()
	var d doc
	if dec.Decode(&d) != nil || d == nil {
		return nil, errors.New("ARM GET: resource unreadable")
	}
	return d, nil
}

// armPut writes d back and then waits for provisioning to finish.
func (z *az) armPut(path string, d doc) error {
	resp, err := z.arm("PUT", path, d)
	if err != nil {
		return err
	}
	switch resp.Status {
	case 200, 201, 202:
	default:
		return fmt.Errorf("ARM PUT: HTTP %d%s", resp.Status, errCode(resp.Body))
	}
	return z.awaitProvisioned(path)
}

// awaitProvisioned polls the resource until provisioningState is Succeeded.
// Only the state is read; polls never log bodies.
func (z *az) awaitProvisioned(path string) error {
	for i := 0; i < maxPolls; i++ {
		d, err := z.armGet(path)
		if err != nil {
			return err
		}
		state, _ := dig(d, "properties")["provisioningState"].(string)
		switch state {
		case "Succeeded":
			return nil
		case "Failed", "Canceled":
			return fmt.Errorf("provisioning %s", state)
		}
		sleep(pollEvery)
	}
	return fmt.Errorf("provisioning still Updating after %d polls", maxPolls)
}

// dig returns the nested map at keys, or nil.
func dig(d doc, keys ...string) doc {
	cur := d
	for _, k := range keys {
		next, _ := cur[k].(map[string]any)
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}
