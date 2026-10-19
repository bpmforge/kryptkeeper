// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package tenantidor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// requestTimeout bounds every probe. It is short on purpose: an SSE route
// (GET /events) streams forever, and the partial body read before the
// deadline is still judged.
const requestTimeout = 3 * time.Second

type apiClient struct {
	base string
	hc   *http.Client
}

func newClient(base string) *apiClient {
	return &apiClient{base: base, hc: &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// do sends one request and returns status and body. A timeout while reading
// the body is not an error: the bytes received so far are returned.
func (c *apiClient) do(token, method, path string, body []byte) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, data, nil
}

// postJSON marshals v, expects a 2xx and returns the parsed body.
func (c *apiClient) postJSON(token, path string, v any) (map[string]any, int, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, 0, err
	}
	st, data, err := c.do(token, http.MethodPost, path, raw)
	if err != nil {
		return nil, st, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		out = nil // non-JSON error body; dig() tolerates a nil map
	}
	if st < 200 || st > 299 {
		return out, st, fmt.Errorf("POST %s -> %d %s", path, st, dig(out, "message"))
	}
	return out, st, nil
}

// dig walks nested map keys, returning "" when any hop is missing.
func dig(m map[string]any, keys ...string) string {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[k]
	}
	s, _ := cur.(string)
	return s
}
