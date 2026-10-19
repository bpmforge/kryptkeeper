// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

const (
	vaultScope = "https://vault.azure.net/.default"
	armScope   = "https://management.azure.com/.default"
)

// az holds one invocation's host and the tokens it has fetched.
type az struct {
	h      *delivery.Host
	inv    abi.Invocation
	tokens map[string]string
}

func newAZ(h *delivery.Host, inv abi.Invocation) *az {
	return &az{h: h, inv: inv, tokens: map[string]string{}}
}

// token runs the client-credentials grant for one scope. Failures carry the
// status only: the request and response hold the client secret.
func (z *az) token(scope string) (string, error) {
	if t := z.tokens[scope]; t != "" {
		return t, nil
	}
	cr := z.inv.Credential
	form := url.Values{
		"grant_type": {"client_credentials"}, "client_id": {cr["client_id"]},
		"client_secret": {cr["client_secret"]}, "scope": {scope},
	}
	resp, err := z.h.HTTP(abi.HTTPRequest{
		Method: "POST", URL: "https://login.microsoftonline.com/" + url.PathEscape(cr["tenant_id"]) + "/oauth2/v2.0/token",
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, Body: []byte(form.Encode()),
	})
	if err != nil {
		return "", errors.New("token request: " + err.Error())
	}
	if resp.Status != 200 {
		return "", fmt.Errorf("token request: HTTP %d", resp.Status)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(resp.Body, &tr) != nil || tr.AccessToken == "" {
		return "", errors.New("token request: no access_token in response")
	}
	z.tokens[scope] = tr.AccessToken
	return tr.AccessToken, nil
}
