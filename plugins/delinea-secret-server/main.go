// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command delinea-secret-server is a credentials plugin that fetches one
// secret from Delinea Secret Server (on-premises or Secret Server Cloud with
// a Secret Server application account).
//
// Token: POST {base_url}/oauth2/token with form fields grant_type=password,
// username and password (and domain when the account is a domain account);
// the answer's access_token goes in "Authorization: Bearer". Secret:
// GET {base_url}/api/v1/secrets/{id}, whose JSON carries items[] with slug
// and itemValue per field.
// https://docs.delinea.com/online-help/secret-server-11-6-x/api-scripting/authenticating/index.htm
// https://docs.delinea.com/online-help/secret-server-11-6-x/api-scripting/rest-api-python3-scripts/index.htm
//
// Delinea Platform tenants that authenticate Secret Server calls through the
// Platform's client-credentials flow are not covered; this plugin speaks the
// Secret Server application account flow only.
//
// The reference's secret_id picks the secret and its "map" says which item
// slug fills which payload field ("private-key:private_key_pem,username:user");
// by default username and password map to themselves. Items with no value are
// skipped, and a secret that yields no mapped field is an error.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/credentials"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

func init() { credentials.Register(delinea{}) }

func main() {}

type delinea struct{}

var (
	defaultMap = map[string]string{"username": "username", "password": "password"}
	secretID   = regexp.MustCompile(`^[0-9]{1,10}$`)
)

func (delinea) Get(h *delivery.Host, req abi.CredentialsGetRequest) (abi.CredentialsGetResult, error) {
	id := strings.TrimSpace(req.Reference["secret_id"])
	if !secretID.MatchString(id) {
		return abi.CredentialsGetResult{}, errors.New("the reference needs a numeric secret_id")
	}
	fieldMap, err := credentials.FieldMap(req.Reference["map"], defaultMap)
	if err != nil {
		return abi.CredentialsGetResult{}, err
	}
	base := strings.TrimRight(req.Credential["base_url"], "/")

	token, err := login(h, base, req.Credential)
	if err != nil {
		return abi.CredentialsGetResult{}, err
	}
	resp, err := h.HTTP(abi.HTTPRequest{
		Method:  "GET",
		URL:     base + "/api/v1/secrets/" + id,
		Headers: map[string]string{"Authorization": "Bearer " + token, "Accept": "application/json"},
	})
	if err != nil {
		return abi.CredentialsGetResult{}, err
	}
	if resp.Status != 200 {
		return abi.CredentialsGetResult{}, credentials.Failed(resp, secretFailure(resp.Status))
	}
	var secret struct {
		Items []struct {
			Slug      string `json:"slug"`
			ItemValue string `json:"itemValue"`
		} `json:"items"`
	}
	if err := json.Unmarshal(resp.Body, &secret); err != nil {
		return abi.CredentialsGetResult{}, errors.New("Secret Server answered 200 with a body that is not a secret record")
	}
	out := map[string]string{}
	for _, it := range secret.Items {
		to, ok := fieldMap[it.Slug]
		if !ok || it.ItemValue == "" {
			continue
		}
		out[to] = it.ItemValue
	}
	if len(out) == 0 {
		return abi.CredentialsGetResult{}, errors.New("the secret has no value for any mapped item slug (is the map right, and is the item filled in?)")
	}
	return abi.CredentialsGetResult{Fields: out}, nil
}

// login exchanges the source's application account for a bearer token. Every
// failure reports a status and a reason, never the response: a token endpoint
// reflects the username.
func login(h *delivery.Host, base string, cred map[string]string) (string, error) {
	form := url.Values{"grant_type": {"password"}, "username": {cred["username"]}, "password": {cred["password"]}}
	if d := strings.TrimSpace(cred["domain"]); d != "" {
		form.Set("domain", d)
	}
	resp, err := h.HTTP(abi.HTTPRequest{
		Method:  "POST",
		URL:     base + "/oauth2/token",
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
		Body:    []byte(form.Encode()),
	})
	if err != nil {
		return "", err
	}
	if resp.Status != 200 {
		return "", credentials.Failed(resp, "the application account could not log in")
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(resp.Body, &tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("Secret Server answered 200 to the token request without an access_token")
	}
	return tok.AccessToken, nil
}

func secretFailure(status int) string {
	switch status {
	case 401:
		return "the token was refused"
	case 403:
		return "the application account may not view this secret"
	case 404:
		return "no such secret"
	}
	return "Secret Server did not return the secret"
}
