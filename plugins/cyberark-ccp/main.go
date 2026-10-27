// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command cyberark-ccp is a credentials plugin that fetches one account from
// the CyberArk Central Credential Provider (CCP) REST web service.
//
// Request: GET {base_url}/AIMWebService/api/Accounts?AppID=&Safe=&Object=
// (optionally Folder, UserName, Address). AppID plus at least one other query
// key is required, "+", "&" and "%" are not supported in values. The provider
// authenticates this hub by the AppID and the AppID's allowed-machine list
// only, which are the hub's network identity, not the plugin's: the hub builds
// the client, the plugin only names the account. The hub does not attach a
// client certificate for credential plugins, so per-source client certificates
// are not yet supported and a CCP AppID that requires one cannot be used.
// https://docs.cyberark.com/credential-providers/latest/en/content/ccp/calling-the-web-service-using-rest.htm
// was unreachable to the build's fetch tool. What was verified: the query keys
// (AppID plus Safe, Folder, Object, UserName, Address, Database, PolicyID) and
// the response keys Address, Content, CreationMethod, DeviceType, Folder, Name,
// PasswordChangeInProcess, PolicyID, Safe, Username and LogonDomain, from the
// RETURN block of CyberArk's Ansible module cyberark_credential
// (github.com/cyberark/ansible-security-automation-collection). That block spells
// the user name "Username" and CCP is commonly seen answering "UserName", so a
// mapped field is looked up case-insensitively. The error JSON's ErrorCode was
// not verified against a document; it is only ever read as a short code. No real
// CCP was available (LIVE_RESULTS_CREDENTIAL_SOURCES_v1.1.md).
//
// The record's Content is the credential's secret (password, or a private key
// for an SSH key object) and is returned as the field the reference's "map"
// names; by default Content becomes password, UserName username and Address
// address.
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

func init() { credentials.Register(ccp{}) }

func main() {}

type ccp struct{}

const accountsPath = "/AIMWebService/api/Accounts"

var defaultMap = map[string]string{"Content": "password", "UserName": "username", "Address": "address"}

// referenceKeys are the CCP query keys a reference may set, by the key's name
// in the reference.
var referenceKeys = map[string]string{
	"safe": "Safe", "object": "Object", "folder": "Folder", "username": "UserName", "address": "Address",
}

// errorCode matches CCP's short codes (APPAP004E); anything else is dropped
// because the message text can reflect request parameters.
var errorCode = regexp.MustCompile(`^[A-Z0-9]{3,16}$`)

func query(cred, ref map[string]string) (url.Values, error) {
	appID := strings.TrimSpace(cred["app_id"])
	if appID == "" {
		return nil, errors.New("the source needs an app_id")
	}
	q := url.Values{"AppID": {appID}}
	for key, name := range referenceKeys {
		v := strings.TrimSpace(ref[key])
		if v == "" {
			continue
		}
		// CCP documents these three as unsupported in query values.
		if strings.ContainsAny(v, "+&%") {
			return nil, fmt.Errorf("reference %s may not contain +, & or %%", key)
		}
		q.Set(name, v)
	}
	if q.Get("Object") == "" {
		return nil, errors.New("the reference needs an object (the account name); safe narrows it")
	}
	return q, nil
}

func (ccp) Get(h *delivery.Host, req abi.CredentialsGetRequest) (abi.CredentialsGetResult, error) {
	q, err := query(req.Credential, req.Reference)
	if err != nil {
		return abi.CredentialsGetResult{}, err
	}
	fieldMap, err := credentials.FieldMap(req.Reference["map"], defaultMap)
	if err != nil {
		return abi.CredentialsGetResult{}, err
	}
	base := strings.TrimRight(req.Credential["base_url"], "/")
	resp, err := h.HTTP(abi.HTTPRequest{
		Method:  "GET",
		URL:     base + accountsPath + "?" + q.Encode(),
		Headers: map[string]string{"Accept": "application/json"},
	})
	if err != nil {
		return abi.CredentialsGetResult{}, err
	}
	if resp.Status != 200 {
		return abi.CredentialsGetResult{}, credentials.Failed(resp, failure(resp))
	}
	var record map[string]any
	if err := json.Unmarshal(resp.Body, &record); err != nil {
		return abi.CredentialsGetResult{}, errors.New("the provider answered 200 with a body that is not a JSON account record")
	}
	out := map[string]string{}
	for from, to := range fieldMap {
		v, ok := lookup(record, from)
		if !ok || v == "" {
			continue
		}
		out[to] = v
	}
	if len(out) == 0 {
		return abi.CredentialsGetResult{}, errors.New("the account record has none of the mapped fields (is the map right, and does the account hold a value?)")
	}
	return abi.CredentialsGetResult{Fields: out}, nil
}

// lookup reads a string field by name, ignoring case.
func lookup(record map[string]any, name string) (string, bool) {
	if v, ok := record[name].(string); ok {
		return v, true
	}
	for k, v := range record {
		if s, ok := v.(string); ok && strings.EqualFold(k, name) {
			return s, true
		}
	}
	return "", false
}

// failure turns a non-200 into a short reason without the body: CCP answers
// 404 for an unknown account, 403 for an AppID or machine that is not
// authorised, and 5xx for provider trouble.
func failure(resp abi.HTTPResponse) string {
	reason := "the provider did not return the account"
	switch resp.Status {
	case 403:
		reason = "the AppID, client certificate or machine is not authorised for this account"
	case 404:
		reason = "no such account"
	case 400:
		reason = "the query was rejected"
	}
	var e struct {
		ErrorCode string `json:"ErrorCode"`
	}
	if json.Unmarshal(resp.Body, &e) == nil && errorCode.MatchString(e.ErrorCode) {
		reason += " (" + e.ErrorCode + ")"
	}
	return reason
}
