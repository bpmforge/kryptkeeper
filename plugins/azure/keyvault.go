// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

const kvAPI = "7.4"

// imported is the Key Vault import result: the new certificate version and
// its versioned secret id.
type imported struct{ Version, SID string }

func (z *az) vaultBase() string { return strings.TrimRight(z.inv.Credential["vault_url"], "/") }

// kv sends a Key Vault request. Errors carry method, path, status and the
// service error code, never a body (request bodies carry the key).
func (z *az) kv(method, path string, body any, want int) ([]byte, error) {
	tok, err := z.token(vaultScope)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{"Authorization": "Bearer " + tok}
	var raw []byte
	if body != nil {
		if raw, err = json.Marshal(body); err != nil {
			return nil, err
		}
		headers["Content-Type"] = "application/json"
	}
	resp, err := z.h.HTTP(abi.HTTPRequest{Method: method, URL: z.vaultBase() + path, Headers: headers, Body: raw})
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, strings.SplitN(path, "?", 2)[0], err)
	}
	if resp.Status != want {
		return nil, fmt.Errorf("%s %s: HTTP %d%s", method, strings.SplitN(path, "?", 2)[0], resp.Status, errCode(resp.Body))
	}
	return resp.Body, nil
}

func (z *az) listCertificates() error {
	_, err := z.kv("GET", "/certificates?api-version="+kvAPI+"&maxresults=1", nil, 200)
	return err
}

// importCert imports bundlePEM (certificate chain then PKCS#8 key) as a new
// version of the named certificate. The response's cer (DER) must hash to the
// leaf fingerprint, which proves the vault stored what was sent.
func (z *az) importCert(name, bundlePEM, fp string) (imported, error) {
	body, err := z.kv("POST", "/certificates/"+name+"/import?api-version="+kvAPI, map[string]any{
		"value":  base64.StdEncoding.EncodeToString([]byte(bundlePEM)),
		"policy": map[string]any{"secret_props": map[string]string{"contentType": "application/x-pem-file"}},
	}, 200)
	if err != nil {
		return imported{}, err
	}
	var r struct {
		ID  string `json:"id"`
		SID string `json:"sid"`
		Cer string `json:"cer"`
	}
	if json.Unmarshal(body, &r) != nil {
		return imported{}, errors.New("import response unreadable")
	}
	der, err := base64.StdEncoding.DecodeString(r.Cer)
	if err != nil || len(der) == 0 {
		return imported{}, errors.New("import response carried no certificate")
	}
	if sha256Hex(der) != fp {
		return imported{}, errors.New("vault stored a certificate that does not match the one pushed")
	}
	version := r.ID[strings.LastIndex(r.ID, "/")+1:]
	wantSID := z.vaultBase() + "/secrets/" + name + "/" + version
	if !versionPattern.MatchString(version) || !bytes.Equal([]byte(r.SID), []byte(wantSID)) {
		return imported{}, errors.New("import response carried no usable secret version id")
	}
	return imported{Version: version, SID: r.SID}, nil
}
