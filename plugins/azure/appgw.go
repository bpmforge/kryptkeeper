// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
)

const appGWAPI = "2023-09-01"

// appGW binds the Key Vault secret id of one SSL certificate on an
// Application Gateway.
type appGW struct {
	z *az
	c config
}

func (g *appGW) path() string {
	return "/subscriptions/" + g.c.sub + "/resourceGroups/" + g.c.group +
		"/providers/Microsoft.Network/applicationGateways/" + g.c.gateway + "?api-version=" + appGWAPI
}

// sslCertificate returns the properties map of the named certificate.
func (g *appGW) sslCertificate(d doc) (doc, error) {
	list, _ := dig(d, "properties")["sslCertificates"].([]any)
	for _, it := range list {
		m, _ := it.(map[string]any)
		if n, _ := m["name"].(string); n == g.c.sslCert {
			p, _ := m["properties"].(map[string]any)
			if p == nil {
				p = map[string]any{}
				m["properties"] = p
			}
			return p, nil
		}
	}
	return nil, fmt.Errorf("gateway has no ssl certificate named %q", g.c.sslCert)
}

func (g *appGW) current() (string, error) {
	d, err := g.z.armGet(g.path())
	if err != nil {
		return "", err
	}
	p, err := g.sslCertificate(d)
	if err != nil {
		return "", err
	}
	id, _ := p["keyVaultSecretId"].(string)
	if id == "" {
		return "", errors.New("ssl certificate is not backed by a Key Vault secret")
	}
	return id, nil
}

func (g *appGW) value(imp imported) string { return imp.SID }

// set takes a fresh copy of the gateway, changes only keyVaultSecretId and
// PUTs the whole document back.
func (g *appGW) set(secretID string) error {
	d, err := g.z.armGet(g.path())
	if err != nil {
		return err
	}
	p, err := g.sslCertificate(d)
	if err != nil {
		return err
	}
	p["keyVaultSecretId"] = secretID
	return g.z.armPut(g.path(), d)
}
