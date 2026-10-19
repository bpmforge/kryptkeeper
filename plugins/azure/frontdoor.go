// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import "errors"

const frontDoorAPI = "2023-05-01"

// frontDoor binds the Key Vault certificate version of one existing Front
// Door secret. The secret must already exist and be attached to a custom
// domain; only its version is swapped.
type frontDoor struct {
	z *az
	c config
}

func (f *frontDoor) path() string {
	return "/subscriptions/" + f.c.sub + "/resourceGroups/" + f.c.group +
		"/providers/Microsoft.Cdn/profiles/" + f.c.profile + "/secrets/" + f.c.secret + "?api-version=" + frontDoorAPI
}

func (f *frontDoor) parameters(d doc) (doc, error) {
	p := dig(d, "properties", "parameters")
	if t, _ := p["type"].(string); t != "CustomerCertificate" {
		return nil, errors.New("front door secret is not a CustomerCertificate")
	}
	return p, nil
}

// current is the pinned version, "" when the secret follows the latest.
func (f *frontDoor) current() (string, error) {
	d, err := f.z.armGet(f.path())
	if err != nil {
		return "", err
	}
	p, err := f.parameters(d)
	if err != nil {
		return "", err
	}
	v, _ := p["secretVersion"].(string)
	return v, nil
}

func (f *frontDoor) value(imp imported) string { return imp.Version }

func (f *frontDoor) set(version string) error {
	d, err := f.z.armGet(f.path())
	if err != nil {
		return err
	}
	p, err := f.parameters(d)
	if err != nil {
		return err
	}
	src, _ := dig(p, "secretSource")["id"].(string)
	if src == "" {
		return errors.New("front door secret has no secretSource id")
	}
	d["properties"].(map[string]any)["parameters"] = doc{
		"type": "CustomerCertificate", "secretSource": doc{"id": src}, "secretVersion": version, "useLatestVersion": false,
	}
	return f.z.armPut(f.path(), d)
}
