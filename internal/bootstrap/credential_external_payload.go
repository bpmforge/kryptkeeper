// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// Payload assembly for external credentials (W38-07). The hub validates what a
// manager returned against the shape of the consuming credential type, so a
// secret in the wrong shape fails at the fetch with a message naming fields,
// never at a deep SSH or WinRM call, and never echoing a value. Convention:
// the manager's field names are the payload's (a KV secret holding
// private_key_pem, user, host_public_key); a plugin renames with its
// reference "map".

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// sshKeyFields are the ssh_key payload fields an external fetch may fill:
// those of sshCredentialPayload. Anything else the manager holds (notes,
// rotation metadata) is dropped, so a stray field never reaches the payload.
var sshKeyFields = map[string]bool{
	"private_key_pem": true, "host_public_key": true, "user": true, "port": true,
	"keystore_password": true, "keystore_format": true,
	"sudo_mode": true, "sudo_password": true, "helper_sha256": true,
}

// assemblePayload merges static (non-secret, from the credential row) under
// fetched (the manager's fields) and returns the JSON payload for credType.
func assemblePayload(credType string, fetched, static map[string]string) ([]byte, error) {
	merged := make(map[string]string, len(static)+len(fetched))
	for k, v := range static {
		merged[k] = v
	}
	for k, v := range fetched {
		merged[k] = v
	}
	switch credType {
	case CredentialTypeSSHKey:
		return sshKeyPayload(merged)
	case CredentialTypeWindowsPassword:
		// The WinRM installers read their per-target settings from this same
		// blob (IIS ipport and app_id, SQL Server sql_instance and sql_port), so
		// everything else the secret or static holds passes through.
		if err := requireFields(merged, "base_url", "username", "password"); err != nil {
			return nil, err
		}
		return json.Marshal(merged)
	case CredentialTypeAPIToken:
		// A secret holding exactly {"value": "..."} is a raw token string, the
		// form several consumers read; anything else is the JSON object of its
		// fields, which is what plugins, upstream CAs and inventory sources read.
		if v, ok := merged["value"]; ok && len(merged) == 1 && v != "" {
			return []byte(v), nil
		}
		fallthrough
	case CredentialTypeCloudIAM:
		if len(merged) == 0 {
			return nil, errors.New("the secret has no fields")
		}
		return json.Marshal(merged)
	}
	return nil, fmt.Errorf("credential type %q has no external payload shape", credType)
}

func pick(m map[string]string, allowed map[string]bool) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if allowed[k] {
			out[k] = v
		}
	}
	return out
}

func requireFields(m map[string]string, names ...string) error {
	var missing []string
	for _, n := range names {
		if m[n] == "" {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("missing required field(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

// sshKeyPayload builds and validates an ssh_key payload. host_public_key is
// required: the SSH executor refuses to dial unpinned (sshCredentialPayload).
func sshKeyPayload(merged map[string]string) ([]byte, error) {
	keep := pick(merged, sshKeyFields)
	if err := requireFields(keep, "private_key_pem", "user", "host_public_key"); err != nil {
		return nil, err
	}
	out := map[string]any{}
	for k, v := range keep {
		if k == "port" {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || n < 1 || n > 65535 {
				return nil, errors.New("port must be a number between 1 and 65535")
			}
			out[k] = n
			continue
		}
		out[k] = v
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	var p sshCredentialPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		zeroize(raw)
		return nil, errors.New("not the documented ssh_key JSON shape")
	}
	if err := p.validatePrivilege(); err != nil {
		zeroize(raw)
		return nil, err
	}
	return raw, nil
}
