// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package tenantidor

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Roles every tenant gets one API key for. The attackers are the acme set; the
// globex set exists so victim data is created by realistic owners.
var Roles = []string{"pki-admin", "pki-operator", "viewer", "auditor"}

const (
	AttackerTenant = "acme"
	VictimTenant   = "globex"
)

// Fixture is the seeded world: who attacks, what they attack, and what could
// not be seeded.
type Fixture struct {
	Attackers   []Principal
	VictimAdmin Principal
	Victim      VictimSet
	// Collections maps a path collection ("cas", "ssh/certificates") to a
	// victim identifier substituted into {param} segments after it.
	Collections map[string]string
	// ids by logical name, for body overrides (ca, template, cert, cred, scan).
	ids     map[string]string
	Skipped []string
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing is unrecoverable
	}
	return hex.EncodeToString(b)
}

// Seed builds tenants, 8 API keys and the victim data through the real API
// using the bootstrap token. Families that cannot be created offline are
// recorded in Skipped rather than failing the run; tenants and keys are
// mandatory.
func Seed(c *apiClient, bootstrapToken string) (*Fixture, error) {
	marker := "idor-" + randHex(4)
	f := &Fixture{
		Victim:      VictimSet{Marker: marker, IDs: map[string]bool{}, Tenant: VictimTenant},
		Collections: map[string]string{},
		ids:         map[string]string{},
	}
	for _, t := range []string{AttackerTenant, VictimTenant} {
		// A reused (postgres) database already has the tenants: 409 is fine.
		if _, st, err := c.postJSON(bootstrapToken, "/api/v1/tenants", map[string]any{"id": t, "name": t}); err != nil && st != 409 {
			return nil, fmt.Errorf("create tenant %s: %w", t, err)
		}
	}
	for _, t := range []string{AttackerTenant, VictimTenant} {
		for _, role := range Roles {
			// Only the victim's names carry the marker: an attacker whose own
			// principal id contained it would see it echoed back by whoami
			// and every list of its own keys, a false positive.
			pfx := marker
			if t == AttackerTenant {
				pfx = "atk-" + randHex(3)
			}
			name := fmt.Sprintf("%s-%s-%s", pfx, t, role)
			out, _, err := c.postJSON(bootstrapToken, "/api/v1/api-keys", map[string]any{
				"name": name, "principal_id": name, "role": role, "scopes": []string{"*"}, "tenant": t,
			})
			if err != nil {
				return nil, fmt.Errorf("mint %s/%s key: %w", t, role, err)
			}
			tok := dig(out, "data", "token")
			if tok == "" {
				return nil, fmt.Errorf("mint %s/%s key: response carried no token", t, role)
			}
			p := Principal{Tenant: t, Role: role, Token: tok}
			switch {
			case t == AttackerTenant:
				f.Attackers = append(f.Attackers, p)
			case role == "pki-admin":
				f.VictimAdmin = p
			}
			if t == VictimTenant {
				f.Victim.IDs[dig(out, "data", "kid")] = true
			}
		}
	}
	f.seedVictimData(c)
	delete(f.Victim.IDs, "")
	return f, nil
}

// family creates one victim resource, records its id, or notes a skip.
func (f *Fixture) family(c *apiClient, name, path string, body map[string]any, idKeys []string, collection string) string {
	out, _, err := c.postJSON(f.VictimAdmin.Token, path, body)
	if err != nil {
		f.Skipped = append(f.Skipped, fmt.Sprintf("seed-skip %s (%v)", name, err))
		return ""
	}
	id := dig(out, append([]string{"data"}, idKeys...)...)
	if id == "" {
		f.Skipped = append(f.Skipped, "seed-skip "+name+" (no id in response)")
		return ""
	}
	f.Victim.IDs[id] = true
	f.ids[name] = id
	if collection != "" {
		f.Collections[collection] = id
	}
	return id
}

func (f *Fixture) seedVictimData(c *apiClient) {
	m := f.Victim.Marker
	ca := f.family(c, "ca", "/api/v1/cas", map[string]any{"name": m + "-ca", "type": "root", "algorithm": "ECDSA-P256", "subject_cn": m + "-ca"}, []string{"id"}, "cas")
	tpl := f.family(c, "template", "/api/v1/templates", map[string]any{
		"name": m + "-tpl", "display_name": m + "-tpl", "validity_period": "P30D", "key_usage": []string{"digitalSignature"},
		"extended_key_usage": []string{"serverAuth"}, "allowed_algorithms": []string{"ECDSA"}, "active": true,
	}, []string{"id"}, "templates")
	var fp string
	if ca != "" && tpl != "" {
		if csr, err := newCSR(m + ".example.test"); err == nil {
			fp = f.family(c, "certificate", "/api/v1/certificates", map[string]any{"ca_id": ca, "template_id": tpl, "csr_pem": csr}, []string{"fingerprint_sha256"}, "certificates")
		}
	} else {
		f.Skipped = append(f.Skipped, "seed-skip certificate (needs ca and template)")
	}
	if ca != "" {
		// The keystore names a CA's key key-<ca id>.
		f.Victim.IDs["key-"+ca] = true
		f.Collections["keys"] = "key-" + ca
	}
	f.family(c, "role", "/api/v1/roles", map[string]any{"name": m + "-role", "permissions": []string{"certificate.read"}}, []string{"name"}, "roles")
	f.family(c, "api-key", "/api/v1/api-keys", map[string]any{"name": m + "-key", "principal_id": m + "-key", "role": "viewer", "scopes": []string{"*"}, "tenant": VictimTenant}, []string{"kid"}, "api-keys")
	f.family(c, "notification-rule", "/api/v1/notifications/rules", map[string]any{"name": m + "-rule", "threshold_days": 30, "channel": "webhook", "target": "https://" + m + ".example.test/hook"}, []string{"id"}, "rules")
	silTarget := tpl
	if silTarget == "" {
		silTarget = m + "-target"
	}
	f.family(c, "notification-silence", "/api/v1/notifications/silences", map[string]any{"target_type": "template", "target_id": silTarget}, []string{"id"}, "silences")
	f.family(c, "credential", "/api/v1/credentials", map[string]any{"name": m + "-cred", "credential_type": "api_token", "payload": map[string]any{"token": "x"}}, []string{"id"}, "credentials")
	f.family(c, "target", "/api/v1/targets", map[string]any{"name": m + "-target", "host": m + ".example.test"}, []string{"id"}, "targets")
	f.family(c, "connector", "/api/v1/connectors", map[string]any{"name": m + "-conn", "type": "internal"}, []string{"id"}, "connectors")
	f.family(c, "inventory-source", "/api/v1/inventory-sources", map[string]any{"name": m + "-inv", "type": "adcs_export", "config_json": "{}"}, []string{"id"}, "inventory-sources")
	if fp != "" {
		f.family(c, "pending-action", "/api/v1/pending-actions", map[string]any{"action_type": "revoke", "rationale": m + "-pa", "params": map[string]any{"fingerprint": fp}}, []string{"id"}, "pending-actions")
	} else {
		f.Skipped = append(f.Skipped, "seed-skip pending-action (needs certificate)")
	}
	// Loopback port 1: the scan fails fast and harmlessly; only the job row matters.
	f.family(c, "discovery-scan", "/api/v1/discovery/scans", map[string]any{"scan_type": "targeted", "target": "127.0.0.1:1"}, []string{"scan_job", "id"}, "scan-jobs")
	f.seedSSH(c)
	for _, fam := range []string{"approval-request"} {
		// Approvals are created only by an approval-gated issuance that a
		// second principal then acts on; out of scope for this offline seed.
		f.Skipped = append(f.Skipped, "seed-skip "+fam+" (needs a second named approver)")
	}
}

func (f *Fixture) seedSSH(c *apiClient) {
	m := f.Victim.Marker
	tpl := f.family(c, "ssh-template", "/api/v1/templates", map[string]any{
		"name": m + "-sshtpl", "display_name": m + "-sshtpl", "validity_period": "P1D", "key_usage": []string{"digitalSignature"}, "extended_key_usage": []string{"clientAuth"},
		"allowed_algorithms": []string{"ECDSA"}, "active": true,
		"ssh_policy": map[string]any{"cert_types": []string{"user"}, "allowed_principals": []string{"idoruser"}, "max_ttl_hours": 2},
	}, []string{"id"}, "")
	if tpl == "" {
		f.Skipped = append(f.Skipped, "seed-skip ssh-certificate (no ssh template)")
		return
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Skipped = append(f.Skipped, "seed-skip ssh-certificate (keygen)")
		return
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		f.Skipped = append(f.Skipped, "seed-skip ssh-certificate (pubkey)")
		return
	}
	id := f.family(c, "ssh-certificate", "/api/v1/ssh/certificates", map[string]any{
		"template_id": tpl, "public_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))), "cert_type": "user",
		"key_id": m + "-sshcert", "principals": []string{"idoruser"}, "ttl_hours": 1,
	}, []string{"serial"}, "ssh/certificates")
	_ = id
}

// newCSR returns a PEM PKCS#10 request for cn. No private key leaves this
// function: the harness never needs the certificate's key.
func newCSR(cn string) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}
