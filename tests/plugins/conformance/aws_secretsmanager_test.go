// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

// Mock AWS Secrets Manager (JSON 1.1) for the aws-secretsmanager plugin
// (W27-29): DescribeSecret (VersionIdsToStages), PutSecretValue (version id =
// ClientRequestToken, AWSCURRENT moves to it), GetSecretValue by VersionId
// and UpdateSecretVersionStage. The hub verifies by the plugin's read-back,
// so Served is the certificate of the version holding AWSCURRENT.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/plugins/delivery"
)

const awsFirstVersion = "00000000-0000-0000-0000-000000000001"

type awsSMDevice struct {
	ts      *httptest.Server
	ids     []string
	current int // 1-based version holding AWSCURRENT
	*verStore
}

func newAWSSMDevice(t *testing.T) *awsSMDevice {
	d := &awsSMDevice{verStore: newVerStore(t, NewCert(t, "awssm-initial"), NewCert(t, "awssm-stale"))}
	d.reset()
	d.ts = httptest.NewTLSServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.ts.Close)
	return d
}

func (d *awsSMDevice) reset() {
	d.verStore.reset()
	d.ids, d.current = []string{awsFirstVersion}, 1
}

func (d *awsSMDevice) Reset()               { d.mu.Lock(); d.reset(); d.mu.Unlock() }
func (d *awsSMDevice) FailNext(step string) { d.failNext(step) }
func (d *awsSMDevice) Served() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Fingerprint(d.certs[d.current-1])
}

func (d *awsSMDevice) Env() delivery.Env {
	return anyHostEnv(d.ts, map[string]string{"access_key_id": "AKIAEXAMPLE", "secret_access_key": awsSecretKey, "session_token": awsSession, "region": "eu-west-1"},
		[]string{"secret_access_key", "session_token"}, map[string]string{"secret_id": "shop/cert"})
}

func (d *awsSMDevice) version(id string) int {
	for i, v := range d.ids {
		if v == id {
			return i + 1
		}
	}
	return 0
}

func (d *awsSMDevice) serve(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.Host != "secretsmanager.eu-west-1.amazonaws.com" || !awsAuthorized(r, "eu-west-1", "secretsmanager") {
		http.Error(w, "bad signature scope", http.StatusForbidden)
		return
	}
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	fail := func(status int, typ string) { awsJSONErr(w, status, typ) }
	var b struct {
		SecretId, SecretString, ClientRequestToken, VersionId, VersionStage, MoveToVersionId string
		VersionStages                                                                        []string
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	if b.SecretId != "shop/cert" {
		fail(http.StatusBadRequest, "ResourceNotFoundException")
		return
	}
	switch r.Header.Get("X-Amz-Target") {
	case "secretsmanager.DescribeSecret":
		reply(map[string]any{"VersionIdsToStages": map[string][]string{d.ids[d.current-1]: {"AWSCURRENT"}}})
	case "secretsmanager.PutSecretValue":
		var sv struct {
			Certificate string `json:"certificate"`
			PrivateKey  string `json:"private_key"`
		}
		if json.Unmarshal([]byte(b.SecretString), &sv) != nil || sv.PrivateKey == "" || len(b.ClientRequestToken) < 32 ||
			len(b.VersionStages) != 1 || b.VersionStages[0] != "AWSCURRENT" {
			fail(http.StatusBadRequest, "InvalidParameterException")
			return
		}
		n, ok := d.writeLocked(sv.Certificate)
		if !ok {
			fail(http.StatusInternalServerError, "InternalServiceError")
			return
		}
		d.ids, d.current = append(d.ids, b.ClientRequestToken), n
		reply(map[string]any{"VersionId": b.ClientRequestToken, "VersionStages": []string{"AWSCURRENT"}})
	case "secretsmanager.GetSecretValue":
		pem, ok := d.readLocked(d.version(b.VersionId))
		if !ok {
			fail(http.StatusBadRequest, "ResourceNotFoundException")
			return
		}
		s, _ := json.Marshal(map[string]string{"certificate": pem, "private_key": "withheld", "fingerprint_sha256": Fingerprint(pem)})
		reply(map[string]any{"VersionId": b.VersionId, "SecretString": string(s)})
	case "secretsmanager.UpdateSecretVersionStage":
		n := d.version(b.MoveToVersionId)
		if n == 0 || b.VersionStage != "AWSCURRENT" {
			fail(http.StatusBadRequest, "InvalidRequestException")
			return
		}
		if d.fail.take("rollback") {
			fail(http.StatusInternalServerError, "InternalServiceError")
			return
		}
		d.current = n
		reply(map[string]string{"ARN": "arn:x"})
	default:
		fail(http.StatusBadRequest, "UnknownOperationException")
	}
}

func TestAWSSecretsManagerPluginConforms(t *testing.T) {
	rt := newRuntime(t)
	p := Load(t, rt, repoPath(t, "plugins/aws-secretsmanager"))
	if p.Manifest().Verification != abi.VerificationReadback {
		t.Fatal("aws-secretsmanager plugin must declare read-back verification")
	}
	Suite(t, p, newAWSSMDevice(t))
}
