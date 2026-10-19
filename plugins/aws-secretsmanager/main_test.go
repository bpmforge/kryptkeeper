// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

const (
	secretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	sessTok   = "FwoGZXIvYXdzEXAMPLESESSIONTOKEN"
	keyMarker = "TOP-SECRET-KEY-BYTES"
)

func newCert(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

var keyPEM = "-----BEGIN PRIVATE KEY-----\n" + keyMarker + "\n-----END PRIVATE KEY-----\n"

type version struct {
	id     string
	string string
	stages []string
}

// fakeSM models secret versions and staging labels.
type fakeSM struct {
	t          *testing.T
	versions   []*version
	failPut    bool
	failStage  bool
	badReadFP  string // when set, reads of the newest version return this certificate
	calls      []string
	stageMoves int
	logs       []string
}

func (f *fakeSM) host() *delivery.Host { return delivery.NewHost(f.call) }

func (f *fakeSM) seed(certPEM string) {
	id := fmt.Sprintf("%08d-0000-0000-0000-000000000000", len(f.versions)+1)
	v := secretString(certPEM)
	f.versions = append(f.versions, &version{id: id, string: v})
	f.setCurrent(id)
}

func secretString(certPEM string) string {
	b, _ := json.Marshal(secretValue{Certificate: certPEM, PrivateKey: keyPEM, Fingerprint: fingerprint(certPEM)})
	return string(b)
}

func (f *fakeSM) setCurrent(id string) {
	for _, v := range f.versions {
		keep := v.stages[:0]
		for _, s := range v.stages {
			if s != stageCurrent && s != "AWSPREVIOUS" {
				keep = append(keep, s)
			}
		}
		v.stages = keep
	}
	for _, v := range f.versions {
		if v.id == id {
			v.stages = append(v.stages, stageCurrent)
		}
	}
}

func (f *fakeSM) current() string {
	for _, v := range f.versions {
		for _, s := range v.stages {
			if s == stageCurrent {
				return v.id
			}
		}
	}
	return ""
}

func (f *fakeSM) find(id string) *version {
	for _, v := range f.versions {
		if v.id == id {
			return v
		}
	}
	return nil
}

func js(v any) []byte { b, _ := json.Marshal(v); return b }

func (f *fakeSM) call(op string, in []byte) ([]byte, error) {
	if op != abi.HostHTTP {
		f.logs = append(f.logs, string(in))
		return json.Marshal(abi.HostReply{})
	}
	var req abi.HTTPRequest
	if err := json.Unmarshal(in, &req); err != nil {
		f.t.Fatal(err)
	}
	status, body := f.serve(req)
	resp, _ := json.Marshal(abi.HTTPResponse{Status: status, Body: body})
	return json.Marshal(abi.HostReply{Result: resp})
}

func awsErr(status int, typ string) (int, []byte) {
	return status, js(map[string]string{"__type": typ, "message": "leaky " + keyMarker})
}

func (f *fakeSM) serve(req abi.HTTPRequest) (int, []byte) {
	u, _ := url.Parse(req.URL)
	if u.Host != "secretsmanager.eu-west-1.amazonaws.com" || req.Method != "POST" || req.Headers["Content-Type"] != "application/x-amz-json-1.1" {
		f.t.Fatalf("unexpected request %s %s", req.Method, req.URL)
	}
	if a := req.Headers["Authorization"]; !strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/") ||
		!strings.Contains(a, "/eu-west-1/secretsmanager/aws4_request,") || req.Headers["X-Amz-Security-Token"] != sessTok {
		f.t.Errorf("bad Authorization %q", a)
	}
	action := strings.TrimPrefix(req.Headers["X-Amz-Target"], "secretsmanager.")
	f.calls = append(f.calls, action)
	var b struct {
		SecretID, SecretString, ClientRequestToken, VersionID, VersionStage, MoveToVersionID, RemoveFromVersionID string
		VersionStages                                                                                             []string
	}
	var raw map[string]any
	_ = json.Unmarshal(req.Body, &raw)
	b.SecretID, _ = raw["SecretId"].(string)
	b.SecretString, _ = raw["SecretString"].(string)
	b.ClientRequestToken, _ = raw["ClientRequestToken"].(string)
	b.VersionID, _ = raw["VersionId"].(string)
	b.VersionStage, _ = raw["VersionStage"].(string)
	b.MoveToVersionID, _ = raw["MoveToVersionId"].(string)
	b.RemoveFromVersionID, _ = raw["RemoveFromVersionId"].(string)
	if b.SecretID != "shop/cert" {
		return awsErr(400, "ResourceNotFoundException")
	}
	switch action {
	case "DescribeSecret":
		m := map[string][]string{}
		for _, v := range f.versions {
			if len(v.stages) > 0 {
				m[v.id] = v.stages
			}
		}
		return 200, js(map[string]any{"ARN": "arn:x", "VersionIdsToStages": m})
	case "PutSecretValue":
		if f.failPut {
			return awsErr(400, "InternalServiceError")
		}
		if len(b.ClientRequestToken) < 32 {
			f.t.Errorf("ClientRequestToken %q too short", b.ClientRequestToken)
		}
		if st, _ := raw["VersionStages"].([]any); len(st) != 1 || st[0] != stageCurrent {
			f.t.Errorf("VersionStages %v", raw["VersionStages"])
		}
		var sv secretValue
		if json.Unmarshal([]byte(b.SecretString), &sv) != nil || sv.Certificate == "" || sv.PrivateKey == "" || sv.Fingerprint != fingerprint(sv.Certificate) {
			f.t.Errorf("bad SecretString shape")
		}
		if v := f.find(b.ClientRequestToken); v != nil {
			return 200, js(map[string]any{"VersionId": v.id, "VersionStages": v.stages})
		}
		f.versions = append(f.versions, &version{id: b.ClientRequestToken, string: b.SecretString})
		f.setCurrent(b.ClientRequestToken)
		return 200, js(map[string]any{"VersionId": b.ClientRequestToken, "VersionStages": []string{stageCurrent}})
	case "GetSecretValue":
		v := f.find(b.VersionID)
		if v == nil {
			return awsErr(400, "ResourceNotFoundException")
		}
		s := v.string
		if f.badReadFP != "" && v == f.versions[len(f.versions)-1] {
			s = secretString(f.badReadFP)
		}
		return 200, js(map[string]any{"VersionId": v.id, "SecretString": s})
	case "UpdateSecretVersionStage":
		f.stageMoves++
		if f.failStage {
			return awsErr(400, "InternalServiceError")
		}
		if b.VersionStage != stageCurrent || f.current() != b.RemoveFromVersionID || f.find(b.MoveToVersionID) == nil {
			return awsErr(400, "InvalidRequestException")
		}
		f.setCurrent(b.MoveToVersionID)
		return 200, js(map[string]string{"ARN": "arn:x"})
	}
	f.t.Fatalf("unexpected action %q", action)
	return 0, nil
}

func inv() abi.Invocation {
	return abi.Invocation{
		Credential: map[string]string{"access_key_id": "AKIAEXAMPLE", "secret_access_key": secretKey, "session_token": sessTok, "region": "eu-west-1"},
		Target:     map[string]string{"secret_id": "shop/cert"},
	}
}

func push(f *fakeSM, certPEM string) (abi.PushResult, error) {
	return (sm{}).Push(f.host(), abi.PushRequest{Invocation: inv(), Name: "shop", CertPEM: certPEM, KeyPEM: keyPEM})
}

func TestValidate(t *testing.T) {
	f := &fakeSM{t: t}
	f.seed(newCert(t, "old"))
	if err := (sm{}).Validate(f.host(), abi.ValidateRequest{Invocation: inv()}); err != nil {
		t.Fatal(err)
	}
	bad := inv()
	bad.Target["secret_id"] = "not a valid id!"
	if err := (sm{}).Validate(f.host(), abi.ValidateRequest{Invocation: bad}); err == nil {
		t.Error("bad secret_id accepted")
	}
}

func TestSecretsManagerPushStagesAWSCURRENT(t *testing.T) {
	f := &fakeSM{t: t}
	f.seed(newCert(t, "old"))
	prior := f.current()
	cert := newCert(t, "new")
	res, err := push(f, cert)
	if err != nil || !res.Installed || res.Outcome != abi.OutcomeInstalled {
		t.Fatalf("%+v %v", res, err)
	}
	var hd handle
	_ = json.Unmarshal([]byte(res.RollbackHandle), &hd)
	if hd.Prior != prior || hd.New == prior || f.current() != hd.New {
		t.Fatalf("handle %+v current %s", hd, f.current())
	}
	if want := strings.Join([]string{"DescribeSecret", "PutSecretValue", "GetSecretValue"}, ","); strings.Join(f.calls, ",") != want {
		t.Errorf("calls %v", f.calls)
	}
}

func TestSecretsManagerFailureLeavesAWSCURRENTUnchanged(t *testing.T) {
	f := &fakeSM{t: t, failPut: true}
	f.seed(newCert(t, "old"))
	prior := f.current()
	res, _ := push(f, newCert(t, "new"))
	if res.Outcome != abi.OutcomeWriteFailed || res.Installed || f.current() != prior {
		t.Fatalf("%+v", res)
	}
	if strings.Contains(res.Detail, keyMarker) || !strings.Contains(res.Detail, "InternalServiceError") {
		t.Errorf("detail %q", res.Detail)
	}
}

func TestReadbackMismatchMovesAWSCURRENTBack(t *testing.T) {
	f := &fakeSM{t: t, badReadFP: newCert(t, "other")}
	f.seed(newCert(t, "old"))
	prior := f.current()
	res, _ := push(f, newCert(t, "new"))
	if res.Outcome != abi.OutcomeBindingFailed || f.current() != prior || strings.Contains(res.Detail, "RESTORE FAILED") {
		t.Fatalf("%+v current %s", res, f.current())
	}
}

func TestReadbackMismatchRestoreFailureIsReported(t *testing.T) {
	f := &fakeSM{t: t, badReadFP: newCert(t, "other"), failStage: true}
	f.seed(newCert(t, "old"))
	res, _ := push(f, newCert(t, "new"))
	if res.Outcome != abi.OutcomeBindingFailed || !strings.Contains(res.Detail, "RESTORE FAILED") {
		t.Fatalf("%+v", res)
	}
}

func TestFirstVersionHasNothingToRestore(t *testing.T) {
	f := &fakeSM{t: t, badReadFP: newCert(t, "other")}
	res, _ := push(f, newCert(t, "new"))
	if res.Outcome != abi.OutcomeBindingFailed || !strings.Contains(res.Detail, "no previous version") || f.stageMoves != 0 {
		t.Fatalf("%+v", res)
	}
	f = &fakeSM{t: t}
	res, _ = push(f, newCert(t, "new"))
	rb, _ := (sm{}).Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	if rb.RolledBack || rb.Detail != "no previous version" {
		t.Fatalf("%+v", rb)
	}
}

func TestRollbackMovesAWSCURRENTBack(t *testing.T) {
	f := &fakeSM{t: t}
	f.seed(newCert(t, "old"))
	prior := f.current()
	res, _ := push(f, newCert(t, "new"))
	rb, _ := (sm{}).Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	if !rb.RolledBack || f.current() != prior {
		t.Fatalf("%+v current %s", rb, f.current())
	}
}

func TestRollbackFailureNotReportedAsRolledBack(t *testing.T) {
	f := &fakeSM{t: t}
	f.seed(newCert(t, "old"))
	res, _ := push(f, newCert(t, "new"))
	f.failStage = true
	rb, _ := (sm{}).Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	if rb.RolledBack || rb.Detail == "" {
		t.Fatalf("%+v", rb)
	}
}

func TestRedeliveringSameCertificateIsIdempotent(t *testing.T) {
	f := &fakeSM{t: t}
	f.seed(newCert(t, "old"))
	cert := newCert(t, "new")
	if res, _ := push(f, cert); !res.Installed {
		t.Fatalf("%+v", res)
	}
	n := len(f.versions)
	res, _ := push(f, cert)
	var hd handle
	_ = json.Unmarshal([]byte(res.RollbackHandle), &hd)
	if !res.Installed || len(f.versions) != n || hd.Prior != "" {
		t.Fatalf("%+v versions %d", res, len(f.versions))
	}
}

func TestVerifyReturnsOnlyCertificateOfWrittenVersion(t *testing.T) {
	f := &fakeSM{t: t}
	f.seed(newCert(t, "old"))
	chain := newCert(t, "new") + newCert(t, "ca")
	res, _ := push(f, chain)
	v, err := (sm{}).Verify(f.host(), abi.VerifyRequest{Invocation: inv(), Name: "shop", Handle: res.RollbackHandle})
	if err != nil {
		t.Fatal(err)
	}
	if v.CertPEM != chain || strings.Contains(v.CertPEM, "PRIVATE") || strings.Contains(v.CertPEM, keyMarker) {
		t.Fatalf("verify returned %q", v.CertPEM)
	}
	// A newer version appearing later must not change what is verified.
	f.seed(newCert(t, "later"))
	v2, _ := (sm{}).Verify(f.host(), abi.VerifyRequest{Invocation: inv(), Handle: res.RollbackHandle})
	if v2.CertPEM != chain {
		t.Error("Verify read a version other than the one Push wrote")
	}
	if _, err := (sm{}).Verify(f.host(), abi.VerifyRequest{Invocation: inv(), Handle: `{"new":"x"}`}); err == nil {
		t.Error("bad handle accepted")
	}
}

func TestSecretsNeverInOutput(t *testing.T) {
	f := &fakeSM{t: t, failPut: true}
	f.seed(newCert(t, "old"))
	res, _ := push(f, newCert(t, "new"))
	out := []string{res.Detail}
	f.failPut = false
	f.badReadFP = newCert(t, "other")
	f.failStage = true
	res, _ = push(f, newCert(t, "new2"))
	out = append(out, res.Detail)
	f.badReadFP, f.failStage = "", false
	res, _ = push(f, newCert(t, "new3"))
	out = append(out, res.RollbackHandle)
	bad := inv()
	bad.Target["secret_id"] = "missing"
	err := (sm{}).Validate(f.host(), abi.ValidateRequest{Invocation: bad})
	out = append(out, err.Error())
	for _, s := range out {
		if strings.Contains(s, secretKey) || strings.Contains(s, sessTok) || strings.Contains(s, keyMarker) || strings.Contains(s, "BEGIN") {
			t.Errorf("secret material in %q", s)
		}
	}
	for _, l := range f.logs {
		if strings.Contains(l, secretKey) || strings.Contains(l, keyMarker) {
			t.Error("secret in log")
		}
	}
}

func TestRejectsUnknownRegion(t *testing.T) {
	in := inv()
	in.Credential["region"] = "mars-north-1"
	if _, err := newClient(nil, in); err == nil {
		t.Fatal("accepted")
	}
}

func TestManifestHostsMatchRegions(t *testing.T) {
	raw, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := abi.ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Verification != abi.VerificationReadback {
		t.Error("must declare readback verification")
	}
	have := map[string]bool{}
	for _, h := range m.Capabilities.Network.Hosts {
		have[h] = true
	}
	for r := range regions {
		if !have["secretsmanager."+r+".amazonaws.com"] {
			t.Errorf("manifest lacks region %s", r)
		}
	}
	if len(have) != len(regions) {
		t.Errorf("%d hosts for %d regions", len(have), len(regions))
	}
}
