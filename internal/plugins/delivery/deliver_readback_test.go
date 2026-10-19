// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/agentinstall"
)

func testLeaf(t *testing.T, cn string) (certPEM, fp string) {
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
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), hex.EncodeToString(sum[:])
}

// readbackPlugin is a Plugin whose wasm calls are scripted.
type readbackPlugin struct {
	*Plugin
	ops      []string
	verifyFn func() (abi.VerifyResult, error)
	verifyN  int
	handle   string
}

func newReadbackPlugin(verification string) *readbackPlugin {
	rp := &readbackPlugin{handle: "v7"}
	rp.Plugin = &Plugin{manifest: abi.Manifest{Verification: verification}, granted: abi.Capabilities{}}
	rp.invokeHook = func(_ context.Context, op string, in []byte) ([]byte, error) {
		rp.ops = append(rp.ops, op)
		var out any
		switch op {
		case abi.OpPush:
			out = abi.PushResult{Installed: true, Outcome: abi.OutcomeInstalled, RollbackHandle: rp.handle}
		case abi.OpVerify:
			rp.verifyN++
			var vr abi.VerifyRequest
			_ = json.Unmarshal(in, &vr)
			if vr.Handle != rp.handle {
				return json.Marshal(abi.Response{Error: "wrong handle " + vr.Handle})
			}
			r, err := rp.verifyFn()
			if err != nil {
				return json.Marshal(abi.Response{Error: err.Error()})
			}
			out = r
		case abi.OpRollback:
			out = abi.RollbackResult{RolledBack: true}
		}
		res, _ := json.Marshal(out)
		return json.Marshal(abi.Response{Result: res})
	}
	return rp
}

func (rp *readbackPlugin) rolledBack() bool {
	for _, o := range rp.ops {
		if o == abi.OpRollback {
			return true
		}
	}
	return false
}

func readbackReq(fp string) DeliverRequest {
	return DeliverRequest{Name: "n", CertPEM: []byte("x"), ExpectedFingerprint: fp, ReadbackVerify: true}
}

func TestReadbackMatchIsVerified(t *testing.T) {
	newPEM, newFP := testLeaf(t, "new")
	rp := newReadbackPlugin("readback")
	rp.verifyFn = func() (abi.VerifyResult, error) { return abi.VerifyResult{CertPEM: newPEM}, nil }
	res := rp.Deliver(context.Background(), Env{}, readbackReq(strings.ToUpper(newFP)), nil)
	if !res.Verified || res.Outcome != agentinstall.OutcomeInstalledVerified || res.ServedFingerprint != newFP || res.RolledBack {
		t.Fatalf("expected installed_verified: %+v", res)
	}
	if rp.rolledBack() {
		t.Error("rollback ran on a verified delivery")
	}
	if !strings.Contains(res.Detail, "store read-back") {
		t.Errorf("detail %q", res.Detail)
	}
}

func TestReadbackOldLeafFailsAndRollsBack(t *testing.T) {
	oldPEM, _ := testLeaf(t, "old")
	_, newFP := testLeaf(t, "new")
	rp := newReadbackPlugin("readback")
	rp.verifyFn = func() (abi.VerifyResult, error) { return abi.VerifyResult{CertPEM: oldPEM}, nil }
	res := rp.Deliver(context.Background(), Env{}, readbackReq(newFP), nil)
	if res.Verified || res.Outcome != agentinstall.OutcomeVerifyFailed || !res.RolledBack || !rp.rolledBack() {
		t.Fatalf("expected verify_failed + rollback: %+v", res)
	}
	if rp.verifyN != verifyAttempts {
		t.Errorf("verify attempts %d, want %d", rp.verifyN, verifyAttempts)
	}
}

func TestReadbackGarbageAndErrorFailClosed(t *testing.T) {
	_, newFP := testLeaf(t, "new")
	for name, fn := range map[string]func() (abi.VerifyResult, error){
		"garbage": func() (abi.VerifyResult, error) { return abi.VerifyResult{CertPEM: "not a pem"}, nil },
		"empty":   func() (abi.VerifyResult, error) { return abi.VerifyResult{}, nil },
		"bad der": func() (abi.VerifyResult, error) {
			return abi.VerifyResult{CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}))}, nil
		},
		"op error": func() (abi.VerifyResult, error) { return abi.VerifyResult{}, errors.New("store down") },
		"key not cert": func() (abi.VerifyResult, error) {
			return abi.VerifyResult{CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("k")}))}, nil
		},
	} {
		rp := newReadbackPlugin("readback")
		rp.verifyFn = fn
		res := rp.Deliver(context.Background(), Env{}, readbackReq(newFP), nil)
		if res.Verified || res.Outcome != agentinstall.OutcomeVerifyFailed || !res.RolledBack || !rp.rolledBack() {
			t.Errorf("%s: expected verify_failed + rollback: %+v", name, res)
		}
	}
}

func TestReadbackRequiresDeclarationAndFingerprint(t *testing.T) {
	_, newFP := testLeaf(t, "new")
	rp := newReadbackPlugin("")
	res := rp.Deliver(context.Background(), Env{}, readbackReq(newFP), nil)
	if res.Verified || res.Installed || len(rp.ops) != 0 {
		t.Errorf("readback accepted for an undeclared plugin: %+v ops=%v", res, rp.ops)
	}
	rp = newReadbackPlugin("readback")
	if res = rp.Deliver(context.Background(), Env{}, readbackReq(""), nil); res.Verified || len(rp.ops) != 0 {
		t.Errorf("readback without a fingerprint pushed anyway: %+v ops=%v", res, rp.ops)
	}
	req := readbackReq(newFP)
	req.VerifyHostPort = "h:443"
	if res = rp.Deliver(context.Background(), Env{}, req, nil); res.Verified || len(rp.ops) != 0 {
		t.Errorf("readback combined with a TLS target pushed anyway: %+v ops=%v", res, rp.ops)
	}
}

// Without ReadbackVerify a readback plugin is verified by the TLS dial and
// the verify op is never called.
func TestTLSPathNeverCallsVerifyOp(t *testing.T) {
	_, newFP := testLeaf(t, "new")
	rp := newReadbackPlugin("readback")
	rp.verifyFn = func() (abi.VerifyResult, error) { t.Fatal("verify op called"); return abi.VerifyResult{}, nil }
	dialed := 0
	res := rp.Deliver(context.Background(), Env{}, DeliverRequest{Name: "n", CertPEM: []byte("x"), VerifyHostPort: "h:443", ExpectedFingerprint: newFP},
		func(context.Context, string) (string, error) { dialed++; return newFP, nil })
	if !res.Verified || dialed != 1 || rp.verifyN != 0 {
		t.Fatalf("tls verify: %+v dialed=%d verifyN=%d", res, dialed, rp.verifyN)
	}
}
