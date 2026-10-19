// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cmp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"
)

type fakeRevoker struct {
	serial *big.Int
	reason int
	actor  string
	scope  string
	err    error
}

func (f *fakeRevoker) Revoke(_ context.Context, serial *big.Int, reason int, actor string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.serial, f.reason, f.actor = serial, reason, actor
	return f.scope, nil
}

type fakeApprover struct {
	needs bool
	state string
	txID  string
}

func (f *fakeApprover) Needs(context.Context) (bool, error) { return f.needs, nil }
func (f *fakeApprover) Propose(_ context.Context, txID, _ string) (string, error) {
	f.txID = txID
	return "appr-1", nil
}
func (f *fakeApprover) State(context.Context, string) (string, error) { return f.state, nil }

type auditSink struct {
	mu     sync.Mutex
	events []AuditEvent
	alerts []string
}

func (a *auditSink) audit(_ context.Context, ev AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
}

func (a *auditSink) alert(_ context.Context, kind string, _ map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.alerts = append(a.alerts, kind)
}

func (a *auditSink) has(action, outcome string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.events {
		if e.Action == action && e.Outcome == outcome {
			return true
		}
	}
	return false
}

func seq(content []byte) []byte {
	b, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
	if err != nil {
		panic(err)
	}
	return b
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// buildRRBody builds RevReqContent with n RevDetails for serial; reason<0
// omits crlEntryDetails.
func buildRRBody(serial *big.Int, reason int, n int) []byte {
	var details []byte
	for i := 0; i < n; i++ {
		serialDER := mustMarshal(serial)
		serialField := mustMarshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: serialDER[2:]})
		tmpl := seq(serialField)
		rd := append([]byte{}, tmpl...)
		if reason >= 0 {
			ext := mustMarshal(pkix.Extension{Id: oidCRLReason, Value: mustMarshal(asn1.Enumerated(reason))})
			rd = append(rd, seq(ext)...)
		}
		details = append(details, seq(rd)...)
	}
	return seq(details)
}

func buildPollReqBody(certReqID int) []byte {
	return seq(seq(mustMarshal(certReqID)))
}

// decodeFail returns the PKIStatusInfo status and the set failInfo bit (-1
// when none) of an error response.
func decodeFail(t *testing.T, body []byte) (status int, bit int) {
	t.Helper()
	msg := decodeResponse(t, body)
	if msg.Body.Tag != PKIBodyError {
		t.Fatalf("body tag = %d, want error (%d)", msg.Body.Tag, PKIBodyError)
	}
	var content struct{ Info pkiStatusInfo }
	if _, err := asn1.Unmarshal(msg.Body.Bytes, &content); err != nil {
		t.Fatalf("parse ErrorMsgContent: %v", err)
	}
	bit = -1
	for i := 0; i < content.Info.FailInfo.BitLength; i++ {
		if content.Info.FailInfo.At(i) == 1 {
			bit = i
		}
	}
	return content.Info.Status, bit
}

func certRespStatus(t *testing.T, msg pkiMessageRaw) (status int, hasCert bool) {
	t.Helper()
	var rep struct {
		Responses []struct {
			ReqID  int
			Status pkiStatusInfo
			Key    asn1.RawValue `asn1:"optional"`
		}
	}
	if _, err := asn1.Unmarshal(msg.Body.Bytes, &rep); err != nil {
		t.Fatalf("parse CertRepMessage: %v", err)
	}
	r := rep.Responses[0]
	return r.Status.Status, len(r.Key.FullBytes) > 0
}

func rrServer(t *testing.T, rev Revoker) (*Server, *auditSink) {
	engine, caID := newCMPTestEngine(t)
	sink := &auditSink{}
	srv := newServerForTest(engine, caID).WithAuditFunc(sink.audit).WithAlertFunc(sink.alert)
	if rev != nil {
		srv.WithRevoker(rev)
	}
	return srv, sink
}

func TestRRRevokesAndReturnsRP(t *testing.T) {
	rev := &fakeRevoker{}
	srv, _ := rrServer(t, rev)
	rr := postCMP(srv.Handler(), buildProtectedPKIMessage(t, PKIBodyRR, buildRRBody(big.NewInt(0x1a2b), 1, 1), pbmOptions{}))
	msg := decodeResponse(t, rr.Body.Bytes())
	if msg.Body.Tag != PKIBodyRP {
		t.Fatalf("body tag = %d, want rp (%d)", msg.Body.Tag, PKIBodyRP)
	}
	var rep struct{ Status []pkiStatusInfo }
	if _, err := asn1.Unmarshal(msg.Body.Bytes, &rep); err != nil || len(rep.Status) != 1 || rep.Status[0].Status != 0 {
		t.Fatalf("rp status = %+v err=%v, want one granted", rep, err)
	}
	if rev.serial == nil || rev.serial.Int64() != 0x1a2b || rev.reason != 1 || rev.actor != testReference {
		t.Fatalf("revoker saw serial=%v reason=%d actor=%q", rev.serial, rev.reason, rev.actor)
	}
}

func TestRRUnknownSerialBadRequest(t *testing.T) {
	for _, e := range []error{ErrUnknownSerial, ErrNotRevocable} {
		srv, sink := rrServer(t, &fakeRevoker{err: e})
		rr := postCMP(srv.Handler(), buildProtectedPKIMessage(t, PKIBodyRR, buildRRBody(big.NewInt(99), -1, 1), pbmOptions{}))
		if status, bit := decodeFail(t, rr.Body.Bytes()); status != 2 || bit != failBadRequest {
			t.Fatalf("%v: status=%d failBit=%d, want rejection/badRequest", e, status, bit)
		}
		if !sink.has("cmp.rr", "denied") {
			t.Fatalf("%v: no denied cmp.rr audit: %+v", e, sink.events)
		}
	}
}

func TestRRWithoutRevokerBadRequest(t *testing.T) {
	srv, _ := rrServer(t, nil)
	rr := postCMP(srv.Handler(), buildProtectedPKIMessage(t, PKIBodyRR, buildRRBody(big.NewInt(5), 0, 1), pbmOptions{}))
	if _, bit := decodeFail(t, rr.Body.Bytes()); bit != failBadRequest {
		t.Fatalf("failBit = %d, want badRequest", bit)
	}
}

func TestRRWrongMACIsBadMessageCheck(t *testing.T) {
	rev := &fakeRevoker{}
	srv, _ := rrServer(t, rev)
	rr := postCMP(srv.Handler(), buildProtectedPKIMessage(t, PKIBodyRR, buildRRBody(big.NewInt(5), 0, 1), pbmOptions{secretForMAC: "wrong"}))
	if _, bit := decodeFail(t, rr.Body.Bytes()); bit != failBadMessageCheck {
		t.Fatalf("failBit = %d, want badMessageCheck", bit)
	}
	if rev.serial != nil {
		t.Fatal("revoked despite bad protection")
	}
}

func TestRRMalformedBadRequest(t *testing.T) {
	cases := map[string][]byte{
		"empty":          seq(nil),
		"two details":    buildRRBody(big.NewInt(5), 0, 2),
		"bad reason":     buildRRBody(big.NewInt(5), 7, 1),
		"no serial":      seq(seq(seq(nil))),
		"not a sequence": mustMarshal(5),
	}
	for name, body := range cases {
		srv, _ := rrServer(t, &fakeRevoker{})
		rr := postCMP(srv.Handler(), buildProtectedPKIMessage(t, PKIBodyRR, body, pbmOptions{}))
		if _, bit := decodeFail(t, rr.Body.Bytes()); bit != failBadRequest {
			t.Errorf("%s: failBit = %d, want badRequest", name, bit)
		}
	}
}

func TestRRAuditAndReason(t *testing.T) {
	srv, sink := rrServer(t, &fakeRevoker{scope: "inventory_only"})
	postCMP(srv.Handler(), buildProtectedPKIMessage(t, PKIBodyRR, buildRRBody(big.NewInt(0xab), 5, 1), pbmOptions{}))
	if len(sink.events) != 1 {
		t.Fatalf("events = %+v", sink.events)
	}
	ev := sink.events[0]
	if ev.Action != "cmp.rr" || ev.Outcome != "success" || ev.Detail != "serial=ab reason=5 revocation_scope=inventory_only" || ev.Actor != testReference {
		t.Fatalf("event = %+v", ev)
	}
}

func TestRRRevokerErrorIsFailure(t *testing.T) {
	srv, sink := rrServer(t, &fakeRevoker{err: errors.New("db down")})
	rr := postCMP(srv.Handler(), buildProtectedPKIMessage(t, PKIBodyRR, buildRRBody(big.NewInt(5), 0, 1), pbmOptions{}))
	if _, bit := decodeFail(t, rr.Body.Bytes()); bit != failBadRequest || !sink.has("cmp.rr", "failure") {
		t.Fatalf("failBit=%d events=%+v", bit, sink.events)
	}
}

// --- deferred issuance / polling ---

func pollFixture(t *testing.T, appr *fakeApprover) (*Server, *auditSink, []byte) {
	t.Helper()
	engine, caID := newCMPTestEngine(t)
	sink := &auditSink{}
	srv := newServerForTest(engine, caID).WithAuditFunc(sink.audit).WithAlertFunc(sink.alert).WithApprover(appr)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return srv, sink, buildCRMFIRBody(t, priv, "poll-test")
}

func sendIR(t *testing.T, srv *Server, body []byte, txn string) pkiMessageRaw {
	rr := postCMP(srv.Handler(), buildProtectedPKIMessage(t, PKIBodyIR, body, pbmOptions{txnID: txn}))
	return decodeResponse(t, rr.Body.Bytes())
}

func sendPoll(t *testing.T, srv *Server, txn string) []byte {
	return postCMP(srv.Handler(), buildProtectedPKIMessage(t, PKIBodyPollReq, buildPollReqBody(0), pbmOptions{txnID: txn})).Body.Bytes()
}

func TestIRWaitingWhenApprovalNeeded(t *testing.T) {
	srv, sink, body := pollFixture(t, &fakeApprover{needs: true, state: "pending"})
	msg := sendIR(t, srv, body, "tx-wait")
	if msg.Body.Tag != PKIBodyIP {
		t.Fatalf("body tag = %d, want ip", msg.Body.Tag)
	}
	if status, hasCert := certRespStatus(t, msg); status != pkiStatusWaiting || hasCert {
		t.Fatalf("status=%d hasCert=%v, want waiting and no cert", status, hasCert)
	}
	if !sink.has("cmp.ir", "pending_approval") {
		t.Fatalf("events = %+v", sink.events)
	}
}

func TestPollReqWaitingThenCert(t *testing.T) {
	appr := &fakeApprover{needs: true, state: "pending"}
	srv, sink, body := pollFixture(t, appr)
	sendIR(t, srv, body, "tx-poll")

	msg := decodeResponse(t, sendPoll(t, srv, "tx-poll"))
	if msg.Body.Tag != PKIBodyPollRep {
		t.Fatalf("body tag = %d, want pollRep", msg.Body.Tag)
	}
	var rep []struct{ CertReqID, CheckAfter int }
	if _, err := asn1.Unmarshal(msg.Body.Bytes, &rep); err != nil || len(rep) != 1 || rep[0].CheckAfter != 30 {
		t.Fatalf("pollRep = %+v err=%v", rep, err)
	}

	appr.state = "approved"
	msg = decodeResponse(t, sendPoll(t, srv, "tx-poll"))
	if msg.Body.Tag != PKIBodyIP {
		t.Fatalf("after approval body tag = %d, want ip", msg.Body.Tag)
	}
	if status, hasCert := certRespStatus(t, msg); status != 0 || !hasCert {
		t.Fatalf("status=%d hasCert=%v, want granted with cert", status, hasCert)
	}
	if !sink.has("cmp.poll", "success") || !sink.has("cmp.ir", "success") {
		t.Fatalf("events = %+v", sink.events)
	}
	if tx, _ := srv.pending.get("tx-poll", srv.now()); tx != nil {
		t.Fatal("transaction not removed after issuance")
	}
	// A further poll finds nothing.
	if _, bit := decodeFail(t, sendPoll(t, srv, "tx-poll")); bit != failBadRequest {
		t.Fatalf("poll after issuance failBit = %d, want badRequest", bit)
	}
}

func TestPollReqRejected(t *testing.T) {
	srv, sink, body := pollFixture(t, &fakeApprover{needs: true, state: "rejected"})
	sendIR(t, srv, body, "tx-rej")
	if _, bit := decodeFail(t, sendPoll(t, srv, "tx-rej")); bit != failNotAuthorized {
		t.Fatalf("failBit = %d, want notAuthorized", bit)
	}
	if !sink.has("cmp.reject", "denied") {
		t.Fatalf("events = %+v", sink.events)
	}
}

func TestPollReqAfterExpiryError(t *testing.T) {
	srv, sink, body := pollFixture(t, &fakeApprover{needs: true, state: "pending"})
	clock := time.Now()
	srv.now = func() time.Time { return clock }
	srv.WithPollTTL(time.Hour)
	sendIR(t, srv, body, "tx-exp")
	clock = clock.Add(2 * time.Hour)
	if _, bit := decodeFail(t, sendPoll(t, srv, "tx-exp")); bit != failBadRequest {
		t.Fatalf("failBit = %d, want badRequest", bit)
	}
	if !sink.has("cmp.poll", "denied") {
		t.Fatalf("events = %+v", sink.events)
	}
}

func TestPollReqUnknownTx(t *testing.T) {
	srv, sink, _ := pollFixture(t, &fakeApprover{state: "pending"})
	if _, bit := decodeFail(t, sendPoll(t, srv, "never-seen")); bit != failBadRequest {
		t.Fatalf("failBit = %d, want badRequest", bit)
	}
	if !sink.has("cmp.poll", "denied") {
		t.Fatalf("events = %+v", sink.events)
	}
}

func TestIRIssuesImmediatelyWhenApprovalNotNeeded(t *testing.T) {
	srv, _, body := pollFixture(t, &fakeApprover{needs: false})
	msg := sendIR(t, srv, body, "tx-now")
	if status, hasCert := certRespStatus(t, msg); status != 0 || !hasCert {
		t.Fatalf("status=%d hasCert=%v", status, hasCert)
	}
}

// --- genm, certConf, replay, failInfo ---

func TestGenMUnsupported(t *testing.T) {
	srv, sink := rrServer(t, nil)
	rr := postCMP(srv.Handler(), buildProtectedPKIMessage(t, PKIBodyGenM, seq(nil), pbmOptions{}))
	if status, bit := decodeFail(t, rr.Body.Bytes()); status != 2 || bit != failBadRequest {
		t.Fatalf("status=%d failBit=%d", status, bit)
	}
	if !sink.has("cmp.reject", "denied") {
		t.Fatalf("events = %+v", sink.events)
	}
}

func TestCertConfRejectionAudited(t *testing.T) {
	srv, sink := rrServer(t, nil)
	status := pkiStatusInfo{Status: 2}
	cs := seq(append(append(mustMarshal([]byte{1, 2, 3}), mustMarshal(0)...), mustMarshal(status)...))
	rr := postCMP(srv.Handler(), buildProtectedPKIMessage(t, PKIBodyCertConf, seq(cs), pbmOptions{}))
	if decodeResponse(t, rr.Body.Bytes()).Body.Tag != PKIBodyPKIConf {
		t.Fatal("certConf rejection must still be answered with pkiconf")
	}
	if !sink.has("cmp.reject", "denied") {
		t.Fatalf("events = %+v", sink.events)
	}
	// An accepted certificate is not audited as a rejection.
	srv2, sink2 := rrServer(t, nil)
	ok := seq(append(append(mustMarshal([]byte{1}), mustMarshal(0)...), mustMarshal(pkiStatusInfo{Status: 0})...))
	postCMP(srv2.Handler(), buildProtectedPKIMessage(t, PKIBodyCertConf, seq(ok), pbmOptions{}))
	if len(sink2.events) != 0 {
		t.Fatalf("unexpected events: %+v", sink2.events)
	}
}

func TestReplayRaisesAlert(t *testing.T) {
	srv, sink := rrServer(t, nil)
	msg := buildProtectedPKIMessage(t, PKIBodyGenM, seq(nil), pbmOptions{txnID: "txn-r", nonce: "nonce-r-000000001"})
	postCMP(srv.Handler(), msg)
	rr := postCMP(srv.Handler(), msg)
	if _, bit := decodeFail(t, rr.Body.Bytes()); bit != failBadRequest {
		t.Fatalf("replay failBit = %d, want badRequest", bit)
	}
	if len(sink.alerts) != 1 || sink.alerts[0] != "cmp.replay" {
		t.Fatalf("alerts = %v", sink.alerts)
	}
	if !sink.has("cmp.reject", "denied") {
		t.Fatalf("events = %+v", sink.events)
	}
}

func TestFailInfoEncoding(t *testing.T) {
	for _, tc := range []struct {
		bit  int
		want []byte
	}{
		{0, []byte{0x80}},
		{1, []byte{0x40}},
		{2, []byte{0x20}},
		{10, []byte{0x00, 0x20}},
		{23, []byte{0x00, 0x00, 0x01}},
		{25, []byte{0x00, 0x00, 0x00, 0x40}},
	} {
		bs := failInfoBits(tc.bit)
		if bs.BitLength != tc.bit+1 || string(bs.Bytes) != string(tc.want) {
			t.Errorf("bit %d: got len=%d bytes=%x, want len=%d bytes=%x", tc.bit, bs.BitLength, bs.Bytes, tc.bit+1, tc.want)
		}
		if bs.At(tc.bit) != 1 {
			t.Errorf("bit %d not set", tc.bit)
		}
	}
}
