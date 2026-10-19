// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cmp

import (
	"context"
	"encoding/asn1"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

const (
	defaultPollTTL = 24 * time.Hour
	// pollMaxEntries bounds the waiting-transaction map; at capacity new
	// deferrals are refused with systemFailure.
	pollMaxEntries = 1000
	// pollCheckAfter is the checkAfter (seconds) a waiting pollRep advertises.
	pollCheckAfter = 30
)

// Approver gates issuance behind a human approval (deferred issuance).
type Approver interface {
	// Needs reports whether the next enrollment must wait for approval.
	Needs(ctx context.Context) (bool, error)
	// Propose queues the enrollment and returns its approval id.
	Propose(ctx context.Context, txID, subject string) (approvalID string, err error)
	// State returns pending|approved|rejected|unknown for an approval id.
	State(ctx context.Context, approvalID string) (string, error)
}

// pendingTx is one deferred enrollment. Held in memory only: a restart loses
// it, and a later pollReq then gets badRequest "unknown transaction" (the
// client must re-enroll; the queued approval itself survives).
type pendingTx struct {
	approvalID string
	req        crmfRequest
	bodyType   int
	created    time.Time
	expires    time.Time
	subject    string
	actor      string
}

type pendingStore struct {
	mu sync.Mutex
	m  map[string]*pendingTx
}

func newPendingStore() *pendingStore { return &pendingStore{m: map[string]*pendingTx{}} }

// sweepLocked drops expired entries.
func (p *pendingStore) sweepLocked(now time.Time) {
	for k, tx := range p.m {
		if !now.Before(tx.expires) {
			delete(p.m, k)
		}
	}
}

// put stores tx; false when the key exists or the store is full.
func (p *pendingStore) put(key string, tx *pendingTx, now time.Time) (ok bool, full bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweepLocked(now)
	if _, exists := p.m[key]; exists {
		return false, false
	}
	if len(p.m) >= pollMaxEntries {
		return false, true
	}
	p.m[key] = tx
	return true, false
}

// get returns the live tx, or (nil, expired) when absent/expired.
func (p *pendingStore) get(key string, now time.Time) (tx *pendingTx, expired bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	tx, ok := p.m[key]
	if !ok {
		return nil, false
	}
	if !now.Before(tx.expires) {
		delete(p.m, key)
		return nil, true
	}
	return tx, false
}

func (p *pendingStore) delete(key string) {
	p.mu.Lock()
	delete(p.m, key)
	p.mu.Unlock()
}

// deferIssuance queues the enrollment for approval and answers a protected
// ip/cp/kup whose CertResponse has status waiting and no certificate.
func (s *Server) deferIssuance(w http.ResponseWriter, r *http.Request, msg *parsedMessage, reqBodyType int, req crmfRequest) {
	action := certAction(reqBodyType)
	key := string(msg.Header.TransactionID)
	subject := req.CSR.Subject.CommonName

	approvalID, err := s.approver.Propose(r.Context(), hex.EncodeToString(msg.Header.TransactionID), subject)
	if err != nil {
		logging.Warnf("cmp: approval proposal failed: %v", err)
		s.emit(r.Context(), r, msg, action, "failure", "approval proposal failed")
		s.writeErrorFail(w, msg.cred, msg.Header, "approval proposal failed", failSystemFailure)
		return
	}
	now := s.now()
	ok, full := s.pending.put(key, &pendingTx{
		approvalID: approvalID, req: req, bodyType: reqBodyType,
		created: now, expires: now.Add(s.pollTTL), subject: subject,
		actor: string(msg.Header.SenderKID),
	}, now)
	if !ok {
		if full {
			s.emit(r.Context(), r, msg, action, "failure", "too many pending transactions")
			s.writeErrorFail(w, msg.cred, msg.Header, "too many pending transactions", failSystemFailure)
		} else {
			s.emit(r.Context(), r, msg, action, "denied", "transaction already pending")
			s.writeErrorFail(w, msg.cred, msg.Header, "badRequest: transaction already pending", failBadRequest)
		}
		return
	}

	pkiMsg, err := buildWaitingResponse(req.CertReqID, responseBodyType(reqBodyType), msg.Header, msg.cred.secret, msg.cred.reference)
	if err != nil {
		logging.Warnf("cmp: build waiting response failed: %v", err)
		s.pending.delete(key)
		s.writeErrorFail(w, msg.cred, msg.Header, "waiting response encoding failed", failSystemFailure)
		return
	}
	s.emit(r.Context(), r, msg, action, "pending_approval", "approval="+approvalID)
	s.write(w, pkiMsg)
}

// handlePollReq answers pollReq (25): pollRep while waiting, the real
// ip/cp/kup once approved, an error if unknown, expired or rejected.
func (s *Server) handlePollReq(w http.ResponseWriter, r *http.Request, msg *parsedMessage) {
	deny := func(detail, clientText string) {
		s.emit(r.Context(), r, msg, "cmp.poll", "denied", detail)
		s.writeErrorFail(w, msg.cred, msg.Header, "badRequest: "+clientText, failBadRequest)
	}

	var reqs []struct{ CertReqID int }
	if _, err := asn1.Unmarshal(msg.BodyBytes, &reqs); err != nil || len(reqs) == 0 {
		deny("malformed pollReq", "malformed pollReq")
		return
	}
	key := string(msg.Header.TransactionID)
	tx, expired := s.pending.get(key, s.now())
	if tx == nil || s.approver == nil {
		if expired {
			deny("transaction expired", "transaction expired")
		} else {
			deny("unknown transaction", "unknown transaction")
		}
		return
	}
	if reqs[0].CertReqID != tx.req.CertReqID {
		deny("certReqId does not match the transaction", "unknown transaction")
		return
	}

	state, err := s.approver.State(r.Context(), tx.approvalID)
	if err != nil {
		logging.Warnf("cmp: approval state lookup failed: %v", err)
		s.emit(r.Context(), r, msg, "cmp.poll", "failure", "approval state lookup failed")
		s.writeErrorFail(w, msg.cred, msg.Header, "approval state lookup failed", failSystemFailure)
		return
	}
	switch state {
	case "pending":
		pkiMsg, err := buildPollRep(tx.req.CertReqID, pollCheckAfter, msg.Header, msg.cred.secret, msg.cred.reference)
		if err != nil {
			logging.Warnf("cmp: build pollRep failed: %v", err)
			s.writeErrorFail(w, msg.cred, msg.Header, "pollRep encoding failed", failSystemFailure)
			return
		}
		s.emit(r.Context(), r, msg, "cmp.poll", "success", "waiting approval="+tx.approvalID)
		s.write(w, pkiMsg)
	case "approved":
		s.pending.delete(key)
		issuanceReq, refusal := s.buildIssuanceRequest(tx.req.CSR, msg.cred.suffixes)
		if refusal != "" {
			s.emit(r.Context(), r, msg, "cmp.poll", "denied", refusal)
			s.writeError(w, msg.cred, msg.Header, refusal)
			return
		}
		s.emit(r.Context(), r, msg, "cmp.poll", "success", "approved approval="+tx.approvalID)
		s.issue(w, r, msg.cred, msg.Header, tx.actor, tx.bodyType, tx.req, issuanceReq)
	case "rejected":
		s.pending.delete(key)
		s.emit(r.Context(), r, msg, "cmp.reject", "denied", "approval rejected approval="+tx.approvalID)
		s.writeErrorFail(w, msg.cred, msg.Header, "notAuthorized: enrollment was not approved", failNotAuthorized)
	default:
		s.pending.delete(key)
		deny("approval not found approval="+tx.approvalID, "unknown transaction")
	}
}
