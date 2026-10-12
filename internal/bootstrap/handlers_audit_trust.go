// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/audittrust"
)

// W17-04: the W16-01 RFC 6962 transparency log, wired.
//
// /api/v1/audit already served the plain log — but a plain log proves
// nothing: anyone who can edit the rows can edit the log. The Merkle
// machinery that makes the trail tamper-EVIDENT shipped complete and
// unreachable. This exposes it so an auditor can prove no retro-tamper
// from a checkpoint pair plus a proof, without trusting this server.
//
// The audit WRITE path is untouched: the tree is derived on read from
// the records themselves. Append-only is a Kryptkeeper law, and a log
// that rebuilds from the records cannot silently disagree with them.

// auditTransparencyMaxEntries bounds one tree build. The log is derived
// per request rather than cached so it can never drift from the records.
const auditTransparencyMaxEntries = 100000

// auditTransparencySigningKey returns the Ed25519 key that signs
// checkpoints, from a base64 seed in the environment.
//
// Deliberately fail-closed with NO ephemeral fallback: a checkpoint
// signed by a per-process key is unverifiable after a restart, which
// looks like tamper evidence while providing none. Unconfigured must
// mean "no checkpoints", not "checkpoints you cannot trust".
func auditTransparencySigningKey() (ed25519.PrivateKey, error) {
	seedB64 := strings.TrimSpace(os.Getenv("AUDIT_TRANSPARENCY_SIGNING_SEED"))
	if seedB64 == "" {
		return nil, fmt.Errorf("AUDIT_TRANSPARENCY_SIGNING_SEED is not set")
	}
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("AUDIT_TRANSPARENCY_SIGNING_SEED must be %d base64-encoded bytes", ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// canonicalAuditLeaf is the exact byte encoding hashed into the tree.
// Field order is fixed by the struct, so two builds over the same
// records produce the same leaves — the property every proof depends on.
func canonicalAuditLeaf(e AuditEntry) []byte {
	canonical := struct {
		ID           int64  `json:"id"`
		Timestamp    string `json:"timestamp"`
		Action       string `json:"action"`
		ActorType    string `json:"actor_type"`
		ActorID      string `json:"actor_id"`
		ResourceType string `json:"resource_type"`
		ResourceID   string `json:"resource_id"`
		Outcome      string `json:"outcome"`
		Tenant       string `json:"tenant"`
	}{e.ID, e.Timestamp, e.Action, e.ActorType, e.ActorID, e.ResourceType, e.ResourceID, string(e.Outcome), e.Tenant}
	raw, _ := json.Marshal(canonical) // fixed-shape struct: cannot fail
	return raw
}

// buildAuditMerkleLog derives the tree from the audit records in
// canonical (oldest-first) order.
func buildAuditMerkleLog(ctx context.Context, provider AuditProvider) (*audittrust.MerkleLog, error) {
	result, err := provider.ListEntries(ctx, AuditListQuery{
		Limit: auditTransparencyMaxEntries,
		Order: "asc", // oldest first: leaf index must be stable as the log grows
	})
	if err != nil {
		return nil, err
	}
	tree := &audittrust.MerkleLog{}
	for _, entry := range result.Entries {
		tree.Append(canonicalAuditLeaf(entry))
	}
	return tree, nil
}

func registerAuditTrustHandlers(mux *http.ServeMux, auth *Authenticator, roles *CustomRoleStore, auditProvider AuditProvider) {
	// Shared preamble: authenticate, then derive the tree.
	prepare := func(w http.ResponseWriter, r *http.Request, action string) (*audittrust.MerkleLog, bool) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return nil, false
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, "audit", "transparency", AuditOutcomeDenied)
			writeUnauthorized(w)
			return nil, false
		}
		if !requireReadPermission(w, r, auditProvider, pd, roles, "audit.read", action, "audit", "transparency") {
			return nil, false
		}
		principal := pd.ID
		tree, err := buildAuditMerkleLog(r.Context(), auditProvider)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, action, "audit", "transparency", AuditOutcomeFailure)
			log.Printf("audit transparency: build tree: %v", err)
			writeServiceUnavailable(w, "audit log unavailable")
			return nil, false
		}
		emitAuditEvent(r, auditProvider, principal, action, "audit", "transparency", AuditOutcomeSuccess)
		return tree, true
	}

	// GET /audit/transparency/checkpoint — the auditor's trust anchor.
	mux.HandleFunc("/api/v1/audit/transparency/checkpoint", func(w http.ResponseWriter, r *http.Request) {
		tree, ok := prepare(w, r, "audit.transparency_checkpoint")
		if !ok {
			return
		}
		priv, err := auditTransparencySigningKey()
		if err != nil {
			writeServiceUnavailable(w, "checkpoint signing is not configured: "+err.Error())
			return
		}
		cp := tree.SignCheckpoint(priv)
		writeJSONData(w, map[string]any{
			"size":       cp.Size,
			"root":       cp.RootB64,
			"signature":  cp.Signature,
			"public_key": base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		})
	})

	// GET /audit/transparency/inclusion?index=N — prove entry N is in the tree.
	mux.HandleFunc("/api/v1/audit/transparency/inclusion", func(w http.ResponseWriter, r *http.Request) {
		tree, ok := prepare(w, r, "audit.transparency_inclusion")
		if !ok {
			return
		}
		index, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("index")))
		if err != nil || index < 0 {
			writeBadRequest(w, "index must be a non-negative integer")
			return
		}
		proof, err := tree.InclusionProof(index)
		if err != nil {
			writeBadRequest(w, err.Error())
			return
		}
		root := tree.Root()
		writeJSONData(w, map[string]any{
			"index":      index,
			"tree_size":  tree.Size(),
			"root":       base64.StdEncoding.EncodeToString(root[:]),
			"audit_path": encodeProof(proof),
		})
	})

	// GET /audit/transparency/consistency?from=M — prove the tree at size
	// M is a prefix of the current tree. A forged old root fails here.
	mux.HandleFunc("/api/v1/audit/transparency/consistency", func(w http.ResponseWriter, r *http.Request) {
		tree, ok := prepare(w, r, "audit.transparency_consistency")
		if !ok {
			return
		}
		from, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("from")))
		if err != nil || from < 1 {
			writeBadRequest(w, "from must be a positive integer tree size")
			return
		}
		proof, err := tree.ConsistencyProof(from)
		if err != nil {
			writeBadRequest(w, err.Error())
			return
		}
		root := tree.Root()
		writeJSONData(w, map[string]any{
			"from_size": from,
			"tree_size": tree.Size(),
			"root":      base64.StdEncoding.EncodeToString(root[:]),
			"proof":     encodeProof(proof),
		})
	})
}

func encodeProof(proof [][32]byte) []string {
	out := make([]string, 0, len(proof))
	for _, h := range proof {
		out = append(out, base64.StdEncoding.EncodeToString(h[:]))
	}
	return out
}
