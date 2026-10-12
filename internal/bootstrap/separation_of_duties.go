// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// FG-2 / A07-4: proposer != approver is decided on the HUMAN behind a
// credential, not on the credential's free-text principal id. An admin can
// mint an API key with any principal_id and role, and the bootstrap token and
// a login session are two ids for one person; comparing raw ids lets one
// person approve their own proposal.

const (
	// maxCanonicalHops bounds the CreatedBy walk. Keys record the minter's
	// canonical human eagerly, so the walk is normally one hop; the bound
	// keeps a hand-edited cyclic config from looping.
	maxCanonicalHops = 5

	// bootstrapHuman is the one canonical identity of the bootstrap token and
	// of every API key minted with it (directly or through a chain of keys).
	// It may propose, never approve (RC1-B-01).
	bootstrapHuman = "bootstrap"

	msgBootstrapCannotApprove = "the bootstrap token and keys minted with it are setup credentials and cannot approve actions; sign in as a named administrator"
	msgSelfApproval           = "the proposer cannot approve their own action"
)

// canonicalHuman resolves pd to the person behind it. An API-key principal
// whose record carries CreatedBy resolves to that minter (following chains
// of keys minted by keys); everything else is its own principal id.
func (a *Authenticator) canonicalHuman(pd AuthPrincipal) string {
	if pd.AuthType == AuthTypeBootstrap {
		return bootstrapHuman
	}
	if a == nil || pd.AuthType != AuthTypeAPIKey || pd.Kid == "" {
		return pd.ID
	}
	records := a.apiKeysSnapshot()
	rec, ok := records[pd.Kid]
	if !ok || rec.CreatedBy == "" {
		return pd.ID
	}
	return followCreatedBy(records, rec.CreatedBy)
}

// followCreatedBy walks a minter id up through any keys that carry their own
// CreatedBy, so a key minted by a key resolves to the first human. Minters
// are recorded as canonical humans at mint time; a match here means the
// minter was itself a key (legacy or config-loaded record).
func followCreatedBy(records map[string]apiKeyRecord, id string) string {
	for hop := 0; hop < maxCanonicalHops; hop++ {
		next := ""
		for _, r := range records {
			if r.PrincipalID == id && r.CreatedBy != "" {
				next = r.CreatedBy
				break
			}
		}
		if next == "" || next == id {
			return id
		}
		id = next
	}
	return id
}

// humansBehind is the set of humans a stored principal id can stand for: the
// id itself plus the minter of every key carrying it as principal id.
// PrincipalID is not unique, and widening to every match only ever refuses
// MORE approvals, so a forged principal id cannot be used to dodge the check.
func (a *Authenticator) humansBehind(principalID string) map[string]bool {
	set := map[string]bool{principalID: true}
	if a == nil {
		return set
	}
	records := a.apiKeysSnapshot()
	for _, r := range records {
		if r.PrincipalID == principalID && r.CreatedBy != "" {
			set[followCreatedBy(records, r.CreatedBy)] = true
		}
	}
	return set
}

// sameHuman reports whether pd is (a credential of) the person behind the
// stored principal id.
func (a *Authenticator) sameHuman(pd AuthPrincipal, storedID string) bool {
	humans := a.humansBehind(storedID)
	return humans[a.canonicalHuman(pd)] || humans[pd.ID]
}

// isBootstrapHuman reports whether pd is the bootstrap token or a key minted
// (at any depth) with it. One person can hold the bootstrap token AND a named
// account, so this identity is never accepted as a decider (RC1-B-01).
func (a *Authenticator) isBootstrapHuman(pd AuthPrincipal) bool {
	return pd.AuthType == AuthTypeBootstrap || a.canonicalHuman(pd) == bootstrapHuman
}

// approverRefusal returns "" when pd may decide an action proposed by
// proposedBy, else the message for a 403. The role capability is checked by
// the caller (principalMayApprove); this covers the identity rules:
//   - the bootstrap token, and any key minted with it, never approves (a
//     token plus a session would be one person approving their own work);
//   - the approver's human must not be the proposer's human, in either
//     direction (a key minted by the proposer, or a proposer who used a key
//     minted by the approver).
func (a *Authenticator) approverRefusal(pd AuthPrincipal, proposedBy string) string {
	if a.isBootstrapHuman(pd) {
		return msgBootstrapCannotApprove
	}
	if a.sameHuman(pd, proposedBy) {
		return msgSelfApproval
	}
	return ""
}

// mayDecide is the role half of the approval gate: an approver capability,
// and never the bootstrap token or a key minted with it.
func (a *Authenticator) mayDecide(pd AuthPrincipal) bool {
	return !a.isBootstrapHuman(pd) && canApproveActions(pd.Role)
}
