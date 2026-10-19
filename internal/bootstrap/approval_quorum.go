// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// approvalQuorumPolicyEnv holds the per-action-class quorum, e.g.
// "revoke=2/3,bulk_revoke=2/3". Unlisted classes stay 1-of-1.
const approvalQuorumPolicyEnv = "APPROVAL_QUORUM_POLICY"

const maxQuorumM = 9

var errAlreadyApproved = errors.New("this approver has already approved the action")

// quorumStore is optional on a PendingActionStore so test fakes that only
// implement the base interface keep compiling.
type quorumStore interface {
	// RecordApproval stores one approval keyed by the canonical human and
	// returns the number of distinct humans who have now approved. actor is
	// the canonical human of the principal physically acting (the delegate
	// when on_behalf_of is used): one actor contributes one vote per action
	// whatever human it votes as.
	RecordApproval(ctx context.Context, actionID, human, actor string) (distinct int, err error)
}

// parseQuorumPolicy parses "class=n/m,..." with 1 <= n <= m <= 9.
func parseQuorumPolicy(raw string) (map[string][2]int, error) {
	out := map[string][2]int{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		class, nm, ok := strings.Cut(entry, "=")
		nStr, mStr, ok2 := strings.Cut(nm, "/")
		class = strings.TrimSpace(class)
		if !ok || !ok2 || class == "" {
			return nil, fmt.Errorf("quorum policy entry %q: want class=n/m", entry)
		}
		n, errN := strconv.Atoi(strings.TrimSpace(nStr))
		m, errM := strconv.Atoi(strings.TrimSpace(mStr))
		if errN != nil || errM != nil || n < 1 || n > m || m > maxQuorumM {
			return nil, fmt.Errorf("quorum policy entry %q: need 1 <= n <= m <= %d", entry, maxQuorumM)
		}
		out[class] = [2]int{n, m}
	}
	return out, nil
}

// ValidateApprovalQuorumPolicyFromEnv is the startup check for
// APPROVAL_QUORUM_POLICY (S-02/D-290-B): a typo must refuse boot, because the
// per-call fallback in quorumFor would otherwise drop every class (e.g.
// revoke=2/3) to a single approver. The error names the offending entry.
func ValidateApprovalQuorumPolicyFromEnv() error {
	raw := strings.TrimSpace(os.Getenv(approvalQuorumPolicyEnv))
	if raw == "" {
		return nil
	}
	if _, err := parseQuorumPolicy(raw); err != nil {
		return fmt.Errorf("%s is invalid: %w", approvalQuorumPolicyEnv, err)
	}
	return nil
}

// quorumFor returns the (n, m) for an action class. It reads the env on every
// call (no cached state). The 1-of-1 fallback on a bad policy is unreachable
// defence: main refuses to start via ValidateApprovalQuorumPolicyFromEnv.
func quorumFor(actionType string) (n, m int) {
	raw := strings.TrimSpace(os.Getenv(approvalQuorumPolicyEnv))
	if raw == "" {
		return 1, 1
	}
	policy, err := parseQuorumPolicy(raw)
	if err != nil {
		logging.Errorf("%s is invalid, falling back to 1-of-1 approvals: %v", approvalQuorumPolicyEnv, err)
		return 1, 1
	}
	if nm, ok := policy[actionType]; ok {
		return nm[0], nm[1]
	}
	return 1, 1
}

// approvalHuman is the identity a quorum counts: the canonical human, so
// several keys of one person count once. A delegate acting on_behalf_of a
// delegator counts as the delegator, so the delegator approving directly and
// again through a delegate is still one approval.
func approvalHuman(a *Authenticator, pd AuthPrincipal, onBehalfOf string) string {
	if onBehalfOf != "" {
		return delegatorHuman(a, onBehalfOf)
	}
	return a.canonicalHuman(pd)
}

// RecordApproval inserts the approval and counts distinct humans in one
// transaction. ON CONFLICT DO NOTHING (portable across sqlite and postgres)
// turns a repeat by the same human into errAlreadyApproved.
//
// F2: the (action_id, human) key alone let a delegate vote once as itself and
// once as its delegator. The same transaction therefore refuses a vote when
// the actor already voted (approver_id) or already is a counted human, and
// when the human it votes as already has an approver; approver_id stores the
// actor's canonical human. A query check, not a unique index, so no migration
// is needed; sqlite serialises writers, and on postgres the primary-key
// conflict still guards the same-human race.
func (s *dbPendingActionStore) RecordApproval(ctx context.Context, actionID, human, actor string) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit
	// Take a write lock on the parent action before the duplicate check, so
	// two concurrent votes by one actor (once as self, once on behalf of a
	// delegator) serialise instead of both passing the check under postgres
	// READ COMMITTED. A no-op UPDATE locks portably on sqlite and postgres.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(
		`UPDATE pending_actions SET id = id WHERE id = %s`, s.ph(1)), actionID); err != nil {
		return 0, err
	}
	var prior int
	if err := tx.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT COUNT(*) FROM pending_action_approvals WHERE action_id = %s
		 AND (approver_id = %s OR human = %s OR human = %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4)), actionID, actor, actor, human).Scan(&prior); err != nil {
		return 0, err
	}
	if prior > 0 {
		return 0, errAlreadyApproved
	}
	res, err := tx.ExecContext(ctx, fmt.Sprintf(
		`INSERT INTO pending_action_approvals (action_id, human, approver_id, created_at)
		 VALUES (%s, %s, %s, %s) ON CONFLICT (action_id, human) DO NOTHING`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4)),
		actionID, human, actor, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, errAlreadyApproved
	}
	var distinct int
	if err := tx.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT COUNT(*) FROM pending_action_approvals WHERE action_id = %s`, s.ph(1)), actionID).Scan(&distinct); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return distinct, nil
}
