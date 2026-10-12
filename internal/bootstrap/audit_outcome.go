// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// AuditOutcome is the closed vocabulary of audit_log.outcome. The database
// CHECK constraint (migration 000076, audit_db_provider.go DDL) enumerates
// exactly these values; audit_outcome_test.go fails if the two drift, and
// bans string literals at emit call sites. An outcome that is not in this set
// is refused by the DB store, which used to make the audit row silently
// vanish (RC6 live autopilot run), so a new outcome needs a constant here, a
// migration widening the CHECK, and the DDL strings updated together.
type AuditOutcome string

const (
	// AuditOutcomeSuccess: the action completed as requested.
	AuditOutcomeSuccess AuditOutcome = "success"
	// AuditOutcomeFailure: the action was attempted and did not complete.
	AuditOutcomeFailure AuditOutcome = "failure"
	// AuditOutcomeDenied: refused by authentication, authorization or policy
	// before it took effect.
	AuditOutcomeDenied AuditOutcome = "denied"
	// AuditOutcomeSkipped: deliberately not performed, e.g. a reminder the
	// configured notification provider cannot deliver.
	AuditOutcomeSkipped AuditOutcome = "skipped"
	// AuditOutcomePendingApproval: held in an approval queue; nothing has
	// taken effect yet.
	AuditOutcomePendingApproval AuditOutcome = "pending_approval"
	// AuditOutcomeProposed: a dual-control proposal was filed; the operation
	// itself runs only once a second principal approves it.
	AuditOutcomeProposed AuditOutcome = "proposed"
	// AuditOutcomeExecuted: the operation ran but its bookkeeping did not
	// complete (FB-05: approved action executed, decision not recorded).
	AuditOutcomeExecuted AuditOutcome = "executed"
	// AuditOutcomeIssuanceFailed: an approval was granted but the issuance it
	// authorised failed.
	AuditOutcomeIssuanceFailed AuditOutcome = "issuance_failed"
	// AuditOutcomePartial: part of a multi-step action took effect and part
	// did not, e.g. a certificate was renewed but its install did not verify.
	AuditOutcomePartial AuditOutcome = "partial"
)

// AllAuditOutcomes lists the vocabulary in a stable order.
func AllAuditOutcomes() []AuditOutcome {
	return []AuditOutcome{
		AuditOutcomeSuccess, AuditOutcomeFailure, AuditOutcomeDenied,
		AuditOutcomeSkipped, AuditOutcomePendingApproval, AuditOutcomeProposed,
		AuditOutcomeExecuted, AuditOutcomeIssuanceFailed, AuditOutcomePartial,
	}
}

// Valid reports whether o is part of the vocabulary.
func (o AuditOutcome) Valid() bool {
	for _, v := range AllAuditOutcomes() {
		if o == v {
			return true
		}
	}
	return false
}

// Adverse reports whether the outcome should raise SIEM severity: the action
// failed, was refused, or only partly took effect.
func (o AuditOutcome) Adverse() bool {
	switch o {
	case AuditOutcomeFailure, AuditOutcomeDenied, AuditOutcomeIssuanceFailed, AuditOutcomePartial:
		return true
	}
	return false
}
