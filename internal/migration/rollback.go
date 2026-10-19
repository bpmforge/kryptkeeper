// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package migration

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

// W24-39: undo a batch by disabling (never deleting) the templates it
// created. Certificates already issued from them are untouched.

// ErrBatchNotFound is returned for an unknown batch id.
var ErrBatchNotFound = errors.New("migration batch not found")

// RollbackStore is the Store extension rollback needs. SQLStore and the test
// memStore implement it; Service reaches it through its Store.
type RollbackStore interface {
	// GetBatch returns the batch's items, including already-disabled ones.
	GetBatch(ctx context.Context, id string) (Batch, []BatchItem, bool, error)
	MarkItemDisabled(ctx context.Context, batchID, sourceKey, at string) error
	// MarkItemRestored retires the item after its template was restored and, in
	// the same transaction, reactivates the item it superseded (when that
	// item's batch is still applied and it was retired by the supersede), so a
	// restored template is owned again.
	MarkItemRestored(ctx context.Context, batchID, sourceKey, at string) error
	MarkItemKept(ctx context.Context, batchID, sourceKey, reason string) error
	// MarkBatchRolledBack sets status='rolled_back'.
	MarkBatchRolledBack(ctx context.Context, batchID, by, at string) error
}

// Rollback item outcomes.
const (
	OutcomeDisabled         = "disabled"
	OutcomeRestored         = "restored"
	OutcomeKept             = "kept"
	OutcomeAlreadyDisabled  = "already_disabled"
	keepReasonPendingApprov = "pending approvals"
)

// RollbackItemResult is one template's rollback outcome.
type RollbackItemResult struct {
	Name       string `json:"name"`
	TemplateID string `json:"template_id"`
	Outcome    string `json:"outcome"`
	Reason     string `json:"reason,omitempty"`
}

// RollbackResult is the outcome of Rollback. Items are sorted by Name.
type RollbackResult struct {
	BatchID           string               `json:"batch_id"`
	AlreadyRolledBack bool                 `json:"already_rolled_back"`
	Disabled          int                  `json:"disabled"`
	Restored          int                  `json:"restored"`
	Kept              int                  `json:"kept"`
	Items             []RollbackItemResult `json:"items"`
}

// Rollback disables every template the batch created, and restores every one
// it updated to its snapshot, except those with pending approvals, which stay
// as they are and are reported as kept. A batch with kept
// items is still marked rolled back (a second call is a no-op by design; the
// operator disables the rest from the Templates page once approvals resolve).
// A Disable failure aborts and leaves the batch applied, so a retry resumes.
func (s *Service) Rollback(ctx context.Context, batchID, actor string) (RollbackResult, error) {
	rs, ok := s.store.(RollbackStore)
	if !ok {
		return RollbackResult{}, errors.New("store does not support rollback")
	}
	b, items, found, err := rs.GetBatch(ctx, batchID)
	if err != nil {
		return RollbackResult{}, err
	}
	if !found {
		return RollbackResult{}, ErrBatchNotFound
	}
	res := RollbackResult{BatchID: batchID, Items: []RollbackItemResult{}}
	if b.Status == "rolled_back" {
		res.AlreadyRolledBack = true
		return res, nil
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Name != items[j].Name {
			return items[i].Name < items[j].Name
		}
		return items[i].SourceKey < items[j].SourceKey
	})
	at := s.now().UTC().Format(time.RFC3339)
	for _, it := range items {
		r := RollbackItemResult{Name: it.Name, TemplateID: it.TemplateID}
		switch {
		case it.DisabledAt != "":
			r.Outcome = OutcomeAlreadyDisabled
		default:
			pending, err := s.sink.HasPendingApprovals(ctx, it.TemplateID)
			if err != nil {
				return res, fmt.Errorf("check approvals for %q: %w", it.Name, err)
			}
			if pending {
				if err := rs.MarkItemKept(ctx, batchID, it.SourceKey, keepReasonPendingApprov); err != nil {
					return res, fmt.Errorf("record kept %q: %w", it.Name, err)
				}
				r.Outcome, r.Reason = OutcomeKept, keepReasonPendingApprov
				res.Kept++
				break
			}
			if it.PriorJSON != "" {
				if err := s.restore(ctx, it); err != nil {
					return res, err
				}
				if err := rs.MarkItemRestored(ctx, batchID, it.SourceKey, at); err != nil {
					return res, fmt.Errorf("record restored %q: %w", it.Name, err)
				}
				r.Outcome = OutcomeRestored
				res.Restored++
				res.Items = append(res.Items, r)
				continue
			}
			if err := s.sink.Disable(ctx, it.TemplateID); err != nil {
				return res, fmt.Errorf("disable %q: %w", it.Name, err)
			}
			r.Outcome = OutcomeDisabled
			res.Disabled++
			if err := rs.MarkItemDisabled(ctx, batchID, it.SourceKey, at); err != nil {
				return res, fmt.Errorf("record %s %q: %w", r.Outcome, it.Name, err)
			}
		}
		res.Items = append(res.Items, r)
	}
	if err := rs.MarkBatchRolledBack(ctx, batchID, actor, at); err != nil {
		return res, fmt.Errorf("mark batch rolled back: %w", err)
	}
	return res, nil
}

func (s *Service) restore(ctx context.Context, it BatchItem) error {
	u, ok := s.sink.(TemplateUpdater)
	if !ok {
		return fmt.Errorf("restore %q: template sink cannot restore", it.Name)
	}
	if err := u.Restore(ctx, it.TemplateID, it.PriorJSON); err != nil {
		return fmt.Errorf("restore %q: %w", it.Name, err)
	}
	return nil
}

func (s *SQLStore) MarkItemDisabled(ctx context.Context, batchID, sourceKey, at string) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE migration_batch_items SET disabled_at = ?, keep_reason = '' WHERE batch_id = ? AND source_key = ?`), at, batchID, sourceKey)
	return err
}

func (s *SQLStore) MarkItemKept(ctx context.Context, batchID, sourceKey, reason string) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE migration_batch_items SET keep_reason = ? WHERE batch_id = ? AND source_key = ?`), reason, batchID, sourceKey)
	return err
}

func (s *SQLStore) MarkBatchRolledBack(ctx context.Context, batchID, by, at string) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE migration_batches SET status = 'rolled_back', rolled_back_by = ?, rolled_back_at = ? WHERE id = ?`), by, at, batchID)
	return err
}

func (s *SQLStore) MarkItemRestored(ctx context.Context, batchID, sourceKey, at string) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback() // the original error is the one worth returning
		}
	}()
	if _, err = tx.ExecContext(ctx, s.q(`UPDATE migration_batch_items SET disabled_at = ?, keep_reason = '' WHERE batch_id = ? AND source_key = ?`), at, batchID, sourceKey); err != nil {
		return err
	}
	// Only an item the supersede itself retired (disabled_at = this batch's
	// created_at) and whose batch is still applied comes back; one retired by a
	// rollback of its own batch stays retired.
	if _, err = tx.ExecContext(ctx, s.q(`UPDATE migration_batch_items SET disabled_at = '', keep_reason = ''
WHERE source_key = ? AND disabled_at = (SELECT created_at FROM migration_batches WHERE id = ?)
AND batch_id = (SELECT supersedes_batch_id FROM migration_item_supersedes WHERE batch_id = ? AND source_key = ?)
AND batch_id IN (SELECT id FROM migration_batches WHERE status = 'applied')`), sourceKey, batchID, batchID, sourceKey); err != nil {
		return err
	}
	return tx.Commit()
}
