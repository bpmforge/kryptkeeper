// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"os"

	"kryptkeeper/internal/logging"
)

// Template history (W23-44) lives in a sidecar next to the template file
// (<APP_TEMPLATE_FILE>.revisions.json, templateID -> revisions) because the
// only template provider is file-backed; a DB-backed provider would need a
// template_revisions table. The template file is the source of truth for the
// current revision: it is written first, then the history, and a history
// write that fails (or a missing sidecar) is repaired on read rather than
// left as a phantom or a hole.

func (p *fileTemplateProvider) historyPath() string { return p.filePath + ".revisions.json" }

func (p *fileTemplateProvider) loadHistory() map[string][]TemplateRevision {
	hist := map[string][]TemplateRevision{}
	body, err := os.ReadFile(p.historyPath())
	if err != nil {
		if !os.IsNotExist(err) {
			logging.Infof("template history unreadable: %v", err)
		}
		return hist
	}
	if err := json.Unmarshal(body, &hist); err != nil || hist == nil {
		logging.Infof("template history invalid JSON; treating as empty")
		return map[string][]TemplateRevision{}
	}
	return hist
}

func (p *fileTemplateProvider) saveHistory(hist map[string][]TemplateRevision) {
	body, err := json.Marshal(hist)
	if err == nil {
		err = writeStateFile(p.historyPath(), body)
	}
	if err != nil {
		logging.Infof("template history not saved: %v", err)
	}
}

func newTemplateRevision(item TemplateItem, prev *TemplateItem) TemplateRevision {
	rev := TemplateRevision{Revision: item.Revision, ChangedAt: item.UpdatedAt, Snapshot: item, Changes: []TemplateFieldChange{}}
	if prev != nil {
		rev.Changes = diffTemplates(*prev, item)
	}
	return rev
}

// startHistory begins a fresh list for a new template (create or clone).
func (p *fileTemplateProvider) startHistory(item TemplateItem) {
	hist := p.loadHistory()
	hist[item.ID] = []TemplateRevision{newTemplateRevision(item, nil)}
	p.saveHistory(hist)
}

// appendHistory records the revision a successful PUT/PATCH produced. A
// template that predates history gets one synthetic entry for its prior state:
// earlier revisions are unknowable.
func (p *fileTemplateProvider) appendHistory(before, after TemplateItem) {
	hist := p.loadHistory()
	list := hist[after.ID]
	if len(list) == 0 {
		list = []TemplateRevision{newTemplateRevision(before, nil)}
	}
	hist[after.ID] = append(list, newTemplateRevision(after, &before))
	p.saveHistory(hist)
}

func (p *fileTemplateProvider) dropHistory(id string) {
	hist := p.loadHistory()
	if _, ok := hist[id]; !ok {
		return
	}
	delete(hist, id)
	p.saveHistory(hist)
}

// ListTemplateRevisions implements TemplateRevisionLister.
func (p *fileTemplateProvider) ListTemplateRevisions(ctx context.Context, id string) ([]TemplateRevision, bool, error) {
	cur, found, err := p.GetTemplate(ctx, id)
	if err != nil || !found {
		return nil, false, err
	}
	list := append([]TemplateRevision(nil), p.loadHistory()[id]...)
	if len(list) == 0 {
		return []TemplateRevision{newTemplateRevision(cur, nil)}, true, nil
	}
	// The sidecar can lag the template file (failed history write); the
	// current revision is always reported.
	if last := list[len(list)-1]; last.Revision != cur.Revision {
		prev := last.Snapshot
		list = append(list, newTemplateRevision(cur, &prev))
	}
	return list, true, nil
}
