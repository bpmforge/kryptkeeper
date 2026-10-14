// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"
)

const defaultCAFilePath = "./var/bootstrap-cas.json"

type fileCAProvider struct {
	filePath string
}

func NewFileCAProviderFromEnv() CAProvider {
	path := strings.TrimSpace(os.Getenv("APP_CA_FILE"))
	if path == "" {
		path = defaultCAFilePath
	}
	initStateDir(path)
	return &fileCAProvider{filePath: path}
}

func (p *fileCAProvider) ListCAs(_ context.Context, query CAListQuery) (CAListResult, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = 25
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}

	body, err := os.ReadFile(p.filePath)
	if err != nil {
		log.Printf("ca file fallback: unreadable %q: %v", p.filePath, err)
		return CAListResult{Items: []CAListItem{}, Total: 0, Limit: limit}, nil
	}

	var items []CAListItem
	if err := json.Unmarshal(body, &items); err != nil {
		log.Printf("ca file fallback: invalid JSON")
		return CAListResult{Items: []CAListItem{}, Total: 0, Limit: limit}, nil
	}

	filtered := make([]CAListItem, 0, len(items))
	for _, item := range items {
		if query.Type != "" && item.Type != query.Type {
			continue
		}
		if query.Status != "" && item.Status != query.Status {
			continue
		}
		filtered = append(filtered, item)
	}

	total := len(filtered)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := filtered[offset:end]

	return CAListResult{Items: page, Total: total, Limit: limit}, nil
}

func (p *fileCAProvider) GetCA(_ context.Context, id string) (CAListItem, bool, error) {
	items, ok := p.loadItems()
	if !ok {
		return CAListItem{}, false, nil
	}
	for _, item := range items {
		if item.ID == id {
			return item, true, nil
		}
	}
	return CAListItem{}, false, nil
}

func (p *fileCAProvider) GetCAChain(_ context.Context, id string) ([]CAListItem, bool, error) {
	items, ok := p.loadItems()
	if !ok {
		return nil, false, nil
	}

	byID := make(map[string]CAListItem, len(items))
	for _, item := range items {
		byID[item.ID] = item
	}

	current, found := byID[id]
	if !found {
		return nil, false, nil
	}

	chain := make([]CAListItem, 0, 4)
	visited := map[string]bool{}
	for {
		if visited[current.ID] {
			break
		}
		visited[current.ID] = true
		chain = append(chain, current)
		if current.ParentCAID == nil || *current.ParentCAID == "" {
			break
		}
		parent, ok := byID[*current.ParentCAID]
		if !ok {
			break
		}
		current = parent
	}

	return chain, true, nil
}

func (p *fileCAProvider) UpdateCA(_ context.Context, id string, req CAUpdateRequest) (CAListItem, error) {
	items, ok := p.loadItems()
	if !ok {
		return CAListItem{}, errCANotFound
	}

	now := time.Now().UTC().Format(time.RFC3339)
	for i := range items {
		if items[i].ID != id {
			continue
		}
		if req.DisplayName != nil {
			items[i].DisplayName = *req.DisplayName
		}
		if req.CRLDistributionPoints != nil {
			items[i].CRLDistributionPoints = *req.CRLDistributionPoints
		}
		if req.OCSPServiceURL != nil {
			trimmed := strings.TrimSpace(*req.OCSPServiceURL)
			if trimmed == "" {
				items[i].OCSPServiceURL = nil
			} else {
				items[i].OCSPServiceURL = &trimmed
			}
		}
		items[i].UpdatedAt = now
		if err := p.saveItems(items); err != nil {
			return CAListItem{}, err
		}
		return items[i], nil
	}
	return CAListItem{}, errCANotFound
}

func (p *fileCAProvider) DeleteCA(_ context.Context, id string) error {
	items, ok := p.loadItems()
	if !ok {
		return errCANotFound
	}

	idx := -1
	for i := range items {
		if items[i].ID != id {
			continue
		}
		idx = i
		break
	}
	if idx < 0 {
		return errCANotFound
	}

	status := items[idx].Status
	if status != "revoked" && status != "expired" {
		return errCAUnprocessable
	}
	if items[idx].ActiveIssuedCertificates > 0 {
		return errCAConflict
	}

	items = append(items[:idx], items[idx+1:]...)
	if err := p.saveItems(items); err != nil {
		return err
	}
	return nil
}

func (p *fileCAProvider) SuspendCA(_ context.Context, id string) (CAStatusChange, error) {
	items, ok := p.loadItems()
	if !ok {
		return CAStatusChange{}, errCANotFound
	}

	now := time.Now().UTC().Format(time.RFC3339)
	for i := range items {
		if items[i].ID != id {
			continue
		}
		if items[i].Status == "suspended" || items[i].Status == "revoked" || items[i].Status == "expired" {
			return CAStatusChange{}, errCAConflict
		}
		items[i].Status = "suspended"
		items[i].UpdatedAt = now
		if err := p.saveItems(items); err != nil {
			return CAStatusChange{}, err
		}
		return CAStatusChange{ID: id, Status: "suspended", UpdatedAt: now}, nil
	}
	return CAStatusChange{}, errCANotFound
}

func (p *fileCAProvider) ActivateCA(_ context.Context, id string) (CAStatusChange, error) {
	items, ok := p.loadItems()
	if !ok {
		return CAStatusChange{}, errCANotFound
	}

	now := time.Now().UTC().Format(time.RFC3339)
	for i := range items {
		if items[i].ID != id {
			continue
		}
		if items[i].Status != "suspended" && items[i].Status != "pending_ceremony" {
			return CAStatusChange{}, errCAConflict
		}
		items[i].Status = "active"
		items[i].UpdatedAt = now
		if err := p.saveItems(items); err != nil {
			return CAStatusChange{}, err
		}
		return CAStatusChange{ID: id, Status: "active", UpdatedAt: now}, nil
	}
	return CAStatusChange{}, errCANotFound
}

func (p *fileCAProvider) CreateCA(_ context.Context, _ CACreateRequest) (CAListItem, error) {
	return CAListItem{}, errCACreateUnsupported
}

func (p *fileCAProvider) loadItems() ([]CAListItem, bool) {
	body, err := os.ReadFile(p.filePath)
	if err != nil {
		log.Printf("ca file fallback: unreadable %q: %v", p.filePath, err)
		return nil, false
	}

	var items []CAListItem
	if err := json.Unmarshal(body, &items); err != nil {
		log.Printf("ca file fallback: invalid JSON")
		return nil, false
	}
	return items, true
}

func (p *fileCAProvider) saveItems(items []CAListItem) error {
	body, err := json.Marshal(items)
	if err != nil {
		return err
	}
	return writeStateFile(p.filePath, body)
}
