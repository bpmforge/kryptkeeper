// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package trustpush

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// entry records one certificate Kryptkeeper added. Removal consults this file
// and nothing else, so a root an administrator installed by hand is never
// deleted because a bundle happened to name it.
type entry struct {
	SHA1    string `json:"sha1"`
	Subject string `json:"subject"`
	Path    string `json:"path,omitempty"`
	Store   string `json:"store,omitempty"`
	Root    bool   `json:"root,omitempty"`
	AddedAt string `json:"added_at"`
}

type state struct {
	Certs map[string]entry `json:"certs"` // keyed by SHA-256 of the DER
}

// DefaultStatePath is where the state lives on goos.
func DefaultStatePath(goos string, getenv func(string) string) string {
	if goos == "windows" {
		pd := getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "Kryptkeeper", "trust-state.json")
	}
	return "/var/lib/kryptkeeper-agent/trust-state.json"
}

func loadState(path string) (*state, error) {
	st := &state{Certs: map[string]entry{}}
	if path == "" {
		return nil, errors.New("no state path")
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, st); err != nil {
		return nil, err
	}
	if st.Certs == nil {
		st.Certs = map[string]entry{}
	}
	return st, nil
}

func (s *state) save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- directory holds public data only
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil { // #nosec G306 -- fingerprints and subjects of public certificates
		return err
	}
	return os.Rename(tmp, path)
}
