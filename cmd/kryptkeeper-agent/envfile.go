// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// serviceEnvFile is set when the agent runs under a service manager; it is the
// file settings were loaded from and where registration credentials persist.
var serviceEnvFile string

// loadEnvFile applies KEY=VALUE lines to the process environment. Blank lines
// and #-comments are skipped; a variable already set in the environment wins,
// so an operator can override one value without editing the file.
func loadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return fmt.Errorf("%s:%d: expected KEY=VALUE", path, n)
		}
		if _, set := os.LookupEnv(k); !set {
			os.Setenv(k, strings.TrimSpace(v))
		}
	}
	return sc.Err()
}

// persistCredentials appends the registration result so the next start reuses
// it. The file already exists (settings were loaded from it) and keeps its ACL.
func persistCredentials(path, agentID, token string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "\nKRYPTKEEPER_AGENT_ID=%s\nKRYPTKEEPER_AGENT_TOKEN=%s\n", agentID, token)
	return err
}

// credentialsFilePath is where a console run keeps its registration:
// KRYPTKEEPER_AGENT_CREDENTIALS_FILE, else <user config dir>/kryptkeeper-agent/
// credentials.env. Empty when neither can be determined.
func credentialsFilePath() string {
	if p := strings.TrimSpace(os.Getenv("KRYPTKEEPER_AGENT_CREDENTIALS_FILE")); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "kryptkeeper-agent", "credentials.env")
}

// writeCredentialsFile stores the registration result readable by the owner
// only (directory 0700, file 0600), replacing any previous registration.
func writeCredentialsFile(path, agentID, token string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("KRYPTKEEPER_AGENT_ID=%s\nKRYPTKEEPER_AGENT_TOKEN=%s\n", agentID, token)), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
