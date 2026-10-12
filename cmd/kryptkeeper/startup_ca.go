// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// envTrue parses a boolean env flag the same way bootstrap's envBool does
// (case-insensitive "true", or "1") so "TRUE" and "1" are not silently
// treated as unset by a bare == "true" comparison.
func envTrue(getenv func(string) string, name string) bool {
	raw := strings.TrimSpace(getenv(name))
	return strings.EqualFold(raw, "true") || raw == "1"
}

// attachPolicyEngine arms the issuance policy gate (W5-05). A build failure
// is an error rather than a log line: swallowing it leaves the engine with
// no policy, so every issuance would skip the gate with nothing but a
// missing "enabled" log to show for it. An operator who truly wants to run
// without the gate must say so with KRYPTKEEPER_ALLOW_NO_POLICY=true, which
// downgrades the failure to a loud warning.
func attachPolicyEngine(engine *ca.Engine, db *sql.DB, postgres bool, getenv func(string) string) error {
	pe, err := ca.NewPolicyEngine(db, postgres)
	if err != nil {
		if envTrue(getenv, "KRYPTKEEPER_ALLOW_NO_POLICY") {
			log.Printf("WARNING: issuance policy gate DISABLED (%v) -- KRYPTKEEPER_ALLOW_NO_POLICY=true; certificates will be issued without policy evaluation", err)
			return nil
		}
		return fmt.Errorf("issuance policy engine: %w (set KRYPTKEEPER_ALLOW_NO_POLICY=true to start without the policy gate)", err)
	}
	engine.SetPolicyEngine(pe)
	log.Print("issuance policy engine: enabled (issuance_policies table)")
	return nil
}

// resolveDefaultCA returns the default CA id: the explicit
// KRYPTKEEPER_DEFAULT_CA_ID, else the first stored CA, else (only when
// KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT is true) a freshly minted root. The
// ListCAs error is checked BEFORE the emptiness test: treating a transient
// read failure as "no CAs" while bootstrap is enabled would mint a second
// root next to the real one. For the same reason the flag is safe to leave
// set permanently: once any CA exists it is never consulted.
func resolveDefaultCA(svc ca.Service, getenv func(string) string) (string, error) {
	if id := getenv("KRYPTKEEPER_DEFAULT_CA_ID"); id != "" {
		return id, nil
	}
	cas, err := svc.ListCAs()
	if err != nil {
		return "", fmt.Errorf("list CAs: %w", err)
	}
	if len(cas) > 0 {
		return cas[0].ID, nil
	}
	if !envTrue(getenv, "KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT") {
		return "", errors.New("no CA configured — set KRYPTKEEPER_DEFAULT_CA_ID to an existing CA, or on a fresh install let the hub create its first root: add KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true to your .env (docker compose) or environment, then restart")
	}
	caName := getenv("KRYPTKEEPER_CA_NAME")
	if caName == "" {
		caName = "Kryptkeeper Root CA"
	}
	rootCA, err := svc.CreateRootCA(caName, pkix.Name{
		CommonName:   caName,
		Organization: []string{"Kryptkeeper"},
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		return "", fmt.Errorf("bootstrap root CA: %w", err)
	}
	log.Printf("[BOOTSTRAP] created root CA %q (id: %s) (KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT only acts when no CA exists, so it is safe to leave set)", caName, rootCA.ID)
	return rootCA.ID, nil
}
