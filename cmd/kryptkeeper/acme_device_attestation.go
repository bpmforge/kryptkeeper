// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/x509"
	"database/sql"
	"net/http"
	"os"
	"strings"

	"kryptkeeper/internal/acme"
	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/logging"
)

const (
	acmeAppleAttestationRootsEnv = "KRYPTKEEPER_ACME_APPLE_ATTESTATION_ROOTS"
	acmeTPMAttestationRootsEnv   = "KRYPTKEEPER_ACME_TPM_ATTESTATION_ROOTS"
)

// loadAttestationRoots reads a PEM bundle named by env. Unset is "format off".
// A set but unreadable or empty bundle also leaves the format off, loudly:
// trusting nothing is the safe reading of a broken trust configuration.
func loadAttestationRoots(envVar string) *x509.CertPool {
	path := strings.TrimSpace(os.Getenv(envVar))
	if path == "" {
		return nil
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		logging.Warnf("%s: %v - that attestation format stays off", envVar, err)
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		logging.Warnf("%s: no certificate found in %s - that attestation format stays off", envVar, path)
		return nil
	}
	return pool
}

// configureACMEDeviceAttestation wires the device inventory API and, when an
// operator configured attestation roots, the device-attest-01 challenge
// (W40-02). The operator supplies every root; none is built in.
func configureACMEDeviceAttestation(srv *acme.Server, auth *bootstrap.Authenticator, db *sql.DB, isPostgres bool,
	audit bootstrap.AuditProvider, templates bootstrap.TemplateProvider) []bootstrap.ServerOption {
	var list acme.DeviceAllowlist = acme.NewMemDeviceAllowlist()
	if db != nil {
		dbList := acme.NewDBDeviceAllowlist(db, isPostgres)
		if err := dbList.EnsureSchema(); err != nil {
			logging.Warnf("ACME device inventory schema failed (%v) - inventory kept in memory", err)
		} else {
			list = dbList
		}
	}
	apple, tpm := loadAttestationRoots(acmeAppleAttestationRootsEnv), loadAttestationRoots(acmeTPMAttestationRootsEnv)
	srv.WithDeviceAttestation(acme.DeviceAttestationConfig{
		AppleRoots:        apple,
		TPMRoots:          tpm,
		DeviceAllowed:     bootstrap.NewACMEDeviceCheck(list, bootstrap.NewTenantStoreFromEnv()),
		TemplateAllows:    bootstrap.NewACMETemplateDeviceCheck(templates),
		DefaultTemplateID: strings.TrimSpace(os.Getenv("KRYPTKEEPER_ACME_TEMPLATE")),
	})
	if apple != nil || tpm != nil {
		logging.Infof("ACME device-attest-01 enabled (apple roots: %t, tpm roots: %t); templates must set device_attestation", apple != nil, tpm != nil)
	}
	return []bootstrap.ServerOption{bootstrap.WithExtraHandlers(func(mux *http.ServeMux) {
		bootstrap.RegisterACMEDeviceHandlers(mux, auth, list, audit)
	})}
}
