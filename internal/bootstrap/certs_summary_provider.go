// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"os"
	"strings"

	"kryptkeeper/internal/logging"
)

const certSummaryProviderEnv = "APP_CERTS_SUMMARY_PROVIDER"

var certSummaryProviderWarnf = logging.Warnf

const (
	certSummaryProviderFile = "file"
	certSummaryProviderDB   = "db"
)

type CertSummarySnapshot struct {
	// Total counts active (non-revoked) certificates -- the rule in
	// certificate_active.go; every other field below is also active-only.
	// Revoked is the complement, reported separately.
	Total          int
	Revoked        int
	Expiring30Days int
	Expired        int
	// Estate split (W11-01, V5/D-106): certificates by management_state.
	// File-backed summaries report zeros -- the split needs the DB.
	Managed   int
	External  int
	Unmanaged int
	// Unowned counts active certificates with no owner team (W22-24);
	// file-backed summaries report it only when the summary file carries it.
	Unowned int
	Source  string
}

type CertSummaryProvider interface {
	LoadSummary(context.Context) (CertSummarySnapshot, error)
}

func NewCertSummaryProviderFromEnv() CertSummaryProvider {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(certSummaryProviderEnv)))
	switch mode {
	case "":
		// S-68: unset follows the certificate provider. In ca mode issuance
		// persists to the core DB, and both stores resolve the same
		// KRYPTKEEPER_DATA_DIR / KRYPTKEEPER_DB_DSN defaults, so counting the
		// file store here reports 0 forever while the inventory fills up.
		// An explicit APP_CERTS_SUMMARY_PROVIDER still wins either way.
		if strings.ToLower(strings.TrimSpace(os.Getenv(certificateProviderEnv))) == certificateProviderCA {
			return newDBCertSummaryProviderFromEnv()
		}
		return NewFileCertSummaryProviderFromEnv()
	case certSummaryProviderFile:
		return NewFileCertSummaryProviderFromEnv()
	case certSummaryProviderDB:
		return newDBCertSummaryProviderFromEnv()
	default:
		certSummaryProviderWarnf("warning: unknown APP_CERTS_SUMMARY_PROVIDER=%q; falling back to file", mode)
		return NewFileCertSummaryProviderFromEnv()
	}
}
