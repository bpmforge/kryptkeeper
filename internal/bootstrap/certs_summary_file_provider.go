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

type fileCertSummaryProvider struct {
	filePath string
}

func NewFileCertSummaryProviderFromEnv() CertSummaryProvider {
	filePath := resolveStateFilePath(os.Getenv, "APP_CERTS_SUMMARY_FILE", "certs-summary.json")

	return &fileCertSummaryProvider{filePath: filePath}
}

func (s *fileCertSummaryProvider) LoadSummary(context.Context) (CertSummarySnapshot, error) {
	body, err := os.ReadFile(s.filePath)
	if err != nil {
		logging.Infof("cert summary file fallback: unreadable %q: %v", s.filePath, err)
		return defaultCertsSummarySnapshot(), nil
	}

	var parsed struct {
		Total          *int `json:"total"`
		Expiring30Days *int `json:"expiring_30_days"`
		Expired        *int `json:"expired"`
		Unowned        int  `json:"unowned"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		logging.Infof("cert summary file fallback: invalid JSON")
		return defaultCertsSummarySnapshot(), nil
	}

	if parsed.Total == nil || parsed.Expiring30Days == nil || parsed.Expired == nil {
		logging.Infof("cert summary file fallback: missing fields")
		return defaultCertsSummarySnapshot(), nil
	}

	if *parsed.Total < 0 || *parsed.Expiring30Days < 0 || *parsed.Expired < 0 {
		logging.Infof("cert summary file fallback: negative values")
		return defaultCertsSummarySnapshot(), nil
	}

	return CertSummarySnapshot{
		Total:          *parsed.Total,
		Expiring30Days: *parsed.Expiring30Days,
		Expired:        *parsed.Expired,
		Unowned:        max(parsed.Unowned, 0),
		Source:         "file-store",
	}, nil
}

func defaultCertsSummarySnapshot() CertSummarySnapshot {
	return CertSummarySnapshot{
		Total:          0,
		Expiring30Days: 0,
		Expired:        0,
		Source:         "file-store-default",
	}
}
