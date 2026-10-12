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
)

const defaultCertsSummaryFile = "./var/certs-summary.json"

type fileCertSummaryProvider struct {
	filePath string
}

func NewFileCertSummaryProviderFromEnv() CertSummaryProvider {
	filePath := strings.TrimSpace(os.Getenv("APP_CERTS_SUMMARY_FILE"))
	if filePath == "" {
		filePath = defaultCertsSummaryFile
	}

	return &fileCertSummaryProvider{filePath: filePath}
}

func (s *fileCertSummaryProvider) LoadSummary(context.Context) (CertSummarySnapshot, error) {
	body, err := os.ReadFile(s.filePath)
	if err != nil {
		log.Printf("cert summary file fallback: unreadable %q: %v", s.filePath, err)
		return defaultCertsSummarySnapshot(), nil
	}

	var parsed struct {
		Total          *int `json:"total"`
		Expiring30Days *int `json:"expiring_30_days"`
		Expired        *int `json:"expired"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		log.Printf("cert summary file fallback: invalid JSON")
		return defaultCertsSummarySnapshot(), nil
	}

	if parsed.Total == nil || parsed.Expiring30Days == nil || parsed.Expired == nil {
		log.Printf("cert summary file fallback: missing fields")
		return defaultCertsSummarySnapshot(), nil
	}

	if *parsed.Total < 0 || *parsed.Expiring30Days < 0 || *parsed.Expired < 0 {
		log.Printf("cert summary file fallback: negative values")
		return defaultCertsSummarySnapshot(), nil
	}

	return CertSummarySnapshot{
		Total:          *parsed.Total,
		Expiring30Days: *parsed.Expiring30Days,
		Expired:        *parsed.Expired,
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
