// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Every catalog report renders in every format it advertises, and the
// validator accepts exactly the advertised matrix (W38-06).
func TestReportCatalogRendersEveryAdvertisedFormat(t *testing.T) {
	store := newTestReportScheduleStore(t)
	s := newTestReportScheduler(t, store, nil)
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	for _, name := range scheduledReportNames() {
		def := reportScheduleCatalog[name]
		for _, f := range def.Formats {
			sched := ReportSchedule{Report: name, Format: f, Cadence: "daily", Recipients: []string{"a@example.com"}}
			if err := validateReportSchedule(&sched); err != nil {
				t.Fatalf("%s/%s should validate: %v", name, f, err)
			}
			body, fn, ct, err := s.renderScheduledReport(context.Background(), sched, now)
			if err != nil {
				t.Fatalf("%s/%s render: %v", name, f, err)
			}
			if len(body) == 0 || !strings.HasSuffix(fn, "."+f) || ct == "" {
				t.Fatalf("%s/%s: empty body or bad name/type (%q, %q)", name, f, fn, ct)
			}
			switch f {
			case "pdf":
				if !bytes.HasPrefix(body, []byte("%PDF-")) {
					t.Fatalf("%s pdf is not a PDF", name)
				}
			case "xlsx":
				if !bytes.HasPrefix(body, []byte("PK")) {
					t.Fatalf("%s xlsx is not a zip", name)
				}
			case "csv":
				if !bytes.Contains(body, []byte("\n")) {
					t.Fatalf("%s csv has no header row", name)
				}
			}
		}
		for _, f := range []string{"csv", "xlsx", "pdf"} {
			wantReject := !slices.Contains(def.Formats, f)
			sched := ReportSchedule{Report: name, Format: f, Recipients: []string{"a@example.com"}}
			if err := validateReportSchedule(&sched); (err != nil) != wantReject {
				t.Fatalf("%s/%s validate err=%v, want rejection=%v", name, f, err, wantReject)
			}
		}
	}
}

// The crypto-posture sheet carries the compute function's number, not its own.
func TestReportCatalogUsesComputeFunctions(t *testing.T) {
	in := scheduledReportInputs{certs: buildTestCerts()}
	_, rows := reportScheduleCatalog["crypto-posture"].table(in)
	want := computeCryptoPostureReport(in.certs, nil).TotalCerts
	if rows[0][0] != "total" || rows[0][2] != strconv.Itoa(want) {
		t.Fatalf("first row %v, want total %d", rows[0], want)
	}
}

func TestReportScheduleCatalogEndpoint(t *testing.T) {
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	RegisterReportScheduleHandlers(mux, auth, newTestReportScheduleStore(t), &recordingAuditProvider{})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/reports/schedules/catalog", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth: %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/schedules/catalog", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("catalog: %d", rec.Code)
	}
	var body struct {
		Data []ReportScheduleCatalogEntry `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Data) != len(reportScheduleCatalog) {
		t.Fatalf("decode: %v len=%d", err, len(body.Data))
	}
}

func TestReportScheduleDailyCadenceDue(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	s := ReportSchedule{Cadence: "daily", Recipients: []string{"a@x.com"}, Enabled: true, LastSentAt: now.Add(-25 * time.Hour).Format(time.RFC3339)}
	if !s.isDue(now) {
		t.Fatal("daily schedule last sent 25h ago must be due")
	}
	s.LastSentAt = now.Add(-2 * time.Hour).Format(time.RFC3339)
	if s.isDue(now) {
		t.Fatal("daily schedule sent 2h ago must not be due")
	}
}
