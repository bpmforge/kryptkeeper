// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// W11-05: direct-CA inventory sync — see the estate before migrating it.
// Sources pull issued-certificate inventory READ-ONLY from the systems that
// issued it; write paths to commercial CAs stay on the W11-03 connector
// interface. Synced certs enter as origin=synced / management_state=external
// (the upstream CA manages them — "unmanaged" is reserved for certs nobody
// demonstrably manages); the W11-06 takeover flips them when wanted.

var (
	errInventorySourceNotFound = errors.New("inventory source not found")
	errInventorySourceInvalid  = errors.New("inventory source name and a type of adcs_export|adcs_live|digicert|sectigo|entrust|aws_pca|gcp_cas are required")
	validInventorySourceTypes  = map[string]bool{"adcs_export": true, "adcs_live": true, "digicert": true, "sectigo": true, "entrust": true, "aws_pca": true, "gcp_cas": true}
)

// SyncedCertificate is one certificate as reported by an external CA.
type SyncedCertificate struct {
	PEM            string
	UpstreamStatus string // active | revoked
}

// InventorySource pulls the current issued-cert inventory from one external
// CA. Implementations must be read-only against the upstream.
type InventorySource interface {
	Fetch(ctx context.Context) ([]SyncedCertificate, error)
}

// InventorySourceRecord is a stored source configuration.
type InventorySourceRecord struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	ConfigJSON      string `json:"config_json"`
	CredentialRef   string `json:"credential_ref,omitempty"`
	ScheduleMinutes int    `json:"schedule_minutes"`
	Tenant          string `json:"tenant"`
	LastSyncAt      string `json:"last_sync_at,omitempty"`
	LastSyncResult  string `json:"last_sync_result,omitempty"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// InventorySyncResult is one sync run's report.
type InventorySyncResult struct {
	Synced        int      `json:"synced"`
	Skipped       int      `json:"skipped"`
	RevokedMarked int      `json:"revoked_marked"`
	Failed        []string `json:"failed,omitempty"`
}

// --- adapters ---------------------------------------------------------------

// adcsExportSource reads a Microsoft ADCS certificate export: a concatenated
// PEM bundle file, or a directory of .pem/.cer/.crt/.der files (the
// documented certutil/ldifde export path). A plain export carries no
// disposition data, so every row syncs as active; live LDAP pull is a
// go-ldap dependency decision, deferred (spec decision 3).
type adcsExportSource struct {
	exportPath string
}

func newADCSExportSource(configJSON string) (InventorySource, error) {
	var cfg struct {
		ExportPath string `json:"export_path"`
	}
	_ = json.Unmarshal([]byte(configJSON), &cfg) // malformed config zeroes out; the empty-field check below catches it
	if cfg.ExportPath == "" {
		return nil, errors.New("adcs_export source requires config_json.export_path (a PEM bundle or a directory of exported certificates)")
	}
	return &adcsExportSource{exportPath: cfg.ExportPath}, nil
}

func (s *adcsExportSource) Fetch(_ context.Context) ([]SyncedCertificate, error) {
	info, err := os.Stat(s.exportPath)
	if err != nil {
		return nil, fmt.Errorf("adcs export path: %w", err)
	}
	var files []string
	if info.IsDir() {
		entries, err := os.ReadDir(s.exportPath)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			switch strings.ToLower(filepath.Ext(e.Name())) {
			case ".pem", ".cer", ".crt", ".der":
				files = append(files, filepath.Join(s.exportPath, e.Name()))
			}
		}
	} else {
		files = []string{s.exportPath}
	}

	var out []SyncedCertificate
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		if !strings.Contains(string(body), "BEGIN CERTIFICATE") {
			// Raw DER file: wrap it.
			out = append(out, SyncedCertificate{
				PEM:            string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: body})),
				UpstreamStatus: "active",
			})
			continue
		}
		rest := body
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			out = append(out, SyncedCertificate{
				PEM:            string(pem.EncodeToMemory(block)),
				UpstreamStatus: "active",
			})
		}
	}
	return out, nil
}

// digicertSource pulls issued certs from DigiCert CertCentral. Endpoint
// shapes are from the vendor docs (dev.digicert.com, fetched 2026-08-18):
// GET {base}/services/v2/order/certificate with header X-DC-DEVKEY returns
// {"orders":[{"id":..,"status":"issued|revoked|..","certificate":{"id":..}}]};
// GET {base}/services/v2/certificate/{certificate_id}/download/format/pem
// returns the PEM.
type digicertSource struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

func newDigicertSource(ctx context.Context, configJSON, credentialRef string, creds OutboundCredentialStore) (InventorySource, error) {
	var cfg struct {
		BaseURL string `json:"base_url"`
	}
	_ = json.Unmarshal([]byte(configJSON), &cfg) // malformed config zeroes out; default substituted below
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://www.digicert.com"
	}
	if credentialRef == "" || creds == nil {
		return nil, errors.New("digicert source requires credential_ref holding the CertCentral API key")
	}
	keyBytes, err := creds.Resolve(ctx, credentialRef)
	if err != nil {
		return nil, fmt.Errorf("digicert credential %q: %w", credentialRef, err)
	}
	return &digicertSource{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:  credentialSecretString(keyBytes, "api_key"),
		client:  inventoryHTTPClient(30 * time.Second),
	}, nil
}

func (s *digicertSource) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-DC-DEVKEY", s.apiKey)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("digicert %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body[:min(len(body), 300)])))
	}
	return body, nil
}

func (s *digicertSource) Fetch(ctx context.Context) ([]SyncedCertificate, error) {
	body, err := s.get(ctx, "/services/v2/order/certificate")
	if err != nil {
		return nil, err
	}
	var listing struct {
		Orders []struct {
			ID          int    `json:"id"`
			Status      string `json:"status"`
			Certificate struct {
				ID int `json:"id"`
			} `json:"certificate"`
		} `json:"orders"`
	}
	if err := json.Unmarshal(body, &listing); err != nil {
		return nil, fmt.Errorf("digicert order listing unparseable: %w", err)
	}
	var out []SyncedCertificate
	for _, order := range listing.Orders {
		if order.Certificate.ID == 0 {
			continue // not issued yet — nothing to sync
		}
		pemBody, err := s.get(ctx, fmt.Sprintf("/services/v2/certificate/%d/download/format/pem", order.Certificate.ID))
		if err != nil {
			return nil, fmt.Errorf("digicert order %d: %w", order.ID, err)
		}
		status := "active"
		if strings.EqualFold(order.Status, "revoked") {
			status = "revoked"
		}
		out = append(out, SyncedCertificate{PEM: string(pemBody), UpstreamStatus: status})
	}
	return out, nil
}

// buildInventorySource materializes a stored record into a runtime source.
func buildInventorySource(ctx context.Context, rec InventorySourceRecord, creds OutboundCredentialStore) (InventorySource, error) {
	switch rec.Type {
	case "adcs_export":
		return newADCSExportSource(rec.ConfigJSON)
	case "adcs_live":
		return newADCSLiveSource(ctx, rec.ConfigJSON, rec.CredentialRef, creds)
	case "digicert":
		return newDigicertSource(ctx, rec.ConfigJSON, rec.CredentialRef, creds)
	case "sectigo":
		return newSectigoSource(ctx, rec.ConfigJSON, rec.CredentialRef, creds)
	case "entrust":
		return newEntrustSource(ctx, rec.ConfigJSON, rec.CredentialRef, creds)
	case "aws_pca":
		return newAWSPCASource(ctx, rec.ConfigJSON, rec.CredentialRef, creds)
	case "gcp_cas":
		return newGCPCASSource(ctx, rec.ConfigJSON, rec.CredentialRef, creds)
	default:
		return nil, fmt.Errorf("inventory source type %q has no implementation", rec.Type)
	}
}

// --- sync engine ------------------------------------------------------------

// syncInventorySource runs one pull: every fetched cert routes through the
// production ImportCertificate (fingerprint conflict = already known =
// skipped — idempotent re-sync), then the estate stamp. Per-item failures
// never sink the batch.
func syncInventorySource(ctx context.Context, source InventorySource, sourceID string, provider CertificateProvider) (InventorySyncResult, error) {
	result := InventorySyncResult{Failed: []string{}}
	certs, err := source.Fetch(ctx)
	if err != nil {
		return result, err
	}
	for i, cert := range certs {
		imported, err := provider.ImportCertificate(ctx, CertificateImportRequest{CertificatePEM: cert.PEM})
		fingerprint := ""
		switch {
		case err == nil:
			fingerprint = imported.CertificateItem.FingerprintSHA256
			result.Synced++
		case errors.Is(err, errCertificateConflict):
			fingerprint = agentFingerprintOfPEM(cert.PEM)
			result.Skipped++
		default:
			if len(result.Failed) < 20 {
				result.Failed = append(result.Failed, fmt.Sprintf("#%d: %v", i, err))
			}
			continue
		}
		update := EstateUpdate{Origin: "synced", ManagementState: "external"}
		// A known certificate someone took over stays managed: a re-sync
		// (scheduled or manual) must never undo a takeover (B3). Origin is
		// left alone too, so revert still derives the right prior state.
		if errors.Is(err, errCertificateConflict) && certificateIsManaged(ctx, provider, fingerprint) {
			update = EstateUpdate{}
		}
		if cert.UpstreamStatus == "revoked" {
			update.RenewalStatus = string(RenewalStatusRevoked)
			result.RevokedMarked++
		}
		if update == (EstateUpdate{}) {
			continue
		}
		if _, err := provider.UpdateEstate(ctx, fingerprint, update); err != nil {
			if len(result.Failed) < 20 {
				result.Failed = append(result.Failed, fmt.Sprintf("#%d estate: %v", i, err))
			}
		}
	}
	_ = sourceID
	return result, nil
}

// certificateIsManaged reports whether fingerprint is a managed certificate.
// A lookup failure counts as managed: skipping one estate stamp is safe,
// silently reverting a takeover is not.
func certificateIsManaged(ctx context.Context, provider CertificateProvider, fingerprint string) bool {
	d, ok, err := provider.GetCertificate(ctx, fingerprint)
	if err != nil {
		return true
	}
	return ok && d.ManagementState == "managed"
}

// --- store ------------------------------------------------------------------

const inventorySourceSchema = `
CREATE TABLE IF NOT EXISTS inventory_sources (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    type             TEXT NOT NULL CHECK (type IN ('adcs_export', 'adcs_live', 'digicert', 'sectigo', 'entrust', 'aws_pca', 'gcp_cas')),
    config_json      TEXT NOT NULL DEFAULT '{}',
    credential_ref   TEXT,
    schedule_minutes INTEGER NOT NULL DEFAULT 0
                     CHECK (schedule_minutes >= 0),
    tenant           TEXT NOT NULL DEFAULT 'default',
    last_sync_at     TEXT,
    last_sync_result TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inventory_sources_tenant ON inventory_sources(tenant);`

type InventorySourceStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, rec InventorySourceRecord) (InventorySourceRecord, error)
	Get(ctx context.Context, id string) (InventorySourceRecord, error)
	List(ctx context.Context) ([]InventorySourceRecord, error)
	Delete(ctx context.Context, id string) error
	RecordSync(ctx context.Context, id, at, result string) error
}

type dbInventorySourceStore struct {
	db       *sql.DB
	postgres bool
}

func newInventorySourceStore(db *sql.DB, postgres bool) InventorySourceStore {
	return &dbInventorySourceStore{db: db, postgres: postgres}
}

func (s *dbInventorySourceStore) ph(n int) string {
	if s.postgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func (s *dbInventorySourceStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, inventorySourceSchema)
	return err
}

func (s *dbInventorySourceStore) Create(ctx context.Context, rec InventorySourceRecord) (InventorySourceRecord, error) {
	if strings.TrimSpace(rec.Name) == "" || !validInventorySourceTypes[rec.Type] {
		return InventorySourceRecord{}, errInventorySourceInvalid
	}
	if rec.ConfigJSON == "" {
		rec.ConfigJSON = "{}"
	}
	if rec.Tenant == "" {
		rec.Tenant = DefaultTenant
	}
	now := time.Now().UTC().Format(time.RFC3339)
	rec.CreatedAt, rec.UpdatedAt = now, now
	q := fmt.Sprintf(`INSERT INTO inventory_sources (id, name, type, config_json, credential_ref, schedule_minutes, tenant, created_at, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9))
	_, err := s.db.ExecContext(ctx, q,
		rec.ID, rec.Name, rec.Type, rec.ConfigJSON, nullString(rec.CredentialRef), rec.ScheduleMinutes, rec.Tenant, rec.CreatedAt, rec.UpdatedAt)
	if err != nil {
		return InventorySourceRecord{}, err
	}
	return rec, nil
}

func (s *dbInventorySourceStore) Get(ctx context.Context, id string) (InventorySourceRecord, error) {
	q := fmt.Sprintf(`SELECT id, name, type, config_json, credential_ref, schedule_minutes, tenant,
		COALESCE(last_sync_at,''), COALESCE(last_sync_result,''), created_at, updated_at
		FROM inventory_sources WHERE id = %s`, s.ph(1))
	row := s.db.QueryRowContext(ctx, q, id)
	return scanInventorySource(row)
}

func (s *dbInventorySourceStore) List(ctx context.Context) ([]InventorySourceRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, type, config_json, credential_ref, schedule_minutes, tenant,
		COALESCE(last_sync_at,''), COALESCE(last_sync_result,''), created_at, updated_at
		FROM inventory_sources ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []InventorySourceRecord{}
	for rows.Next() {
		var rec InventorySourceRecord
		var credRef sql.NullString
		if err := rows.Scan(&rec.ID, &rec.Name, &rec.Type, &rec.ConfigJSON, &credRef, &rec.ScheduleMinutes, &rec.Tenant,
			&rec.LastSyncAt, &rec.LastSyncResult, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		rec.CredentialRef = credRef.String
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *dbInventorySourceStore) Delete(ctx context.Context, id string) error {
	q := fmt.Sprintf(`DELETE FROM inventory_sources WHERE id = %s`, s.ph(1))
	res, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errInventorySourceNotFound
	}
	return nil
}

func (s *dbInventorySourceStore) RecordSync(ctx context.Context, id, at, result string) error {
	q := fmt.Sprintf(`UPDATE inventory_sources SET last_sync_at=%s, last_sync_result=%s, updated_at=%s WHERE id=%s`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4))
	_, err := s.db.ExecContext(ctx, q, at, result, at, id)
	return err
}

func scanInventorySource(row *sql.Row) (InventorySourceRecord, error) {
	var rec InventorySourceRecord
	var credRef sql.NullString
	err := row.Scan(&rec.ID, &rec.Name, &rec.Type, &rec.ConfigJSON, &credRef, &rec.ScheduleMinutes, &rec.Tenant,
		&rec.LastSyncAt, &rec.LastSyncResult, &rec.CreatedAt, &rec.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return InventorySourceRecord{}, errInventorySourceNotFound
	}
	if err != nil {
		return InventorySourceRecord{}, err
	}
	rec.CredentialRef = credRef.String
	return rec, nil
}

func newInventorySourceID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "invsrc-" + hex.EncodeToString(buf), nil
}

func newInventorySourceStoreFromEnv() InventorySourceStore {
	state := newDBProviderState[InventorySourceStore](
		"inventory-source",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_INVENTORY_SOURCES_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_INVENTORY_SOURCES_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_INVENTORY_SOURCES_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) InventorySourceStore { return newInventorySourceStore(db, false) },
		func(db *sql.DB) InventorySourceStore { return newInventorySourceStore(db, true) },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("inventory-source", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("inventory-source", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}

// --- scheduler --------------------------------------------------------------

// InventorySyncScheduler ticks every checkInterval and runs each source whose
// schedule_minutes has elapsed since its last sync. 0 = manual-only.
type InventorySyncScheduler struct {
	store    InventorySourceStore
	provider CertificateProvider
	creds    OutboundCredentialStore

	checkInterval time.Duration
	stop          chan struct{}

	haCoordinator *HACoordinator   // nil => single-replica behaviour (no gate)
	now           func() time.Time // nil => time.Now; test seam
}

// haLockInventorySyncPrefix + source ID names the per-source sync lease, so
// replicas may legitimately sync different sources but never the same one in
// the same interval.
const haLockInventorySyncPrefix = "inventory-sync:"

// inventorySyncTimeout bounds one source's sync so a hung vendor cannot wedge
// the scheduler.
const inventorySyncTimeout = 30 * time.Minute

// newInventorySourceForSync is a test seam (production = buildInventorySource).
var newInventorySourceForSync = buildInventorySource

func (s *InventorySyncScheduler) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func NewInventorySyncSchedulerFromEnv(provider CertificateProvider) *InventorySyncScheduler {
	return &InventorySyncScheduler{
		store:         newInventorySourceStoreFromEnv(),
		provider:      provider,
		creds:         newOutboundCredentialStoreFromEnv(),
		checkInterval: time.Hour,
		stop:          make(chan struct{}),
		haCoordinator: newHACoordinatorFromEnvLogged(),
	}
}

func (s *InventorySyncScheduler) Start() {
	if s.store == nil {
		logging.Warn("inventory sync scheduler: store unavailable; scheduled syncs disabled (manual syncs via the API still work when the store returns)")
		return
	}
	go func() {
		ticker := time.NewTicker(s.checkInterval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-ticker.C:
				s.runDue(context.Background())
			}
		}
	}()
}

func (s *InventorySyncScheduler) Stop() { close(s.stop) }

func (s *InventorySyncScheduler) runDue(ctx context.Context) {
	recs, err := s.store.List(ctx)
	if err != nil {
		logging.Warnf("inventory sync scheduler: list failed: %v", err)
		return
	}
	now := s.clock().UTC()
	for _, rec := range recs {
		if rec.ScheduleMinutes <= 0 {
			continue
		}
		if rec.LastSyncAt != "" {
			last, err := time.Parse(time.RFC3339, rec.LastSyncAt)
			if err == nil && now.Sub(last) < time.Duration(rec.ScheduleMinutes)*time.Minute {
				continue
			}
		}
		// Held for the whole interval and never released: that is what makes
		// it one sync per source per interval. The holder renews on its next
		// due tick; a crashed holder's lease lapses and a peer takes over.
		if s.haCoordinator != nil {
			lease := time.Duration(rec.ScheduleMinutes) * time.Minute
			ok, err := s.haCoordinator.TryAcquire(ctx, haLockInventorySyncPrefix+rec.ID, lease)
			if err != nil {
				logging.Warnf("inventory sync scheduler: ha lock check failed for %s, skipping: %v", rec.ID, err)
				continue
			}
			if !ok {
				continue
			}
		}
		source, err := newInventorySourceForSync(ctx, rec, s.creds)
		if err != nil {
			logging.Infof("inventory sync scheduler: source %s unbuildable: %v", rec.ID, err)
			continue
		}
		syncCtx, cancel := context.WithTimeout(ctx, inventorySyncTimeout)
		result, err := syncInventorySource(syncCtx, source, rec.ID, s.provider)
		cancel()
		summary, _ := json.Marshal(result)
		if err != nil {
			summary = []byte(fmt.Sprintf(`{"error":%q}`, err.Error()))
			logging.Warnf("inventory sync scheduler: sync %s failed: %v", rec.ID, err)
		}
		if err := s.store.RecordSync(ctx, rec.ID, now.Format(time.RFC3339), string(summary)); err != nil {
			logging.Warnf("inventory sync scheduler: record sync %s failed: %v", rec.ID, err)
		}
	}
}
