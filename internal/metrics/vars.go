// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

// Latency histogram buckets in seconds: 1ms → 10s.
var durationBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 10}

// OCSP
var (
	OCSPRequestsGood    = Default.Counter("kryptkeeper_ocsp_requests_good_total", "OCSP requests answered: certificate good")
	OCSPRequestsRevoked = Default.Counter("kryptkeeper_ocsp_requests_revoked_total", "OCSP requests answered: certificate revoked")
	OCSPRequestsUnknown = Default.Counter("kryptkeeper_ocsp_requests_unknown_total", "OCSP requests answered: certificate unknown")
	OCSPRequestsError   = Default.Counter("kryptkeeper_ocsp_requests_error_total", "OCSP requests that returned an error")
)

// CRL
var (
	CRLRequestsTotal = Default.Counter("kryptkeeper_crl_requests_total", "CRL fetch requests served")
)

// Certificate issuance
var (
	CertIssueTotal    = Default.Counter("kryptkeeper_cert_issue_total", "Certificates successfully issued")
	CertIssueErrors   = Default.Counter("kryptkeeper_cert_issue_errors_total", "Certificate issuance failures")
	CertIssueDuration = Default.Histogram("kryptkeeper_cert_issue_duration_seconds", "Latency of certificate issuance end-to-end", durationBuckets)
)

// Certificate revocation
var (
	CertRevokeTotal  = Default.Counter("kryptkeeper_cert_revoke_total", "Certificates successfully revoked")
	CertRevokeErrors = Default.Counter("kryptkeeper_cert_revoke_errors_total", "Certificate revocation failures")
)

// ACME
var (
	ACMEOrdersCreated   = Default.Counter("kryptkeeper_acme_orders_created_total", "ACME orders created")
	ACMEOrdersFinalized = Default.Counter("kryptkeeper_acme_orders_finalized_total", "ACME orders successfully finalized")
	ACMEOrdersInvalid   = Default.Counter("kryptkeeper_acme_orders_invalid_total", "ACME orders that transitioned to invalid")
)

// CA signing (instrumented at the engine level via middleware in main)
var (
	CASignDuration = Default.Histogram("kryptkeeper_ca_sign_duration_seconds", "Latency of CA signing operations", durationBuckets)
)

// Audit trail and SIEM forwarding
var (
	AuditAppendFailures = Default.Counter("kryptkeeper_audit_append_failures_total", "Audit entries that could not be appended to the audit store")
	SIEMEventsForwarded = Default.Counter("kryptkeeper_siem_events_forwarded_total", "Audit-derived events delivered to a SIEM target")
	SIEMEventsDropped   = Default.Counter("kryptkeeper_siem_events_dropped_total", "Audit-derived events dropped because the SIEM forward queue was full")
	SIEMSendFailures    = Default.Counter("kryptkeeper_siem_send_failures_total", "SIEM deliveries that failed (per target attempt)")
)
