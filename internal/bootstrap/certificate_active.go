// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// The one counting rule for "how many certificates do we have".
//
// An ACTIVE certificate is one that has not been revoked and has not been
// superseded by a renewal (renewal_status revoked / renewed). Revoked certificates cannot expire into an outage, be
// renewed or be migrated to a post-quantum algorithm, and a renewed
// predecessor has been superseded by its successor, so counting either in an
// estate total, an expiry timeline or a PQC/posture score only inflates the
// denominator (the successor is already counted). Expired and reissue_required
// certificates are still active here: they are exactly what the "expired"
// buckets and replacement work exist to surface. The per-CA "N certs" count
// (S-72) used to require renewal_status = 'active' and so dropped those too;
// it now follows this rule like every other surface.
//
// Every surface that labels a number "certificates" -- dashboard summary,
// per-CA counts, expiry timeline, crypto posture, PQC and compliance reports
// -- uses this rule. The inventory list is a record listing and still returns
// every row (revoked and superseded included; status filters select
// subsets). Revoked certificates are reported separately (dashboard
// `revoked`, the revocation-activity report). The SQL mirror of this rule is
// activeCertSQL.

// activeCertSQL is isActiveCertificate for the certificates table.
const activeCertSQL = "revoked_at IS NULL AND COALESCE(renewal_status, 'active') NOT IN ('revoked', 'renewed')"

func isActiveCertificate(item *CertificateItem) bool {
	return item.RevokedAt == nil &&
		item.RenewalStatus != string(RenewalStatusRevoked) &&
		item.RenewalStatus != string(RenewalStatusRenewed)
}

// activeCertificates filters certs to the active ones, returning certs
// unchanged (no copy) when every certificate is active.
func activeCertificates(certs []CertificateItem) []CertificateItem {
	inactive := 0
	for i := range certs {
		if !isActiveCertificate(&certs[i]) {
			inactive++
		}
	}
	if inactive == 0 {
		return certs
	}
	out := make([]CertificateItem, 0, len(certs)-inactive)
	for i := range certs {
		if isActiveCertificate(&certs[i]) {
			out = append(out, certs[i])
		}
	}
	return out
}

// revokedCertSQL selects the revoked subset reported alongside the active
// total. renewal_status = 'revoked' is honoured because the estate update path
// can write that status without a revoked_at timestamp. Superseded (renewed)
// certificates are neither active nor revoked.
const revokedCertSQL = "(revoked_at IS NOT NULL OR renewal_status = 'revoked')"
