// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

// PortEvidence is one fingerprint evidence row a host scan observed for a
// local port. The store joins it to the network endpoint on the same host and
// port, so the row carries no endpoint identity of its own.
type PortEvidence struct {
	Port     int      `json:"port"`
	Evidence Evidence `json:"evidence"`
}

// HostObservations are the facts a host-side scan (agentless SSH) saw about
// the machine itself, as opposed to what the wire showed. They ride on the
// scan's own endpoint and are applied to the rest of the estate after the
// endpoint rows are written.
type HostObservations struct {
	// TargetID is the managed target the scan ran for.
	TargetID string `json:"target_id,omitempty"`
	// ListenersScanned distinguishes "the sweep ran and found nothing" (stale
	// listener evidence is dropped) from "the sweep did not run" (kept).
	ListenersScanned bool           `json:"listeners_scanned,omitempty"`
	Listeners        []PortEvidence `json:"listeners,omitempty"`
	// HiddenListeners counts sockets or processes whose owner the scan
	// account could not see; it is the measure of what privilege would add.
	HiddenListeners int `json:"hidden_listeners,omitempty"`
	// PrivilegeMode and UnreadableCount are what the scan ran with and what it
	// could not read; stored on the managed target (W34-10).
	PrivilegeMode   string `json:"privilege_mode,omitempty"`
	UnreadableCount int    `json:"unreadable_count,omitempty"`
	// FilesScanned distinguishes "no certificate files" (stale rows go) from
	// "the posture pass did not run" (rows kept).
	FilesScanned bool       `json:"files_scanned,omitempty"`
	Files        []HostFile `json:"files,omitempty"`
}

// Install postures of a discovered file.
const (
	PostureStandard    = "standard"
	PosturePrivileged  = "privileged"
	PostureRootService = "root_service"
	PostureUnknown     = "unknown"
)

// HostFile is one certificate, key or keystore file on a scanned host with its
// ownership and the service using it. Key files are described by stat only.
type HostFile struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"` // pem, jks, p12, key, config
	OwnerUID int    `json:"owner_uid"`
	OwnerGID int    `json:"owner_gid"`
	Owner    string `json:"owner,omitempty"`
	Group    string `json:"group,omitempty"`
	Mode     string `json:"mode,omitempty"`
	// Statted is false when the account could not stat the file.
	Statted     bool   `json:"statted"`
	ServiceTech string `json:"service_tech,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	ServiceUID  int    `json:"service_uid"`
	// Posture is standard, privileged, root_service or unknown.
	Posture string `json:"posture"`
	// Findings are "CODE: detail" strings.
	Findings         []string `json:"findings,omitempty"`
	CertFingerprints []string `json:"cert_fingerprints,omitempty"`
}

// ListenerEvidence builds the listener row for a process bound to a port.
// hidden says the owning uid could not be read: the process name still votes,
// but at the lower weight, so it can never lift a fingerprint to high.
func ListenerEvidence(value, tech, platform string, uidHidden bool) Evidence {
	e := NewEvidence(SignalListener, value, tech)
	e.Platform = platform
	if uidHidden {
		e.Weight = 60
	}
	return e
}

// RecommendedInstallMode is the install mode a resolved fingerprint implies
// once a listener has raised its confidence after the network scan finished.
// A low-confidence fingerprint never recommends, matching finalizeFingerprint.
func RecommendedInstallMode(fp Fingerprint, protocol string) string {
	if fp.Confidence == ConfidenceLow || !IsWebServerTech(fp.Tech) {
		return ""
	}
	return recommendInstallMode(fp.Tech, protocol)
}
