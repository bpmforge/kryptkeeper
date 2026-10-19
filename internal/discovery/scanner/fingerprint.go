// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"sort"
	"strings"
)

// Fingerprint evidence signals. A signal names where an observation came
// from; its weight (SignalWeight) says how far the observation can be
// trusted. Listener is what the host itself reports as bound to the port, so
// it outranks anything inferred from the wire.
const (
	SignalListener   = "listener"
	SignalHTTPHeader = "http_header"
	SignalBanner     = "banner"
	SignalRootDSE    = "rootdse"
	SignalTDS        = "tds_prelogin"
	SignalCertIssuer = "cert_issuer"
	SignalCertSubj   = "cert_subject"
	SignalCertExt    = "cert_ext"
	SignalTLSStack   = "tls_stack"
	SignalPort       = "port"
)

// Confidence levels of a resolved fingerprint.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// Platform values.
const (
	PlatformWindows   = "windows"
	PlatformLinux     = "linux"
	PlatformJava      = "java"
	PlatformAppliance = "appliance"
	PlatformUnknown   = "unknown"
)

// TechUnknown is the headline when no signal votes or the vote is tied.
const TechUnknown = "unknown"

// otherTechPrefix marks a technology outside the closed vocabulary; the raw
// token is kept so the estate records something rather than losing it.
const otherTechPrefix = "other:"

const (
	maxEvidenceValue = 200
	maxOtherToken    = 40
	// strongWeight is the lowest weight that counts as a real, protocol-level
	// observation. Port defaults and TLS-stack guesses sit below it and can
	// never lift a fingerprint above low confidence on their own.
	strongWeight = 40
)

// Evidence is one observation voting for a technology.
type Evidence struct {
	Signal string `json:"signal"`
	// Value is the raw-but-redacted observation, e.g. "Server: Apache-Coyote/1.1".
	Value string `json:"value"`
	// Tech is the technology this signal votes for; empty for a row that only
	// carries a platform or TLS-stack observation.
	Tech   string `json:"tech"`
	Weight int    `json:"weight"`
	// Platform is an explicit platform vote (WWW-Authenticate: Negotiate says
	// windows without naming a product). Empty means "derive it from Tech".
	Platform string `json:"platform,omitempty"`
}

// Fingerprint is the resolved technology behind one endpoint.
type Fingerprint struct {
	Tech       string     `json:"tech"`
	Confidence string     `json:"confidence"`
	Platform   string     `json:"platform"`
	TLSStack   string     `json:"tls_stack"`
	Evidence   []Evidence `json:"evidence"`
}

// techVocabulary is the closed set of technologies a fingerprint can name.
// Anything else is recorded as other:<token>.
var techVocabulary = map[string]bool{
	"apache": true, "nginx": true, "iis": true, "tomcat": true, "jetty": true,
	"wildfly": true, "weblogic": true, "websphere": true, "haproxy": true,
	"envoy": true, "caddy": true, "traefik": true, "kestrel": true, "node": true,
	"ldap-ad": true, "ldap-openldap": true, "ldap-389ds": true,
	"mssql": true, "mysql": true, "postgres": true, "oracle": true,
	"mongodb": true, "redis": true, "kafka": true, "elasticsearch": true,
	"vault": true, "consul": true, "etcd": true, "kubernetes-api": true,
	"winrm": true, "rdp": true, "exchange": true, "postfix": true, "exim": true,
	"sendmail": true, "dovecot": true, "cyrus": true, "openssh": true,
	"f5-bigip": true, "citrix-adc": true, "fortinet": true, "paloalto": true,
	"cisco-asa": true, "vmware-vcenter": true, "vmware-esxi": true,
	"idrac": true, "ilo": true, "printer": true, TechUnknown: true,
}

// webServerTechs are the technologies server_tech mirrors for compatibility
// with readers that predate the fingerprint columns.
var webServerTechs = map[string]bool{
	"apache": true, "nginx": true, "iis": true, "tomcat": true, "jetty": true,
	"wildfly": true, "weblogic": true, "websphere": true, "haproxy": true,
	"envoy": true, "caddy": true, "traefik": true, "kestrel": true, "node": true,
}

// IsWebServerTech reports whether tech is a web server, i.e. a value
// endpoints.server_tech should equal.
func IsWebServerTech(tech string) bool { return webServerTechs[tech] }

// NormalizeTech maps a raw technology token into the vocabulary, or into
// other:<token> when it is unknown. An empty token stays empty.
func NormalizeTech(raw string) string {
	t := strings.ToLower(strings.TrimSpace(raw))
	if t == "" {
		return ""
	}
	if techVocabulary[t] {
		return t
	}
	if strings.HasPrefix(t, otherTechPrefix) {
		t = strings.TrimPrefix(t, otherTechPrefix)
	}
	var b strings.Builder
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		}
		if b.Len() >= maxOtherToken {
			break
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return otherTechPrefix + b.String()
}

// SignalWeight is the vote weight of a signal.
func SignalWeight(signal string) int {
	switch signal {
	case SignalListener:
		return 100
	case SignalHTTPHeader, SignalBanner, SignalRootDSE, SignalTDS:
		return 60
	case SignalCertIssuer, SignalCertSubj, SignalCertExt:
		return strongWeight
	case SignalTLSStack:
		return 25
	case SignalPort:
		return 10
	default:
		return 0
	}
}

// NewEvidence builds an evidence row with the signal's weight and a value
// that is safe to store and show: control characters dropped, length capped.
func NewEvidence(signal, value, tech string) Evidence {
	return Evidence{Signal: signal, Value: redactEvidenceValue(value), Tech: NormalizeTech(tech), Weight: SignalWeight(signal)}
}

// redactEvidenceValue keeps one printable line. Callers pass header and banner
// lines only; this is the backstop that guarantees no body or binary reaches
// the database.
func redactEvidenceValue(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
	v = strings.TrimSpace(v)
	if len(v) > maxEvidenceValue {
		v = v[:maxEvidenceValue]
	}
	return v
}

// platformOfTech is the platform a technology implies on its own. Products
// that run on several platforms (kestrel, mssql, apache) are left out.
func platformOfTech(tech string) string {
	switch tech {
	case "iis", "exchange", "winrm", "rdp", "ldap-ad":
		return PlatformWindows
	case "tomcat", "jetty", "wildfly", "weblogic", "websphere":
		return PlatformJava
	case "postfix", "exim", "sendmail", "dovecot", "cyrus", "ldap-openldap", "ldap-389ds":
		return PlatformLinux
	case "f5-bigip", "citrix-adc", "fortinet", "paloalto", "cisco-asa",
		"vmware-vcenter", "vmware-esxi", "idrac", "ilo", "printer":
		return PlatformAppliance
	}
	return ""
}

// TLSStack values accepted on a tls_stack evidence row.
func tlsStackPlatform(stack string) string {
	switch stack {
	case "schannel":
		return PlatformWindows
	case "jsse":
		return PlatformJava
	}
	return ""
}

// Resolve folds evidence into one fingerprint.
//
// Each technology scores the sum of its rows' weights; the highest wins. A
// tie goes to the technology holding the single heaviest signal (listener
// beats banner beats certificate beats TLS stack beats port), and a tie that
// survives that is TechUnknown with the evidence kept.
//
// Confidence is high when a listener row agrees with the winner or two
// independent strong rows do, medium when one strong row stands alone, and
// low when only port or TLS-stack rows (or nothing) back it.
func Resolve(evidence []Evidence) Fingerprint {
	rows := make([]Evidence, len(evidence))
	copy(rows, evidence)
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Weight > rows[j].Weight })

	score := map[string]int{}
	best := map[string]int{}
	for _, e := range rows {
		if e.Tech == "" || e.Tech == TechUnknown {
			continue
		}
		score[e.Tech] += e.Weight
		if e.Weight > best[e.Tech] {
			best[e.Tech] = e.Weight
		}
	}

	fp := Fingerprint{Tech: TechUnknown, Confidence: ConfidenceLow, Platform: PlatformUnknown, TLSStack: "unknown", Evidence: rows}
	if fp.Evidence == nil {
		fp.Evidence = []Evidence{}
	}
	fp.Tech = pickWinner(score, best)
	fp.Platform = resolvePlatform(rows)
	for _, e := range rows {
		if e.Signal == SignalTLSStack && e.Value != "" {
			fp.TLSStack = strings.ToLower(e.Value)
			break
		}
	}
	if fp.Tech != TechUnknown {
		fp.Confidence = confidenceFor(fp.Tech, rows)
	}
	return fp
}

func pickWinner(score, best map[string]int) string {
	win, winScore, winBest, tied := TechUnknown, 0, 0, false
	// Sorted keys keep the outcome independent of map iteration order.
	techs := make([]string, 0, len(score))
	for t := range score {
		techs = append(techs, t)
	}
	sort.Strings(techs)
	for _, t := range techs {
		s, b := score[t], best[t]
		switch {
		case s > winScore || (s == winScore && b > winBest):
			win, winScore, winBest, tied = t, s, b, false
		case s == winScore && b == winBest:
			tied = true
		}
	}
	if tied {
		return TechUnknown
	}
	return win
}

func resolvePlatform(rows []Evidence) string {
	votes := map[string]int{}
	stackVotes := map[string]int{}
	for _, e := range rows {
		p := e.Platform
		if p == "" {
			p = platformOfTech(e.Tech)
		}
		if p == "" && e.Signal == SignalTLSStack {
			if sp := tlsStackPlatform(strings.ToLower(e.Value)); sp != "" {
				stackVotes[sp] += e.Weight
			}
			continue
		}
		if p != "" {
			votes[p] += e.Weight
		}
	}
	// A TLS stack only breaks a platform tie of silence: any stronger signal
	// (header, banner, certificate, listener) decides on its own.
	if len(votes) == 0 {
		votes = stackVotes
	}
	return highestVote(votes)
}

func highestVote(votes map[string]int) string {
	keys := make([]string, 0, len(votes))
	for p := range votes {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	win, winScore, tied := PlatformUnknown, 0, false
	for _, p := range keys {
		switch {
		case votes[p] > winScore:
			win, winScore, tied = p, votes[p], false
		case votes[p] == winScore:
			tied = true
		}
	}
	if tied {
		return PlatformUnknown
	}
	return win
}

// independenceKey identifies the source of a row so two header lines from one
// response count as two observations but a repeated header does not.
func independenceKey(e Evidence) string {
	if e.Signal == SignalHTTPHeader {
		name, _, _ := strings.Cut(e.Value, ":")
		return e.Signal + "/" + strings.ToLower(strings.TrimSpace(name))
	}
	return e.Signal
}

func confidenceFor(tech string, rows []Evidence) string {
	strong := map[string]bool{}
	for _, e := range rows {
		if e.Tech != tech {
			continue
		}
		// A listener row whose weight was lowered (the owning uid was hidden)
		// is only a medium-grade observation.
		if e.Signal == SignalListener && e.Weight >= SignalWeight(SignalListener) {
			return ConfidenceHigh
		}
		if e.Weight >= strongWeight {
			strong[independenceKey(e)] = true
		}
	}
	switch {
	case len(strong) >= 2:
		return ConfidenceHigh
	case len(strong) == 1:
		return ConfidenceMedium
	}
	return ConfidenceLow
}

// portTech maps a catalogue protocol tag to the technology its well-known
// port suggests. Ambiguous services (ldaps, imaps, https) are deliberately
// absent: a port is a guess, not an observation.
var portTech = map[string]string{
	"ssh":            "openssh",
	"postgres":       "postgres",
	"mssql":          "mssql",
	"mysql":          "mysql",
	"oracle":         "oracle",
	"redis":          "redis",
	"mongodb":        "mongodb",
	"kafka":          "kafka",
	"elasticsearch":  "elasticsearch",
	"vault":          "vault",
	"consul":         "consul",
	"rdp":            "rdp",
	"winrm-https":    "winrm",
	"kubernetes-api": "kubernetes-api",
	"etcd":           "etcd",
	"etcd-peer":      "etcd",
}

// portEvidence is the weakest signal: what the catalogue says normally lives
// on this port. It is nil for ports that imply nothing.
func portEvidence(protocol string) []Evidence {
	tech, ok := portTech[protocol]
	if !ok {
		return nil
	}
	return []Evidence{NewEvidence(SignalPort, protocol, tech)}
}

// EvidenceJSON serializes the evidence rows for endpoints.tech_evidence. It
// returns "" for no evidence so callers store NULL.
func EvidenceJSON(ev []Evidence) string {
	if len(ev) == 0 {
		return ""
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return ""
	}
	return string(b)
}

// ParseEvidenceJSON is the inverse of EvidenceJSON; malformed stored JSON
// yields no evidence rather than an error, matching the other stored-JSON
// endpoint columns.
func ParseEvidenceJSON(s string) []Evidence {
	if s == "" {
		return nil
	}
	var ev []Evidence
	if json.Unmarshal([]byte(s), &ev) != nil {
		return nil
	}
	return ev
}
