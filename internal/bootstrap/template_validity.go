// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// defaultIssuedValidity is the lifetime of a certificate whose template names
// none.
const defaultIssuedValidity = 90 * 24 * time.Hour

// maxValidityPeriod bounds a template's total validity. Per-component caps
// alone do not: seven maxed ISO components overflow int64 nanoseconds and wrap
// to a small positive value. The issuing CA's NotAfter still clamps below this.
const maxValidityPeriod = 100 * 365 * 24 * time.Hour

// The API, UI and seed data write validity_period as an ISO-8601 duration
// (P90D, P1Y), but older rows and the CLI also carry Go durations (2160h) and
// "90d". time.ParseDuration alone rejects the ISO form, which silently turned
// every ISO-valued template into the 90-day default.
var isoDurationRE = regexp.MustCompile(`^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$`)

var daysSuffixRE = regexp.MustCompile(`^(\d+)d$`)

// ParseValidityPeriod parses a template validity_period: an ISO-8601 duration
// (years are 365 days, months 30), a Go duration, or "<n>d". An empty string
// returns (0, nil) meaning "unset"; anything else must parse to a positive
// duration.
func ParseValidityPeriod(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	var d time.Duration
	switch upper := strings.ToUpper(s); {
	case isoDurationRE.MatchString(upper) && upper != "P" && !strings.HasSuffix(upper, "T"):
		m := isoDurationRE.FindStringSubmatch(upper)
		unit := [...]time.Duration{
			365 * 24 * time.Hour, 30 * 24 * time.Hour, 7 * 24 * time.Hour, 24 * time.Hour,
			time.Hour, time.Minute, time.Second,
		}
		for i, u := range unit {
			if m[i+1] == "" {
				continue
			}
			n, err := strconv.ParseInt(m[i+1], 10, 64)
			if err != nil || n > int64(maxValidityPeriod)/int64(u) {
				return 0, fmt.Errorf("validity period %q out of range", s)
			}
			// d <= maxValidityPeriod before each add and the component is
			// <= maxValidityPeriod, so the sum cannot overflow int64.
			d += time.Duration(n) * u
			if d > maxValidityPeriod {
				return 0, fmt.Errorf("validity period %q out of range (max 100 years)", s)
			}
		}
	case daysSuffixRE.MatchString(strings.ToLower(s)):
		n, err := strconv.ParseInt(daysSuffixRE.FindStringSubmatch(strings.ToLower(s))[1], 10, 64)
		if err != nil || n > 36500 {
			return 0, fmt.Errorf("validity period %q out of range", s)
		}
		d = time.Duration(n) * 24 * time.Hour
	default:
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("invalid validity period %q (want ISO-8601 like P90D, or 2160h)", s)
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("validity period %q must be positive", s)
	}
	if d > maxValidityPeriod {
		return 0, fmt.Errorf("validity period %q out of range (max 100 years)", s)
	}
	return d, nil
}

// templateValidity is the lifetime a template asks for: its validity_period,
// capped at the short-lived maximum when the template is short-lived, else
// defaultIssuedValidity when the template names none. The CA engine further
// clamps to the issuing CA's own NotAfter.
func templateValidity(tpl TemplateItem) (time.Duration, error) {
	d, err := ParseValidityPeriod(tpl.ValidityPeriod)
	if err != nil {
		return 0, fmt.Errorf("template %q: %w", tpl.ID, err)
	}
	if d == 0 {
		d = defaultIssuedValidity
	}
	if tpl.ShortLived && d > shortLivedTemplateMax {
		d = shortLivedTemplateMax
	}
	return d, nil
}

const shortLivedTemplateMax = 7 * 24 * time.Hour
