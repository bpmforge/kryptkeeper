// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

const (
	maxRecordID = 256
	maxZoneName = 253
)

// DNS01Present publishes the challenge TXT record through a dns01 plugin and
// returns where it went. The plugin's answer is untrusted input to the hub's
// own propagation check: the zone must be the fqdn or one of its parents (a
// plugin cannot point the check at an unrelated zone's name servers), and the
// record id is capped and stripped of anything a log line should not carry.
func (p *Plugin) DNS01Present(ctx context.Context, env Env, fqdn, value string, ttlSeconds int) (abi.DNS01PresentResult, error) {
	if p.manifest.Kind != abi.KindDNS01 {
		return abi.DNS01PresentResult{}, fmt.Errorf("%w: %q on a %s plugin", ErrOpNotForKind, abi.OpDNS01Present, p.manifest.Kind)
	}
	st := p.state(env)
	var res abi.DNS01PresentResult
	req := abi.DNS01PresentRequest{Invocation: invocation(env), FQDN: fqdn, Value: value, TTLSeconds: ttlSeconds}
	if err := p.run(ctx, env, st, abi.OpDNS01Present, req, &res); err != nil {
		return abi.DNS01PresentResult{}, err
	}
	res.Zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(res.Zone), "."))
	lower := strings.ToLower(fqdn)
	if res.Zone == "" || len(res.Zone) > maxZoneName || (lower != res.Zone && !strings.HasSuffix(lower, "."+res.Zone)) {
		return abi.DNS01PresentResult{}, errors.New("the plugin reported a zone that does not contain the challenge name")
	}
	res.RecordID = sanitize(res.RecordID, st.redact)
	if len(res.RecordID) > maxRecordID {
		res.RecordID = res.RecordID[:maxRecordID]
	}
	return res, nil
}

// DNS01Cleanup removes the record DNS01Present wrote. Failure is returned to
// the caller, which logs it: a challenge record left behind is untidy, not
// unsafe, and must never fail an issuance that already succeeded.
func (p *Plugin) DNS01Cleanup(ctx context.Context, env Env, fqdn, value, recordID string) error {
	if p.manifest.Kind != abi.KindDNS01 {
		return fmt.Errorf("%w: %q on a %s plugin", ErrOpNotForKind, abi.OpDNS01Cleanup, p.manifest.Kind)
	}
	st := p.state(env)
	var res abi.DNS01CleanupResult
	req := abi.DNS01CleanupRequest{Invocation: invocation(env), FQDN: fqdn, Value: value, RecordID: recordID}
	if err := p.run(ctx, env, st, abi.OpDNS01Cleanup, req, &res); err != nil {
		return err
	}
	if !res.Removed {
		return errors.New("the plugin did not confirm the record was removed")
	}
	return nil
}
