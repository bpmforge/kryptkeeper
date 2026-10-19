// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package servicenow

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"kryptkeeper/internal/notifications/itsm"
)

const cmdbCIPath = "/api/now/table/cmdb_ci"

// hostRE is the only shape interpolated into sysparm_query, where "^" joins
// clauses: anything else (a wildcard CN, an injected clause) simply has no CI.
var hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$`)

var _ itsm.CMDBSource = (*Connector)(nil)

// LookupOwner implements itsm.CMDBSource: the CI whose fqdn or name is host.
// The dot-walked fields need the integration user to read cmdb_ci and sys_user.
func (c *Connector) LookupOwner(ctx context.Context, host string) (itsm.CMDBOwner, bool, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if !hostRE.MatchString(host) {
		return itsm.CMDBOwner{}, false, nil
	}
	q := url.Values{}
	q.Set("sysparm_query", "fqdn="+host+"^ORname="+host)
	q.Set("sysparm_limit", "1")
	q.Set("sysparm_fields", "owned_by.email,support_group.name")
	status, data, err := c.do(ctx, http.MethodGet, cmdbCIPath, q, nil)
	if status == http.StatusNotFound {
		return itsm.CMDBOwner{}, false, nil
	}
	if err != nil {
		return itsm.CMDBOwner{}, false, err
	}
	var out struct {
		Result []map[string]any `json:"result"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return itsm.CMDBOwner{}, false, fmt.Errorf("%w: unreadable servicenow response", itsm.ErrTemporary)
	}
	if len(out.Result) == 0 {
		return itsm.CMDBOwner{}, false, nil
	}
	owner := itsm.CMDBOwner{
		OwnerEmail: strings.TrimSpace(str(out.Result[0]["owned_by.email"])),
		OwnerTeam:  strings.TrimSpace(str(out.Result[0]["support_group.name"])),
	}
	if owner.OwnerEmail == "" && owner.OwnerTeam == "" {
		return itsm.CMDBOwner{}, false, nil
	}
	return owner, true, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
