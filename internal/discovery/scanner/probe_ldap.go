// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// W34-04: the LDAP rootDSE. An anonymous base-scope read of the empty DN names
// the directory product. Active probe: full and deep scans only (D-206).
//
// Tell status (see the W34-04 spec):
//   - OpenLDAP: verified against OpenLDAP 2.6 (Alpine 3.20) in a local
//     container. It answers objectClass OpenLDAProotDSE and configContext
//     cn=config, and sends no vendorName.
//   - Active Directory (supportedCapabilities 1.2.840.113556.1.4.800 plus a
//     defaultNamingContext) and 389 Directory Server (vendorName naming 389):
//     taken from the products' documentation, UNVERIFIED until the W34-20 corpus.
const adCapabilityOID = "1.2.840.113556.1.4.800"

var rootDSEAttributes = []string{"vendorName", "vendorVersion", "supportedCapabilities", "configContext", "defaultNamingContext", "objectClass"}

// classifyRootDSE maps rootDSE attributes (keys lower-cased) to a technology
// and the short tell that decided it. 389 is checked before OpenLDAP because it
// also exposes a configuration context. An unrecognised directory returns "".
func classifyRootDSE(attrs map[string][]string) (tech, tell string) {
	if v := strings.Join(attrs["vendorname"], " "); strings.Contains(v, "389") {
		ver := strings.Join(attrs["vendorversion"], " ")
		return "ldap-389ds", strings.TrimSpace("vendorName=" + v + " vendorVersion=" + ver)
	}
	if hasValue(attrs["supportedcapabilities"], adCapabilityOID) && len(attrs["defaultnamingcontext"]) > 0 {
		return "ldap-ad", "supportedCapabilities=" + adCapabilityOID + " defaultNamingContext present"
	}
	if hasValue(attrs["objectclass"], "OpenLDAProotDSE") {
		return "ldap-openldap", "objectClass=OpenLDAProotDSE"
	}
	if len(attrs["configcontext"]) > 0 {
		return "ldap-openldap", "configContext present"
	}
	return "", ""
}

func hasValue(vals []string, want string) bool {
	for _, v := range vals {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

// rootDSEEvidence reads the rootDSE over an established LDAP connection.
//   - a recognised directory: one rootdse row voting for it;
//   - an answered but unrecognised directory: one row with no vote;
//   - a server that refuses the anonymous read (insufficient access, strong
//     authentication required, ...): one row, value "refused", no vote;
//   - a transport failure: nothing, since nothing was learned.
//
// Values never include the naming contexts, which carry the domain name.
func rootDSEEvidence(c *ldap.Conn, timeout time.Duration) []Evidence {
	c.SetTimeout(timeout)
	limit := max(int(timeout.Seconds()), 1)
	res, err := c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, limit, false,
		"(objectClass=*)", rootDSEAttributes, nil))
	if err != nil {
		if ldap.IsErrorAnyOf(err, ldap.LDAPResultInsufficientAccessRights, ldap.LDAPResultStrongAuthRequired,
			ldap.LDAPResultOperationsError, ldap.LDAPResultUnwillingToPerform, ldap.LDAPResultNoSuchObject,
			ldap.LDAPResultInappropriateAuthentication) {
			return []Evidence{NewEvidence(SignalRootDSE, "refused", "")}
		}
		return nil
	}
	if len(res.Entries) == 0 {
		return []Evidence{NewEvidence(SignalRootDSE, "refused", "")}
	}
	attrs := map[string][]string{}
	for _, a := range res.Entries[0].Attributes {
		attrs[strings.ToLower(a.Name)] = a.Values
	}
	tech, tell := classifyRootDSE(attrs)
	if tech == "" {
		return []Evidence{NewEvidence(SignalRootDSE, "answered, no known vendor tell", "")}
	}
	return []Evidence{NewEvidence(SignalRootDSE, "rootDSE "+tell, tech)}
}
