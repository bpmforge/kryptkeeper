// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package wstep

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"

	"kryptkeeper/internal/logging"
)

const (
	// EnvKeytabFile is the keytab holding the hub's service principal key.
	EnvKeytabFile = "KRYPTKEEPER_WSTEP_KEYTAB_FILE"
	// EnvSPN is the service principal clients request tickets for, e.g.
	// HTTP/hub.corp.example. It must match the name clients dial.
	EnvSPN = "KRYPTKEEPER_WSTEP_SPN"
)

// KerberosFromEnv builds the enrollment authenticator from the environment.
// WSTEP and XCEP are served only when it succeeds; the error says why not and
// never contains key material.
func KerberosFromEnv() (AuthWrapper, error) {
	path := strings.TrimSpace(os.Getenv(EnvKeytabFile))
	spn := strings.TrimSpace(os.Getenv(EnvSPN))
	if path == "" || spn == "" {
		return nil, fmt.Errorf("%s and %s must both be set", EnvKeytabFile, EnvSPN)
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		logging.Infof("wstep: keytab %s is readable by group/other (mode %v); it is as sensitive as a private key, restrict it to 0600", path, fi.Mode().Perm())
	}
	kt, err := keytab.Load(path)
	if err != nil {
		// gokrb5's error text names the path and the parse failure, not keys.
		return nil, fmt.Errorf("loading keytab: %w", err)
	}
	return Kerberos(kt, spn)
}

// EnabledFromEnv reports whether KerberosFromEnv would enable the endpoints,
// so status APIs say what the listener actually serves.
func EnabledFromEnv() bool {
	_, err := KerberosFromEnv()
	return err == nil
}

// Kerberos returns an AuthWrapper that accepts only SPNEGO/Kerberos tickets
// for spn, validated against kt. NTLM (what Windows sends when it dials the
// hub by IP) is rejected by gokrb5 with a 401.
func Kerberos(kt *keytab.Keytab, spn string) (AuthWrapper, error) {
	if !keytabHasSPN(kt, spn) {
		return nil, fmt.Errorf("keytab has no entry for %s", spn)
	}
	// gokrb5 wants a *log.Logger; bridge it into slog so its lines are JSON too.
	logger := slog.NewLogLogger(slog.Default().With("component", "wstep").Handler(), slog.LevelWarn)
	return func(inner http.Handler) http.Handler {
		bind := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := goidentity.FromHTTPRequestContext(r)
			if id == nil || !id.Authenticated() || id.UserName() == "" || id.Domain() == "" {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			inner.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), IdentityForPrincipal(id.UserName(), id.Domain()))))
		})
		return spnego.SPNEGOKRB5Authenticate(bind, kt,
			service.KeytabPrincipal(spn),
			service.Logger(logger),
			// Group membership drives no decision here, and PAC validation
			// is a known source of lab-only failures.
			service.DecodePAC(false),
		)
	}, nil
}

// keytabHasSPN reports whether kt holds a key for spn in any realm; the
// realm comes from the client's ticket, not from configuration. The match is
// case-sensitive because gokrb5's key lookup is: a case-only mismatch would
// pass here and then fail every ticket at runtime.
func keytabHasSPN(kt *keytab.Keytab, spn string) bool {
	want, _ := types.ParseSPNString(spn)
	if len(want.NameString) == 0 {
		return false
	}
	for _, e := range kt.Entries {
		if want.Equal(types.PrincipalName{NameString: e.Principal.Components}) {
			return true
		}
	}
	return false
}
