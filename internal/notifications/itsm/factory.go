// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package itsm

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"kryptkeeper/internal/egress"
)

// NewHTTPClient is the only HTTP client ITSM connectors may use: the egress
// guard refuses link-local and metadata addresses and cross-host redirects.
func NewHTTPClient() *http.Client {
	return egress.NewClient(egress.PolicyFromEnv(egress.Policy{
		AllowPrivate:          true,
		MaxRedirects:          3,
		SameHostRedirectsOnly: true,
		Timeout:               10 * time.Second,
	}))
}

// Factory builds a Connector from a connection's base URL and the plaintext
// credential. W32-11 and W32-14 supply one each, keyed by Connector kind.
type Factory func(baseURL string, credential []byte, hc *http.Client) (Connector, error)

// PluginConnectorFactory builds the Connector of a "plugin" connection. The
// plugin runtime lives in internal/bootstrap, which itsm cannot import, so the
// wiring layer supplies this. The factory resolves the credential itself, per
// call, and never holds it.
type PluginConnectorFactory func(ctx context.Context, conn Connection) (Connector, error)

// NewConnectorSource resolves a connection's credential from the encrypted
// store at use time (never cached, never logged) and builds its connector
// with hc, which must be an egress-guarded client.
func NewConnectorSource(store *Store, creds CredentialResolver, hc *http.Client, factories map[string]Factory, plugins PluginConnectorFactory) ConnectorSource {
	return func(ctx context.Context, connectionID string) (Connector, error) {
		conn, err := store.GetConnection(ctx, connectionID)
		if err != nil {
			return nil, err
		}
		if !conn.Enabled {
			return nil, fmt.Errorf("itsm: connection %q is disabled", connectionID)
		}
		if conn.Kind == KindPlugin {
			if plugins == nil {
				return nil, fmt.Errorf("itsm: ticket plugins are not available on this hub")
			}
			return plugins(ctx, conn)
		}
		factory, ok := factories[conn.Kind]
		if !ok {
			return nil, fmt.Errorf("itsm: no connector available for kind %q", conn.Kind)
		}
		if creds == nil {
			return nil, fmt.Errorf("itsm: credential store not configured")
		}
		secret, err := creds.Resolve(ctx, conn.CredentialRef)
		if err != nil {
			// Name the reference, never the secret.
			return nil, fmt.Errorf("itsm: resolving credential %q: %w", conn.CredentialRef, err)
		}
		return factory(conn.BaseURL, secret, hc)
	}
}
