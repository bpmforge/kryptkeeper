// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// registerAuthMethodsHandler exposes WHICH sign-in methods this deployment
// offers — deliberately unauthenticated, because its whole purpose is to
// let the login page render the right buttons before anyone is signed in.
// It reveals only booleans an anonymous caller could already learn by
// probing /auth/login, /auth/oidc/login and /auth/saml/login (each answers
// 503 when its flow is off), never issuer/client/endpoint configuration.
func registerAuthMethodsHandler(mux *http.ServeMux, auth *Authenticator) {
	mux.HandleFunc("/api/v1/auth/methods", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		// Same anonymous-flood posture as the login endpoints themselves.
		if !auth.allowRateLimit("auth-methods:"+clientIP(r), 60, time.Minute, time.Now()) {
			writeTooManyRequests(w, "rate limit exceeded")
			return
		}
		cfg := auth.config
		resp := struct {
			Data struct {
				Password bool `json:"password"`
				OIDC     bool `json:"oidc"`
				SAML     bool `json:"saml"`
			} `json:"data"`
		}{}
		resp.Data.Password = cfg.loginEnabled
		resp.Data.OIDC = cfg.oidcLoginEnabled && cfg.oidcClientID != "" && cfg.oidcRedirectURL != "" && cfg.oidcAuthorizationEndpoint != ""
		resp.Data.SAML = cfg.samlLoginEnabled && samlServiceProviderFromConfig(cfg) != nil
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/auth/methods response: %v", err)
		}
	})
}
