// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

// Mock secret managers for the first-party credentials plugins (W38-07):
// CyberArk Central Credential Provider and Delinea Secret Server. Each is
// strict about the request shape the vendor documents, so a plugin that sends
// the wrong query or skips the token exchange fails here.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"kryptkeeper/internal/plugins/delivery"
)

type managerMock struct {
	ts   *httptest.Server
	mu   sync.Mutex
	fail string
}

func (m *managerMock) FailNext(mode string) { m.mu.Lock(); m.fail = mode; m.mu.Unlock() }

func (m *managerMock) take() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	mode := m.fail
	m.fail = ""
	return mode
}

// --- CyberArk CCP ---

const ccpAppID = "Kryptkeeper"

type ccpMock struct{ *managerMock }

func (ccpMock) Reference() map[string]string {
	return map[string]string{"safe": "Infra", "object": "web1-root", "map": "Content:private_key_pem,UserName:user"}
}
func (ccpMock) Unknown() map[string]string {
	return map[string]string{"safe": "Infra", "object": "no-such", "map": "Content:private_key_pem,UserName:user"}
}
func (ccpMock) Expected() map[string]string {
	return map[string]string{"private_key_pem": "FAKE-CCP-KEY-MATERIAL-0123456789", "user": "svc-kryptkeeper"}
}

func (m ccpMock) Env() delivery.Env {
	return anyHostEnv(m.ts, map[string]string{"base_url": "https://ccp.example.com", "app_id": ccpAppID}, nil, nil)
}

func newCCPMock(t *testing.T) ccpMock {
	m := &managerMock{}
	m.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch m.take() {
		case "denied":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"ErrorCode":"APPAP008E","ErrorMsg":"Application is not allowed: leaks web1-root"}`))
			return
		case "server_error":
			w.WriteHeader(http.StatusInternalServerError)
			return
		case "missing":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"ErrorCode":"APPAP004E","ErrorMsg":"Password object matching query not found"}`))
			return
		}
		q := r.URL.Query()
		if r.Method != http.MethodGet || r.URL.Path != "/AIMWebService/api/Accounts" || q.Get("AppID") != ccpAppID || q.Get("Object") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if q.Get("Object") != "web1-root" || q.Get("Safe") != "Infra" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"ErrorCode":"APPAP004E","ErrorMsg":"Password object matching query not found"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"Content":%q,"UserName":"svc-kryptkeeper","Address":"web1.example.com","Safe":"Infra","Folder":"Root","Name":"web1-root","PolicyID":"UnixSSHKeys","PasswordChangeInProcess":"False"}`,
			ccpMock{}.Expected()["private_key_pem"])
	}))
	t.Cleanup(m.ts.Close)
	return ccpMock{m}
}

func TestCyberArkCCPPluginConforms(t *testing.T) {
	rt := newRuntime(t)
	CredentialsSuite(t, Load(t, rt, repoPath(t, "plugins/cyberark-ccp")), newCCPMock(t))
}

// --- Delinea Secret Server ---

const (
	dsUser = "kk-app"
	dsPass = "ds-application-password-9f3a"
)

type delineaMock struct{ *managerMock }

func (delineaMock) Reference() map[string]string {
	return map[string]string{"secret_id": "42", "map": "username:username,password:password"}
}
func (delineaMock) Unknown() map[string]string {
	return map[string]string{"secret_id": "999", "map": "username:username,password:password"}
}
func (delineaMock) Expected() map[string]string {
	return map[string]string{"username": "Administrator", "password": "Win-Admin-Pass-71c2e"}
}

func (m delineaMock) Env() delivery.Env {
	return anyHostEnv(m.ts, map[string]string{"base_url": "https://vault.example.com/SecretServer", "username": dsUser, "password": dsPass},
		[]string{"password"}, nil)
}

func newDelineaMock(t *testing.T) delineaMock {
	m := &managerMock{}
	const token = "ds-access-token-77aa"
	m.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/SecretServer")
		switch {
		case r.Method == http.MethodPost && path == "/oauth2/token":
			raw, _ := io.ReadAll(r.Body)
			vals, _ := url.ParseQuery(string(raw))
			if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
				vals.Get("grant_type") != "password" || vals.Get("username") != dsUser || vals.Get("password") != dsPass {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			_, _ = fmt.Fprintf(w, `{"access_token":%q,"token_type":"bearer","expires_in":1200}`, token)
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v1/secrets/"):
			if r.Header.Get("Authorization") != "Bearer "+token {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			switch m.take() {
			case "denied":
				w.WriteHeader(http.StatusForbidden)
				return
			case "server_error":
				w.WriteHeader(http.StatusInternalServerError)
				return
			case "missing":
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if path != "/api/v1/secrets/42" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			exp := delineaMock{}.Expected()
			body, _ := json.Marshal(map[string]any{
				"id": 42, "name": "win-admin", "active": true,
				"items": []map[string]any{
					{"slug": "machine", "fieldName": "Machine", "itemValue": "win1.example.com"},
					{"slug": "username", "fieldName": "Username", "itemValue": exp["username"]},
					{"slug": "password", "fieldName": "Password", "itemValue": exp["password"], "isPassword": true},
					{"slug": "notes", "fieldName": "Notes", "itemValue": ""},
				},
			})
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(m.ts.Close)
	return delineaMock{m}
}

func TestDelineaSecretServerPluginConforms(t *testing.T) {
	rt := newRuntime(t)
	CredentialsSuite(t, Load(t, rt, repoPath(t, "plugins/delinea-secret-server")), newDelineaMock(t))
}
