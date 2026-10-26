// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// W38-07: the real first-party credentials plugins (compiled to wasm) run
// through the hub's own path: plugin manager, credential source, Resolve and
// payload validation, against local TLS stand-ins for CyberArk CCP and Delinea
// Secret Server.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/tests/plugins/conformance"
)

// installCredentialsPlugin builds plugins/<name>, installs it and enables it
// the way an approver would, and returns the plugin id.
func installCredentialsPlugin(t *testing.T, mgr *DeliveryPluginManager, name string) string {
	t.Helper()
	dir := repoDir("plugins/" + name)
	wasm := conformance.Build(t, dir)
	manifest := conformance.PinManifest(t, dir, wasm)
	v, err := mgr.Install(context.Background(), manifest, wasm, "", "admin")
	if err != nil {
		t.Fatalf("install %s: %v", name, err)
	}
	if v.Kind != abi.KindCredentials || v.CapabilityTier != abi.TierCritical {
		t.Fatalf("%s: kind %q tier %q, want credentials / critical", name, v.Kind, v.CapabilityTier)
	}
	// Critical: never enabled by the operator alone.
	if _, _, err := mgr.RequestEnable(context.Background(), v.PluginID, v.Version, "admin", DefaultTenant); err == nil {
		t.Fatalf("%s was enabled without a second person", name)
	}
	if err := mgr.enable(context.Background(), v.PluginID, v.Version, "approver"); err != nil {
		t.Fatal(err)
	}
	return v.PluginID
}

// tlsClientTo dials ts whatever host the plugin names, verifying its
// certificate as example.com.
func tlsClientTo(ts *httptest.Server) *http.Client {
	addr := ts.Listener.Addr().String()
	tr := ts.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12, ServerName: "example.com"}
	return &http.Client{Transport: tr}
}

func (e *extEnv) pluginSource(pluginID, loginJSON string, client *http.Client) CredentialSource {
	e.t.Helper()
	login, err := e.store.Create(context.Background(), "cred-plogin-"+pluginID, "plugin login", CredentialTypeAPIToken, DefaultTenant, []byte(loginJSON))
	if err != nil {
		e.t.Fatal(err)
	}
	src, err := e.sources.Create(context.Background(), CredentialSource{ID: "src-" + pluginID, Name: pluginID, Kind: CredentialSourcePlugin,
		Tenant: DefaultTenant, CredentialRef: login.ID, Config: CredentialSourceConfig{PluginID: pluginID}})
	if err != nil {
		e.t.Fatal(err)
	}
	r := e.store.external()
	r.pluginClient = client
	r.plugins = func() *DeliveryPluginManager { return NewDeliveryPluginManager(e.db, false, nil, nil) }
	return src
}

func TestCyberArkPluginSourceResolvesAnSSHCredential(t *testing.T) {
	e := newExtEnv(t)
	const key = "FAKE-CCP-PRIVATE-KEY-MATERIAL-5d4c3b2a"
	var query url.Values
	ccp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query()
		if r.URL.Path != "/AIMWebService/api/Accounts" || query.Get("AppID") != "Kryptkeeper" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintf(w, `{"Content":%q,"UserName":"svc-kk","Address":"web1.example.com"}`, key)
	}))
	t.Cleanup(ccp.Close)

	mgr := NewDeliveryPluginManager(e.db, false, nil, nil)
	id := installCredentialsPlugin(t, mgr, "cyberark-ccp")
	src := e.pluginSource(id, `{"base_url":"https://ccp.example.com","app_id":"Kryptkeeper"}`, tlsClientTo(ccp))

	cred, err := e.store.CreateExternal(context.Background(), "cred-ccp-ssh", "web1", CredentialTypeSSHKey, DefaultTenant, src.ID, ExternalReference{
		Reference: map[string]string{"safe": "Infra", "object": "web1-root", "map": "Content:private_key_pem,UserName:user"},
		Static:    sshStatic,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.store.Resolve(context.Background(), cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	var p sshCredentialPayload
	if err := json.Unmarshal(got, &p); err != nil || p.PrivateKeyPEM != key || p.User != "svc-kk" || p.HostPublicKey != fakeKVHostKey {
		t.Fatalf("payload %+v err %v", p, err)
	}
	if query.Get("Safe") != "Infra" || query.Get("Object") != "web1-root" {
		t.Fatalf("the plugin queried %v", query)
	}
	rows := e.auditRows()
	if len(rows) != 1 || !strings.Contains(rows[0].ChangeSummary, "source=plugin:"+src.ID) || strings.Contains(fmt.Sprint(rows[0]), key) {
		t.Fatalf("audit %+v", rows)
	}

	// A record that does not fit the type is refused with the fields named,
	// never with a value.
	badRef := ExternalReference{Reference: map[string]string{"safe": "Infra", "object": "web1-root"}, Static: sshStatic} // default map: password, username
	bad, err := e.store.CreateExternal(context.Background(), "cred-ccp-bad", "web1", CredentialTypeSSHKey, DefaultTenant, src.ID, badRef)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.store.Resolve(context.Background(), bad.ID)
	var re *CredentialResolveError
	if !errors.As(err, &re) || re.Class != resolveClassInvalid || !strings.Contains(err.Error(), "private_key_pem") || strings.Contains(err.Error(), key) {
		t.Fatalf("bad map: %v", err)
	}
}

func TestDelineaPluginSourceResolvesAWindowsCredential(t *testing.T) {
	e := newExtEnv(t)
	const pass = "Win-Admin-Pass-71c2e"
	ss := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth2/token":
			_ = r.ParseForm()
			if r.PostForm.Get("grant_type") != "password" || r.PostForm.Get("username") != "kk-app" || r.PostForm.Get("password") != "ds-app-pass-0042" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"tok-1","token_type":"bearer"}`))
		case r.URL.Path == "/api/v1/secrets/42" && r.Header.Get("Authorization") == "Bearer tok-1":
			_, _ = fmt.Fprintf(w, `{"id":42,"items":[{"slug":"username","itemValue":"Administrator"},{"slug":"password","itemValue":%q}]}`, pass)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ss.Close)

	mgr := NewDeliveryPluginManager(e.db, false, nil, nil)
	id := installCredentialsPlugin(t, mgr, "delinea-secret-server")
	src := e.pluginSource(id, `{"base_url":"https://vault.example.com","username":"kk-app","password":"ds-app-pass-0042"}`, tlsClientTo(ss))

	cred, err := e.store.CreateExternal(context.Background(), "cred-ds-win", "win1", CredentialTypeWindowsPassword, DefaultTenant, src.ID, ExternalReference{
		Reference: map[string]string{"secret_id": "42"},
		Static:    map[string]string{"base_url": "https://win1.example.com:5986/wsman"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.store.Resolve(context.Background(), cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	var w struct{ BaseURL, Username, Password string }
	var m map[string]string
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	w.BaseURL, w.Username, w.Password = m["base_url"], m["username"], m["password"]
	if w.BaseURL != "https://win1.example.com:5986/wsman" || w.Username != "Administrator" || w.Password != pass {
		t.Fatalf("payload %+v", w)
	}

	// The source's own login never reaches the audit trail or a caller error.
	_, err = e.store.Resolve(context.Background(), mustExternal(t, e, src, "cred-ds-missing", map[string]string{"secret_id": "7"}))
	if err == nil || strings.Contains(err.Error(), "ds-app-pass-0042") || !strings.Contains(err.Error(), "no such secret") {
		t.Fatalf("missing secret: %v", err)
	}
	for _, r := range e.auditRows() {
		if blob, _ := json.Marshal(r); strings.Contains(string(blob), "ds-app-pass-0042") || strings.Contains(string(blob), pass) {
			t.Fatalf("audit row carries a secret: %s", blob)
		}
	}
}

func mustExternal(t *testing.T, e *extEnv, src CredentialSource, id string, ref map[string]string) string {
	t.Helper()
	if _, err := e.store.CreateExternal(context.Background(), id, id, CredentialTypeWindowsPassword, DefaultTenant, src.ID,
		ExternalReference{Reference: ref, Static: map[string]string{"base_url": "https://win.example.com:5986/wsman"}}); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPluginSourceNeedsAnEnabledCredentialsPlugin(t *testing.T) {
	e := newExtEnv(t)
	src := e.pluginSource("kryptkeeper.not-installed", `{"base_url":"https://x.example.com"}`, nil)
	id := mustExternal(t, e, src, "cred-np", map[string]string{"secret_id": "1"})
	_, err := e.store.Resolve(context.Background(), id)
	var re *CredentialResolveError
	if !errors.As(err, &re) || re.Class != resolveClassConfig || !strings.Contains(err.Error(), "not an enabled plugin") {
		t.Fatalf("missing plugin: %v", err)
	}
	// And with plugins off the failure says so.
	e.store.external().plugins = func() *DeliveryPluginManager { return nil }
	if _, err := e.store.Resolve(context.Background(), id); err == nil || !strings.Contains(err.Error(), "plugins are off") {
		t.Fatalf("plugins off: %v", err)
	}
}
