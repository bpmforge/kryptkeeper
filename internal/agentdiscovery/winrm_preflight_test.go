// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Each fixture replays one wire shape captured live on 2026-09-10.

func preflightServer(t *testing.T, mode string, groupsCSV string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case mode == "401":
			w.WriteHeader(http.StatusUnauthorized) // bare, no SOAP body, as HTTP.sys sends it
		case mode == "no_shell" && strings.Contains(string(body), "transfer/Create"):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault><s:Reason><s:Text xml:lang="en-US">Access is denied. </s:Text></s:Reason><s:Detail><f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="5" Machine="h"><f:Message>Access is denied. </f:Message></f:WSManFault></s:Detail></s:Fault></s:Body></s:Envelope>`)
		case strings.Contains(string(body), "transfer/Create"):
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="x"><s:Body><ResourceCreated><ReferenceParameters><SelectorSet><Selector Name="ShellId">SHELL-1</Selector></SelectorSet></ReferenceParameters></ResourceCreated></s:Body></s:Envelope>`)
		case strings.Contains(string(body), "shell/Command"):
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="x"><s:Body><CommandResponse><CommandId>CMD-1</CommandId></CommandResponse></s:Body></s:Envelope>`)
		case strings.Contains(string(body), "shell/Receive"):
			enc := base64.StdEncoding.EncodeToString([]byte(groupsCSV))
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="x"><s:Body><ReceiveResponse><Stream Name="stdout">`+enc+`</Stream><CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"/></ReceiveResponse></s:Body></s:Envelope>`)
		default:
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="x"><s:Body/></s:Envelope>`)
		}
	}))
}

func runPreflight(t *testing.T, srv *httptest.Server) WinRMPreflight {
	t.Helper()
	return PreflightWinRM(context.Background(), WinRMConfig{EndpointURL: srv.URL, Username: "u", Password: "p"}, srv.Client())
}

func TestPreflightBare401IsUnauthenticatedAndNamesBothCauses(t *testing.T) {
	srv := preflightServer(t, "401", "")
	defer srv.Close()
	got := runPreflight(t, srv)
	if got.Level != PreflightUnauthenticated || got.CanDiscover || got.CanInstall {
		t.Fatalf("%+v", got)
	}
	// The wire cannot separate a wrong password from an un-admitted
	// account; the verdict must say so rather than pick one.
	if !strings.Contains(got.Detail, "password is wrong") || !strings.Contains(got.Detail, "Remote Management Users") {
		t.Fatalf("detail must name both causes: %s", got.Detail)
	}
}

func TestPreflightFaultCode5OnCreateIsNoShell(t *testing.T) {
	srv := preflightServer(t, "no_shell", "")
	defer srv.Close()
	got := runPreflight(t, srv)
	if got.Level != PreflightNoShell || got.CanDiscover {
		t.Fatalf("%+v", got)
	}
	if !strings.Contains(got.Detail, "authenticated") {
		t.Fatalf("must say the password was right: %s", got.Detail)
	}
}

const mediumGroups = `"Group Name","Type","SID","Attributes"` + "\r\n" +
	`"BUILTIN\Remote Management Users","Alias","S-1-5-32-580","Mandatory group, Enabled by default, Enabled group"` + "\r\n" +
	`"Mandatory Label\Medium Mandatory Level","Label","S-1-16-8192",""` + "\r\n"

// A UAC-filtered administrator: the group is present but marked deny-only,
// and the label is Medium. Membership would lie; the label does not.
const filteredAdminGroups = `"Group Name","Type","SID","Attributes"` + "\r\n" +
	`"BUILTIN\Administrators","Alias","S-1-5-32-544","Group used for deny only"` + "\r\n" +
	`"Mandatory Label\Medium Mandatory Level","Label","S-1-16-8192",""` + "\r\n"

const highGroups = `"Group Name","Type","SID","Attributes"` + "\r\n" +
	`"BUILTIN\Administrators","Alias","S-1-5-32-544","Mandatory group, Enabled by default, Enabled group, Group owner"` + "\r\n" +
	`"Mandatory Label\High Mandatory Level","Label","S-1-16-12288",""` + "\r\n"

func TestPreflightMediumTokenIsDiscoverOnly(t *testing.T) {
	for name, csv := range map[string]string{"standard user": mediumGroups, "filtered admin": filteredAdminGroups} {
		srv := preflightServer(t, "ok", csv)
		got := runPreflight(t, srv)
		srv.Close()
		if got.Level != PreflightDiscover || !got.CanDiscover || got.CanInstall {
			t.Fatalf("%s: %+v", name, got)
		}
	}
}

func TestPreflightHighTokenCanInstall(t *testing.T) {
	srv := preflightServer(t, "ok", highGroups)
	defer srv.Close()
	got := runPreflight(t, srv)
	if got.Level != PreflightInstall || !got.CanDiscover || !got.CanInstall {
		t.Fatalf("%+v", got)
	}
}

func TestPreflightTransportFailureIsUnreachable(t *testing.T) {
	srv := preflightServer(t, "ok", highGroups)
	srv.Close() // connection refused
	got := PreflightWinRM(context.Background(), WinRMConfig{EndpointURL: srv.URL, Username: "u", Password: "p"}, srv.Client())
	if got.Level != PreflightUnreachable || got.CanDiscover {
		t.Fatalf("%+v", got)
	}
}
