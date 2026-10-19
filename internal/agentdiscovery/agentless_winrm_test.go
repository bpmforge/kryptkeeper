// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// W14-02: agentless Windows discovery against a fixture WS-Man Shell
// server — the Create/Command/Receive/Delete dance, base64-DER cert
// output, agent-identical fingerprints, Basic auth, and no key access.

func certDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(60 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return der
}

// wsmanFixture plays the WS-Man Shell conversation. corruptStdout makes
// the Receive return a non-base64 stdout stream.
type wsmanFixture struct {
	srv           *httptest.Server
	actions       []string
	stdout        string // the command output (pre-base64)
	corruptStdout bool
	// postureStdout answers the W34-12 posture script; empty = same as stdout.
	postureOut string
	posture    bool
}

func newWSManFixture(t *testing.T, stdout string) *wsmanFixture {
	t.Helper()
	f := &wsmanFixture{stdout: stdout}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "winadmin" || pass != "winpass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		w.Header().Set("Content-Type", "application/soap+xml")
		switch {
		case strings.Contains(body, "transfer/Create"):
			f.actions = append(f.actions, "create")
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="x"><s:Body><ResourceCreated><ReferenceParameters><SelectorSet><Selector Name="ShellId">SHELL-1</Selector></SelectorSet></ReferenceParameters></ResourceCreated></s:Body></s:Envelope>`)
		case strings.Contains(body, "shell/Command"):
			f.actions = append(f.actions, "command")
			f.posture = strings.Contains(body, xmlEscape(powerShellEncode(winPostureScript)))
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="x"><s:Body><CommandResponse><CommandId>CMD-1</CommandId></CommandResponse></s:Body></s:Envelope>`)
		case strings.Contains(body, "shell/Receive"):
			f.actions = append(f.actions, "receive")
			out := f.stdout
			if f.posture && f.postureOut != "" {
				out = f.postureOut
			}
			payload := base64.StdEncoding.EncodeToString([]byte(out))
			if f.corruptStdout {
				payload = "!!!not base64!!!"
			}
			_, _ = io.WriteString(w, fmt.Sprintf(`<s:Envelope xmlns:s="x"><s:Body><ReceiveResponse><Stream Name="stdout">%s</Stream><CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><ExitCode>0</ExitCode></CommandState></ReceiveResponse></s:Body></s:Envelope>`, payload))
		case strings.Contains(body, "transfer/Delete"):
			f.actions = append(f.actions, "delete")
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="x"><s:Body/></s:Envelope>`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *wsmanFixture) scanner() *AgentlessWinRMScanner {
	shell := NewWSManShell(WinRMConfig{EndpointURL: f.srv.URL, Username: "winadmin", Password: "winpass"}, f.srv.Client())
	return NewAgentlessWinRMScanner(shell, "win-host")
}

func TestWinRMScanParsesCertStores(t *testing.T) {
	der := certDER(t, "srv.corp.example")
	stdout := base64.StdEncoding.EncodeToString(der) + " My\n" +
		base64.StdEncoding.EncodeToString(certDER(t, "root.corp.example")) + " Root\n"
	f := newWSManFixture(t, stdout)

	res := f.scanner().Scan(context.Background())
	if len(res.Certs) != 2 {
		t.Fatalf("expected 2 certs, got %d: %+v (errors %v)", len(res.Certs), res.Certs, res.Errors)
	}
	// Store tag carried through.
	if res.Certs[0].Source != "agentless-winrm:My" {
		t.Fatalf("store tag: %q", res.Certs[0].Source)
	}
	// Fingerprint matches the agent's own parser.
	agentCerts, _, _ := parseCertsSkippingKeys([]byte("-----BEGIN CERTIFICATE-----\n"+base64Wrap(der)+"\n-----END CERTIFICATE-----"), "x")
	if len(agentCerts) != 1 || res.Certs[0].Fingerprint != agentCerts[0].Fingerprint {
		t.Fatalf("fingerprint mismatch vs agent parser")
	}
	// The full WS-Man conversation happened.
	joined := strings.Join(f.actions, ",")
	if !strings.HasPrefix(joined, "create,command,receive") {
		t.Fatalf("ws-man conversation: %v", f.actions)
	}
	// No key material in the result.
	if strings.Contains(fmt.Sprintf("%+v", res), "PRIVATE KEY") {
		t.Fatal("result must not carry key material")
	}
}

// W18-17: the IIS marker line rides the same round trip as the cert
// enumeration and must never be mistaken for a cert line.
func TestWinRMScanReportsW3SVCState(t *testing.T) {
	der := certDER(t, "srv.corp.example")
	certLine := base64.StdEncoding.EncodeToString(der) + " My\n"

	t.Run("running", func(t *testing.T) {
		f := newWSManFixture(t, certLine+"__KK_W3SVC__=Running\n")
		res := f.scanner().Scan(context.Background())
		if res.IISService != "Running" {
			t.Fatalf("IISService = %q, want Running", res.IISService)
		}
		if len(res.Certs) != 1 {
			t.Fatalf("marker line must not be counted as a cert: %+v", res.Certs)
		}
	})

	t.Run("absent", func(t *testing.T) {
		f := newWSManFixture(t, certLine+"__KK_W3SVC__=absent\n")
		res := f.scanner().Scan(context.Background())
		if res.IISService != "absent" {
			t.Fatalf("IISService = %q, want absent", res.IISService)
		}
		if len(res.Certs) != 1 {
			t.Fatalf("marker line must not be counted as a cert: %+v", res.Certs)
		}
	})

	t.Run("missing marker", func(t *testing.T) {
		f := newWSManFixture(t, certLine)
		res := f.scanner().Scan(context.Background())
		if res.IISService != "" {
			t.Fatalf("IISService = %q, want empty when the marker is missing", res.IISService)
		}
		if len(res.Certs) != 1 {
			t.Fatalf("cert count must be unaffected: %+v", res.Certs)
		}
	})
}

func TestWinRMEncodedCommandIsUTF16LEAndKeyless(t *testing.T) {
	enc := powerShellEncode(certEnumScript)
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("encoded command not base64: %v", err)
	}
	// UTF-16LE: even length, ASCII chars have a zero high byte.
	if len(raw)%2 != 0 || raw[1] != 0 {
		t.Fatalf("encoded command is not UTF-16LE")
	}
	// Round-trips back to the script.
	u16 := make([]uint16, len(raw)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	if string(utf16.Decode(u16)) != certEnumScript {
		t.Fatal("encoded command does not round-trip")
	}
	// The enumeration never touches private keys.
	if strings.Contains(certEnumScript, "PrivateKey") {
		t.Fatal("enumeration script must not access PrivateKey")
	}
}

func TestWinRMAuthFailureSurfaces(t *testing.T) {
	f := newWSManFixture(t, "")
	shell := NewWSManShell(WinRMConfig{EndpointURL: f.srv.URL, Username: "winadmin", Password: "wrong"}, f.srv.Client())
	res := NewAgentlessWinRMScanner(shell, "win-host").Scan(context.Background())
	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0], "401") {
		t.Fatalf("auth failure must surface: %v", res.Errors)
	}
}

func TestWinRMCorruptStdoutErrors(t *testing.T) {
	f := newWSManFixture(t, "")
	f.corruptStdout = true
	res := f.scanner().Scan(context.Background())
	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0], "base64") {
		t.Fatalf("corrupt stdout must error: %v", res.Errors)
	}
}

// base64Wrap wraps a DER cert as 64-col PEM body.
func base64Wrap(der []byte) string {
	s := base64.StdEncoding.EncodeToString(der)
	var b strings.Builder
	for len(s) > 64 {
		b.WriteString(s[:64])
		b.WriteByte('\n')
		s = s[64:]
	}
	b.WriteString(s)
	return b.String()
}

// W18-06: the listener-trust and fault-preservation contract.
//
// A WinRM listener is routinely fronted by a certificate THIS product
// issued, which the system roots do not know about. Before W18-06 the
// production path took http.DefaultClient (renewal_executor passes a nil
// pushClient), so such a listener could not be verified at all — and the
// only escape would have been a skip-verify knob, which a product that
// distributes trust does not get to ship.

// tlsWSManFixture serves the WS-Man conversation over HTTPS.
func tlsWSManFixture(t *testing.T, stdout string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/soap+xml")
		switch {
		case strings.Contains(string(body), "transfer/Create"):
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="x"><s:Body><ResourceCreated><ReferenceParameters><SelectorSet><Selector Name="ShellId">SHELL-1</Selector></SelectorSet></ReferenceParameters></ResourceCreated></s:Body></s:Envelope>`)
		case strings.Contains(string(body), "shell/Command"):
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="x"><s:Body><CommandResponse><CommandId>CMD-1</CommandId></CommandResponse></s:Body></s:Envelope>`)
		case strings.Contains(string(body), "shell/Receive"):
			_, _ = io.WriteString(w, fmt.Sprintf(`<s:Envelope xmlns:s="x"><s:Body><ReceiveResponse><Stream Name="stdout">%s</Stream><CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"/></ReceiveResponse></s:Body></s:Envelope>`,
				base64.StdEncoding.EncodeToString([]byte(stdout))))
		default:
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="x"><s:Body/></s:Envelope>`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestWinRMTrustsConfiguredCABundleAndRejectsOthers(t *testing.T) {
	srv := tlsWSManFixture(t, "ok\n")

	trusting := x509.NewCertPool()
	trusting.AddCert(srv.Certificate())

	// Passing a nil client is what production does; the pool must be what
	// makes verification succeed.
	shell := NewWSManShell(WinRMConfig{EndpointURL: srv.URL, Username: "u", Password: "p", RootCAs: trusting}, nil)
	if _, err := shell.Run(context.Background(), "cmd", "/C", "echo ok"); err != nil {
		t.Fatalf("a listener cert chaining to the configured bundle must verify: %v", err)
	}

	// Red-check: an unrelated CA must FAIL. If this stays green, the pool
	// is not being consulted and the test above proves nothing.
	unrelated := x509.NewCertPool()
	unrelated.AddCert(mustParse(t, certDER(t, "somebody-else")))
	shell = NewWSManShell(WinRMConfig{EndpointURL: srv.URL, Username: "u", Password: "p", RootCAs: unrelated}, nil)
	_, err := shell.Run(context.Background(), "cmd", "/C", "echo ok")
	if err == nil {
		t.Fatal("a listener cert outside the configured bundle must NOT verify — no skip-verify path may exist")
	}
	// Assert it failed for the RIGHT reason: any error would satisfy a bare
	// nil-check, including one that never reached TLS.
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("expected an x509 trust failure, got a different error: %v", err)
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

func TestWinRMRootCAsFromEnv(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER(t, "bundle.example")})

	t.Run("unset means system roots", func(t *testing.T) {
		pool, err := WinRMRootCAsFromEnv()
		if err != nil || pool != nil {
			t.Fatalf("no env must mean (nil, nil), got %v %v", pool, err)
		}
	})
	t.Run("inline PEM", func(t *testing.T) {
		t.Setenv("KRYPTKEEPER_WINRM_CA_CERT", string(pemBytes))
		pool, err := WinRMRootCAsFromEnv()
		if err != nil || pool == nil {
			t.Fatalf("inline PEM must build a pool: %v %v", pool, err)
		}
	})
	t.Run("file", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(f, pemBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("KRYPTKEEPER_WINRM_CA_CERT_FILE", f)
		pool, err := WinRMRootCAsFromEnv()
		if err != nil || pool == nil {
			t.Fatalf("PEM file must build a pool: %v %v", pool, err)
		}
	})
	t.Run("garbage errors rather than silently using system roots", func(t *testing.T) {
		t.Setenv("KRYPTKEEPER_WINRM_CA_CERT", "not a certificate")
		if _, err := WinRMRootCAsFromEnv(); err == nil {
			t.Fatal("an unusable bundle must error — falling back to system roots would hide the misconfiguration until a confusing verification failure later")
		}
	})
}

// The 401 previously blamed AllowBasic, which is the CLIENT-side setting
// (winrm/config/client/auth) and cannot affect a Go client. An operator
// following it changed the wrong knob.
func TestWinRM401NamesServiceSideKnobsNotAllowBasic(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	shell := NewWSManShell(WinRMConfig{EndpointURL: srv.URL, Username: "u", Password: "p"}, srv.Client())
	_, err := shell.Run(context.Background(), "cmd")
	if err == nil {
		t.Fatal("a 401 must surface as an error")
	}
	msg := err.Error()
	for _, want := range []string{"401", "service/auth", "CLIENT-side"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("401 error must mention %q so the operator changes the right knob; got: %s", want, msg)
		}
	}
}

// A WS-Man fault carries the only text that distinguishes "this account
// may not use WinRM" from "wrong password". Dropping it is the same
// swallowing defect showBinding had.
func TestWinRMSoapFaultReasonReachesTheError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/soap+xml")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault><s:Reason><s:Text>Access is denied.</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>`)
	}))
	t.Cleanup(srv.Close)

	shell := NewWSManShell(WinRMConfig{EndpointURL: srv.URL, Username: "u", Password: "p"}, srv.Client())
	_, err := shell.Run(context.Background(), "cmd")
	if err == nil || !strings.Contains(err.Error(), "Access is denied.") {
		t.Fatalf("the SOAP fault Reason must reach the operator, got: %v", err)
	}
}
