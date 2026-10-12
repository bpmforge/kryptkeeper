// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode/utf16"
)

// W14-02: agentless Windows discovery over WinRM. WinRM is WS-Management
// (SOAP/XML over HTTP), the same family the WSTEP client hand-rolls with
// stdlib; the WS-Man Shell (WinRS) protocol runs a command and reads
// stdout through plain SOAP round-trips — no PSRP binary framing, so no
// new dependency. Auth is HTTP Basic over HTTPS: TLS is what satisfies
// WinRM's message-encryption requirement, so the host keeps
// service/AllowUnencrypted=false and only needs service/auth Basic=true.
//
// W18-06: that distinction is load-bearing and was previously stated
// wrongly here. AllowUnencrypted is a MESSAGE-layer requirement, separate
// from authentication -- over plain HTTP, WinRM rejects an unencrypted
// SOAP body even after auth succeeds. Adding an auth mechanism alone
// (Negotiate/NTLM) therefore does NOT unblock a default-configured host;
// it also needs sealing of the payload, which W18-09 supplies for http
// endpoints (winrm_sealed.go, ntlm_session.go). HTTPS
// satisfies both requirements at once, which is why it is the supported
// path and not merely the recommended one.

const (
	wsmanShellURI = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
	wsmanNS       = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
)

// WinRMConfig locates and authenticates the WS-Man endpoint.
type WinRMConfig struct {
	// EndpointURL, e.g. https://host.corp.example:5986/wsman
	EndpointURL string
	Username    string
	Password    string
	// RootCAs, when non-nil, is the pool the listener certificate must
	// chain to; nil means the host's system roots. A WinRM listener is
	// routinely fronted by a certificate this very product issued, which
	// the system roots do not know about -- that is what this exists for.
	//
	// There is deliberately NO skip-verify companion to this field. A
	// product whose job is to distribute trust does not get to switch
	// verification off to deliver a certificate; if the listener cert does
	// not verify, the install fails loudly and the operator fixes the
	// trust path.
	RootCAs *x509.CertPool
}

// WinRMRootCAsFromEnv builds the listener trust pool from
// KRYPTKEEPER_WINRM_CA_CERT (inline PEM) or KRYPTKEEPER_WINRM_CA_CERT_FILE
// (path), mirroring the vocabulary internal/certmanager already uses for
// KRYPTKEEPER_K8S_CA_CERT. Returns (nil, nil) when neither is set, meaning
// "verify against the system roots".
func WinRMRootCAsFromEnv() (*x509.CertPool, error) {
	pem := []byte(os.Getenv("KRYPTKEEPER_WINRM_CA_CERT"))
	if f := os.Getenv("KRYPTKEEPER_WINRM_CA_CERT_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read WinRM CA cert file %q: %w", f, err)
		}
		pem = b
	}
	if len(pem) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		// Silently falling back to system roots here would turn a
		// mistyped bundle into a confusing verification failure later.
		return nil, fmt.Errorf("WinRM CA bundle contains no usable PEM certificate")
	}
	return pool, nil
}

// WSManShell runs commands on a Windows host through WS-Man Shell.
type WSManShell struct {
	cfg    WinRMConfig
	client *http.Client
	sealed sealedSession
}

func NewWSManShell(cfg WinRMConfig, client *http.Client) *WSManShell {
	// A caller-supplied client WINS: the tests hand in httptest's client,
	// whose transport already trusts the fixture's own certificate, and
	// rebuilding it from cfg would break that. Config-driven trust applies
	// only to the nil case, which is what production takes
	// (renewal_executor passes a nil pushClient).
	if client == nil {
		client = &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12},
			// One connection: NTLM authenticates the TCP connection, so the
			// sealed http path must keep talking over the one it authenticated.
			MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1,
		}}
	}
	return &WSManShell{cfg: cfg, client: client}
}

// messageID returns a fresh WS-Addressing MessageID. WS-Man requires one on
// every request and Windows rejects an envelope without it ("MessageID
// element that was either invalid, duplicated, or too long") -- captured
// live on 2026-09-10, the first time this client reached a real listener.
// A random v4 UUID from crypto/rand keeps the module free of a uuid dep.
func messageID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never returns an error on supported platforms
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("uuid:%08X-%04X-%04X-%04X-%012X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// soap posts one WS-Man request. shellID is empty only for the Create that
// mints it; every later action must carry it as a SelectorSet or the
// service has no shell to route the call to.
func (s *WSManShell) soap(ctx context.Context, action, shellID, body string) ([]byte, error) {
	selector := ""
	if shellID != "" {
		selector = `<w:SelectorSet><w:Selector Name="ShellId">` + xmlEscape(shellID) + `</w:Selector></w:SelectorSet>`
	}
	// WINRS_CODEPAGE 65001 makes the host emit UTF-8 so non-ASCII in
	// netsh/certutil output survives decoding; NOPROFILE skips a profile
	// load the enumeration and install scripts never need.
	options := ""
	if strings.HasSuffix(action, "/transfer/Create") {
		options = `<w:OptionSet><w:Option Name="WINRS_NOPROFILE">TRUE</w:Option><w:Option Name="WINRS_CODEPAGE">65001</w:Option></w:OptionSet>`
	}
	envelope := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:w="%s"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <a:To>%s</a:To>
    <a:ReplyTo><a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
    <a:Action s:mustUnderstand="true">%s</a:Action>
    <a:MessageID>%s</a:MessageID>
    <w:ResourceURI s:mustUnderstand="true">%s</w:ResourceURI>
    <w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>
    <w:OperationTimeout>PT60S</w:OperationTimeout>
    %s%s
  </s:Header>
  <s:Body>%s</s:Body>
</s:Envelope>`, wsmanNS, xmlEscape(s.cfg.EndpointURL), action, messageID(), wsmanShellURI, selector, options, body)

	u, err := url.Parse(s.cfg.EndpointURL)
	if err != nil {
		return nil, fmt.Errorf("winrm: bad endpoint URL: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		// W18-09: Basic never leaves over http. The sealed NTLM path is the only one.
		return s.soapSealed(ctx, action, []byte(envelope))
	default:
		return nil, fmt.Errorf("winrm: endpoint scheme %q is not http or https", u.Scheme)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.EndpointURL, strings.NewReader(envelope))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.SetBasicAuth(s.cfg.Username, s.cfg.Password)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // error surfaces via status/parse below
	// W18-06: the fault body used to be read and thrown away, so every
	// non-2xx collapsed into a bare status code. WS-Man answers with a
	// SOAP fault whose Reason distinguishes "this account may not use
	// WinRM" from "wrong password" -- the same swallowing defect showBinding
	// had, one layer down. Anything built on top of this can only be as
	// specific as what this function preserves.
	if resp.StatusCode >= 400 {
		detail, code := faultDetail(raw)
		return nil, &WinRMError{Status: resp.StatusCode, FaultCode: code, Action: action, Detail: detail}
	}
	return raw, nil
}

// WinRMError is a non-2xx answer from the listener. Status and FaultCode
// are what callers classify on (W18-11): a 401 is "wrong password OR not
// admitted by the RootSDDL" and the wire cannot say which; a 500 whose
// WSManFault Code is 5 (ERROR_ACCESS_DENIED) is "authenticated, admitted,
// but not allowed to open a shell". Both captured live on 2026-09-10.
type WinRMError struct {
	Status    int
	FaultCode int
	Action    string
	Detail    string
	// Sealed marks an answer on the NTLM-over-http path, whose 401 means
	// something different from the Basic-over-HTTPS one.
	Sealed bool
}

func (e *WinRMError) Error() string {
	if e.Status == http.StatusUnauthorized && e.Sealed {
		return "winrm: HTTP 401 on the NTLM-over-http path: the password is wrong, the account is not admitted by the " +
			"RootSDDL, or the listener dropped the connection-bound session" + e.Detail
	}
	if e.Status == http.StatusUnauthorized {
		return fmt.Sprintf("winrm: HTTP 401 unauthorized%s "+
			"(this client authenticates with HTTP Basic: the listener needs "+
			"`winrm set winrm/config/service/auth @{Basic=\"true\"}` and an HTTPS "+
			"listener, which lets service/AllowUnencrypted stay false. "+
			"AllowBasic is the CLIENT-side setting and does not apply here)", e.Detail)
	}
	return fmt.Sprintf("winrm %s: HTTP %d%s", e.Action, e.Status, e.Detail)
}

// ShellDenied reports the "admitted to WinRM but may not create a shell"
// state: authentication succeeded, so telling the operator to check the
// password would send them after a password that is already right.
func (e *WinRMError) ShellDenied() bool {
	return e.Status == http.StatusInternalServerError && e.FaultCode == 5
}

// faultDetail extracts the human-readable Reason and the WSManFault Code
// from a WS-Man SOAP fault, formatted for appending to an error. Returns
// ("", 0) when the body carries no fault -- a 401 from the HTTP layer has
// no SOAP body at all.
func faultDetail(raw []byte) (string, int) {
	var env struct {
		Body struct {
			Fault struct {
				Reason string `xml:"Reason>Text"`
				Detail struct {
					WSManFault struct {
						Code    string `xml:"Code,attr"`
						Message string `xml:"Message"`
					} `xml:"WSManFault"`
				} `xml:"Detail"`
			} `xml:"Fault"`
		} `xml:"Body"`
	}
	if err := xml.Unmarshal(raw, &env); err != nil {
		return "", 0
	}
	code, _ := strconv.Atoi(strings.TrimSpace(env.Body.Fault.Detail.WSManFault.Code))
	for _, s := range []string{env.Body.Fault.Detail.WSManFault.Message, env.Body.Fault.Reason} {
		if t := strings.Join(strings.Fields(s), " "); t != "" {
			return ": " + t, code
		}
	}
	return "", code
}

// xmlEscape (defined in wstep_client.go's package — this is a distinct
// package, so a local copy).
func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s)) // bytes.Buffer writes cannot fail
	return b.String()
}

// powerShellEncode returns the -EncodedCommand argument: UTF-16LE
// base64, PowerShell's documented contract.
func powerShellEncode(script string) string {
	u16 := utf16.Encode([]rune(script))
	buf := make([]byte, len(u16)*2)
	for i, r := range u16 {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

type wsmanShellResp struct {
	Body struct {
		Selector []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"ResourceCreated>ReferenceParameters>SelectorSet>Selector"`
		CommandID string `xml:"CommandResponse>CommandId"`
		Streams   []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"ReceiveResponse>Stream"`
		CommandState struct {
			State    string `xml:"State,attr"`
			ExitCode string `xml:"ExitCode"`
		} `xml:"ReceiveResponse>CommandState"`
	} `xml:"Body"`
}

// Run executes `command args...` and returns decoded stdout. Transport
// and SOAP failures are errors; the remote exit status is not -- callers
// that need it use RunExit.
func (s *WSManShell) Run(ctx context.Context, command string, args ...string) (string, error) {
	stdout, _, _, err := s.RunExit(ctx, command, args...)
	return stdout, err
}

// RunExit executes `command args...` and returns stdout, stderr and the
// process exit code WS-Man reports in the final CommandState (MS-WSMV
// rsp:ExitCode). That native report replaced an echoed-sentinel scheme:
// the sentinel needed a wrapper process, and wrapping a long script twice
// (once for the child, once for the wrapper) blew past the WinRM cmd
// shell's command-line limit so the sentinel never ran (live, 2026-09-10,
// the PFX build). Here nothing is wrapped: a native command runs as-is
// and a PowerShell script is encoded exactly once.
func (s *WSManShell) RunExit(ctx context.Context, command string, args ...string) (stdout, stderr string, exitCode int, err error) {
	// 1. Create shell.
	raw, err := s.soap(ctx, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create", "",
		`<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>`)
	if err != nil {
		return "", "", 0, err
	}
	var created wsmanShellResp
	if err := xml.Unmarshal(raw, &created); err != nil {
		return "", "", 0, fmt.Errorf("winrm create: %w", err)
	}
	shellID := ""
	for _, sel := range created.Body.Selector {
		if sel.Name == "ShellId" {
			shellID = strings.TrimSpace(sel.Value)
		}
	}
	if shellID == "" {
		return "", "", 0, fmt.Errorf("winrm: shell creation returned no ShellId")
	}
	defer func() {
		_, _ = s.soap(ctx, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete", shellID, "") // best-effort cleanup
	}()

	// 2. Command. WinRM joins Arguments with spaces and does not quote,
	// so an argument with whitespace is quoted here (cmd.exe rules).
	var argXML strings.Builder
	for _, a := range args {
		fmt.Fprintf(&argXML, "<rsp:Arguments>%s</rsp:Arguments>", xmlEscape(cmdQuote(a)))
	}
	raw, err = s.soap(ctx, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command", shellID,
		fmt.Sprintf(`<rsp:CommandLine><rsp:Command>%s</rsp:Command>%s</rsp:CommandLine>`, xmlEscape(command), argXML.String()))
	if err != nil {
		return "", "", 0, err
	}
	var cmd wsmanShellResp
	if err := xml.Unmarshal(raw, &cmd); err != nil {
		return "", "", 0, fmt.Errorf("winrm command: %w", err)
	}
	commandID := strings.TrimSpace(cmd.Body.CommandID)

	// 3. Receive until Done.
	var out, errOut strings.Builder
	for i := 0; i < 100; i++ {
		raw, err = s.soap(ctx, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive", shellID,
			fmt.Sprintf(`<rsp:Receive><rsp:DesiredStream CommandId="%s">stdout stderr</rsp:DesiredStream></rsp:Receive>`, commandID))
		if err != nil {
			return "", "", 0, err
		}
		var recv wsmanShellResp
		if err := xml.Unmarshal(raw, &recv); err != nil {
			return "", "", 0, fmt.Errorf("winrm receive: %w", err)
		}
		for _, st := range recv.Body.Streams {
			dec, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(st.Value))
			if derr != nil {
				return "", "", 0, fmt.Errorf("winrm: %s not base64: %w", st.Name, derr)
			}
			switch st.Name {
			case "stdout":
				out.Write(dec)
			case "stderr":
				errOut.Write(dec)
			}
		}
		if strings.HasSuffix(recv.Body.CommandState.State, "/Done") {
			if c := strings.TrimSpace(recv.Body.CommandState.ExitCode); c != "" {
				exitCode, _ = strconv.Atoi(c)
			}
			break
		}
	}
	return out.String(), errOut.String(), exitCode, nil
}

// cmdQuote wraps an argument containing whitespace or a quote in double
// quotes, escaping embedded quotes, which is what cmd.exe's parser expects.
func cmdQuote(a string) string {
	if a != "" && !strings.ContainsAny(a, " \t\"") {
		return a
	}
	return `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
}

// certEnumScript enumerates the machine cert stores, emitting one
// base64 DER per line. It reads only .RawData — never .PrivateKey —
// so no key material is ever accessed.
//
// W18-17: it also appends one marker line reporting the W3SVC (IIS)
// service state, in the same round trip as the cert enumeration -- a
// second PowerShell invocation would double the WinRM shell-creation
// cost for a single service lookup. The install recommendation this
// feeds must come from what the host reports, not from the transport
// used to reach it: a Windows box with no IIS installed must not get an
// IIS install recommendation just because it answered on WinRM.
const certEnumScript = `$s='My','Root','CA','TrustedPublisher';foreach($n in $s){Get-ChildItem "Cert:\LocalMachine\$n" -EA SilentlyContinue|ForEach-Object{[Convert]::ToBase64String($_.RawData)+' '+$n}};$w=Get-Service W3SVC -EA SilentlyContinue;if($w){Write-Output ('__KK_W3SVC__='+$w.Status)}else{Write-Output '__KK_W3SVC__=absent'}`

// iisMarkerPrefix tags the W3SVC status line certEnumScript appends so it
// can be pulled out of the enumeration output before the cert-line loop
// runs -- it must never be mistaken for a (malformed) cert line.
const iisMarkerPrefix = "__KK_W3SVC__="

// AgentlessWinRMScanner enumerates Windows machine cert stores.
type AgentlessWinRMScanner struct {
	shell *WSManShell
	host  string
}

func NewAgentlessWinRMScanner(shell *WSManShell, host string) *AgentlessWinRMScanner {
	return &AgentlessWinRMScanner{shell: shell, host: host}
}

// Scan runs the enumeration and parses each base64 DER into a cert.
func (s *AgentlessWinRMScanner) Scan(ctx context.Context) AgentlessScanResult {
	res := AgentlessScanResult{Host: s.host}
	out, err := s.shell.Run(ctx, "powershell", "-NonInteractive", "-EncodedCommand", powerShellEncode(certEnumScript))
	if err != nil {
		res.Errors = append(res.Errors, s.host+": "+err.Error())
		return res
	}
	seen := map[string]struct{}{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Pull the IIS marker out before it can reach the cert-line
		// parsing below -- it carries no base64 payload and would
		// otherwise be logged as an undecodable cert line.
		if strings.HasPrefix(line, iisMarkerPrefix) {
			res.IISService = strings.TrimPrefix(line, iisMarkerPrefix)
			continue
		}
		fields := strings.Fields(line)
		store := ""
		if len(fields) == 2 {
			store = fields[1]
		}
		der, derr := base64.StdEncoding.DecodeString(fields[0])
		if derr != nil {
			res.Errors = append(res.Errors, s.host+": undecodable cert line")
			continue
		}
		cert, perr := x509.ParseCertificate(der)
		if perr != nil {
			res.Errors = append(res.Errors, s.host+": unparseable cert in "+store)
			continue
		}
		c := certToDiscovered(cert, "agentless-winrm:"+store)
		if _, dup := seen[c.Fingerprint]; dup {
			continue
		}
		seen[c.Fingerprint] = struct{}{}
		res.Certs = append(res.Certs, c)
		res.Parsed = append(res.Parsed, cert)
	}
	return res
}
