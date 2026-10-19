// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

// IIS has neither a cert file to write (unlike nginx/apache in installer.go)
// nor an in-process reload call: the renewed key pair must land in the
// Windows certificate store and the HTTP.sys SSL binding must be repointed
// at it. Both operations only exist as OS tooling (certutil, netsh), so this
// file follows the same "shell out through Executor" shape as installer.go
// rather than calling Win32 APIs directly — there is no PKCS#12 encoder in
// this module's dependencies (golang.org/x/crypto/pkcs12 is decode-only,
// confirmed via `go doc golang.org/x/crypto/pkcs12`; software.sslmate.com/src/go-pkcs12
// would encode but isn't in go.mod, and adding a dependency for this is a
// refusal condition per MASTER_PROMPT.md) and golang.org/x/sys/windows does
// not wrap the NCrypt/CertSetCertificateContextProperty calls a from-scratch
// store import would need, so a hand-rolled binding would be exactly the
// kind of unverifiable low-level crypto call this codebase's rules warn
// against. The PFX-building PowerShell and the certutil/netsh flag syntax
// below are standard, long-documented Windows tooling but were written on a
// non-Windows dev host and could not be exercised against a real Windows box
// in this session — see the commit body and docs/STATUS.md for exactly what
// was and wasn't verified.
//
// Because there's no in-process PFX encoder, the renewed key still has to
// touch disk as a PKCS#8 DER file for the PowerShell step to read. It is
// staged in a directory created fresh for this one install and locked down
// with an explicit icacls ACL (SYSTEM + Administrators only) BEFORE any key
// bytes are written into it — not the shared, every-local-account-writable
// C:\Windows\Temp, and not relying on the Windows-file-mode bits WriteFile's
// `mode` parameter carries (os.Chmod/os.WriteFile on Windows only toggles
// the FILE_ATTRIBUTE_READONLY DOS attribute from the 0200 bit; it does not
// create an ACL). The whole per-install directory, not just the individual
// files, is removed once certutil has imported the PFX. Residual, honestly
// stated: certutil's -p password still goes over argv (Executor has no
// stdin-passing Run variant), so the actual protection here is the random
// per-install password plus the ACL'd, freshly-created, immediately-deleted
// directory — not secrecy of that password. There's also a narrow TOCTOU
// window between the mkdir and the icacls call that a from-scratch Win32
// CreateDirectory+SetSecurityDescriptor could close atomically; Executor's
// shell-command-only interface can't express that, and adding a Win32 API
// dependency runs into the same unverifiable-low-level-call problem noted
// above.

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // Windows store thumbprint is a lookup key (CERT_SHA1_HASH_PROP_ID), not a signature
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"software.sslmate.com/src/go-pkcs12"
	"strconv"
	"strings"
)

// IIS-specific outcomes. installer.go's Outcome* constants cover the
// file-based server types; IIS fails at different steps (store import,
// HTTP.sys binding) with no equivalent there.
const (
	OutcomeCertImportFailed = "cert_import_failed"
	OutcomeBindingFailed    = "binding_failed"
)

// defaultIISStageRoot is the parent under which a fresh, ACL-locked
// subdirectory is created for each install (see createLockedStageDir). The
// root's own permissions don't matter for confidentiality — the key never
// lands there directly, only inside the locked-down subdirectory — but using
// Kryptkeeper's own ProgramData tree rather than the machine-wide
// C:\Windows\Temp at least keeps the staging subdirectories out of a
// directory every local process already has a reason to watch.
const defaultIISStageRoot = `C:\ProgramData\Kryptkeeper\iis-stage`

// SIDs for the stage directory's ACL, used instead of names ("BUILTIN\Administrators")
// so icacls behaves the same regardless of the box's display-language locale.
const (
	sidLocalSystem    = `*S-1-5-18`
	sidAdministrators = `*S-1-5-32-544`
)

// IISInstallRequest describes a renewed cert/key to install into the Windows
// certificate store and bind to an IIS HTTPS endpoint via HTTP.sys.
type IISInstallRequest struct {
	// IPPort is the HTTP.sys binding address, e.g. "0.0.0.0:443".
	IPPort string
	// AppID is the IIS application GUID that owns the binding (see the
	// site's applicationHost.config). Required by netsh; if empty, the
	// AppID of the binding currently at IPPort is reused.
	AppID string
	// StoreName is the certificate store to import into; defaults to "My"
	// (Personal, LocalMachine).
	StoreName string

	CertPEM []byte
	KeyPEM  []byte

	// Verify-after-install, same contract as InstallRequest: when both are
	// set, the installer TLS-dials VerifyHostPort after reload and rolls
	// back if the served leaf doesn't match ExpectedFingerprint.
	VerifyHostPort      string
	ExpectedFingerprint string
}

// sslBinding is a captured HTTP.sys SSL certificate binding (the output of
// `netsh http show sslcert`), used to restore prior state on rollback.
type sslBinding struct {
	certHash  string
	appID     string
	storeName string
	existed   bool
}

// IISInstaller imports a renewed cert into the Windows certificate store and
// rebinds it to an IIS HTTPS endpoint, with rollback on failure. All
// privileged work goes through Executor, exactly like Installer, so it is
// testable without a real Windows host.
type IISInstaller struct {
	exec    Executor
	verify  Verifier
	tempDir string
}

// NewIISInstaller returns an IISInstaller backed by exec and the default
// TLS-dial verifier.
func NewIISInstaller(exec Executor) *IISInstaller {
	return &IISInstaller{exec: exec, verify: defaultVerifier, tempDir: defaultIISStageRoot}
}

// WithVerifier overrides the verifier (used in tests).
func (in *IISInstaller) WithVerifier(v Verifier) *IISInstaller {
	in.verify = v
	return in
}

// WithTempDir overrides the root under which each install's locked-down
// staging subdirectory is created (used in tests).
func (in *IISInstaller) WithTempDir(dir string) *IISInstaller {
	in.tempDir = dir
	return in
}

// Install imports the renewed cert/key into the Windows certificate store,
// captures the existing HTTP.sys SSL binding for req.IPPort, rebinds it to
// the renewed cert, reloads IIS, and verifies the new cert is actually being
// served. Any failure after the binding change rolls the binding back to
// what was captured; a failure before the binding change (cert import) never
// touches the live binding at all.
func (in *IISInstaller) Install(ctx context.Context, req IISInstallRequest) (InstallResult, error) {
	if req.IPPort == "" || len(req.CertPEM) == 0 || len(req.KeyPEM) == 0 {
		return InstallResult{}, fmt.Errorf("iis install: ipport, cert PEM, and key PEM are required")
	}
	if err := validateIISRequestFields(req); err != nil {
		return InstallResult{}, err
	}
	store := req.StoreName
	if store == "" {
		store = "My"
	}

	// 1. Capture the existing binding (if any) so we can restore it on rollback.
	prior, err := in.showBinding(ctx, req.IPPort)
	if err != nil {
		return InstallResult{}, fmt.Errorf("iis install: %w", err)
	}

	appID := req.AppID
	if appID == "" {
		appID = prior.appID
	}
	if appID == "" {
		return InstallResult{}, fmt.Errorf("iis install: appid required (no prior binding at %s to inherit from)", req.IPPort)
	}

	// 2. Import the renewed cert+key into the certificate store. Nothing
	// live is touched yet, so a failure here needs no rollback.
	thumbprint, err := in.importCert(ctx, store, req.CertPEM, req.KeyPEM)
	if err != nil {
		// This is where a non-administrator actually fails: the store
		// write precedes any netsh call, so the operator never sees a
		// binding error at all.
		err = elevationHint("writing to the LocalMachine certificate store", err)
		return InstallResult{Outcome: OutcomeCertImportFailed, Detail: err.Error()},
			fmt.Errorf("iis install: cert import failed: %w", err)
	}

	// 3. Rebind: delete the old binding (if any) and add the new one.
	// setBinding restores the prior binding itself if the add half fails, so
	// the site is never left with no binding at all.
	if touched, err := in.setBinding(ctx, req.IPPort, thumbprint, appID, store, prior); err != nil {
		err = elevationHint("changing the HTTP.sys SSL binding", err)
		// RolledBack only when there was something to roll back. Claiming
		// it on an untouched host is the same lie as a phantom restore
		// failure, just in the reassuring direction.
		return InstallResult{Installed: true, RolledBack: touched && prior.existed, Outcome: OutcomeBindingFailed, Detail: err.Error()},
			fmt.Errorf("iis install: binding failed: %w", err)
	}

	// 4. Reload so IIS/HTTP.sys present the new binding on new handshakes.
	if _, err := in.exec.Run(ctx, "iisreset", "/noforce"); err != nil {
		rolledBack, detail := in.rollback(ctx, req.IPPort, store, prior, err.Error())
		return InstallResult{Installed: true, RolledBack: rolledBack, Outcome: OutcomeReloadFailed, Detail: detail},
			fmt.Errorf("iis install: reload failed: %w", err)
	}

	// 5. Verify-after-install (optional): confirm the renewed cert is
	// actually being served before calling the renewal done.
	if req.VerifyHostPort != "" && req.ExpectedFingerprint != "" {
		served, err := in.verify(ctx, req.VerifyHostPort)
		if err != nil {
			rolledBack, detail := in.rollback(ctx, req.IPPort, store, prior, err.Error())
			return InstallResult{Installed: true, Reloaded: true, RolledBack: rolledBack, Outcome: OutcomeVerifyFailed, Detail: detail},
				fmt.Errorf("iis install: verify failed: %w", err)
		}
		if normalizeFingerprint(served) != normalizeFingerprint(req.ExpectedFingerprint) {
			rolledBack, detail := in.rollback(ctx, req.IPPort, store, prior,
				"served fingerprint does not match renewed cert")
			return InstallResult{
					Installed: true, Reloaded: true, RolledBack: rolledBack,
					ServedFingerprint: served, Outcome: OutcomeVerifyFailed,
					Detail: detail,
				},
				fmt.Errorf("iis install: verify mismatch (served %s, want %s), rolled back",
					served, req.ExpectedFingerprint)
		}
		return InstallResult{
			Installed: true, Reloaded: true, Verified: true,
			ServedFingerprint: served, Outcome: OutcomeInstalledVerified,
		}, nil
	}

	return InstallResult{Installed: true, Reloaded: true, Outcome: OutcomeInstalled}, nil
}

// showBinding reads the current HTTP.sys SSL binding for ipPort via
// `netsh http show sslcert`. A non-zero exit from netsh itself means no
// binding exists — benign, "nothing to restore", mirroring
// Installer.snapshot's tolerance of a missing file. A transport/auth
// failure, where the command never ran, is returned instead: masking it
// as "no binding" sent operators chasing a missing appid.
func (in *IISInstaller) showBinding(ctx context.Context, ipPort string) (sslBinding, error) {
	out, err := in.exec.Run(ctx, "netsh", "http", "show", "sslcert", "ipport="+ipPort)
	if err != nil {
		// netsh exits non-zero when no binding exists — benign, return
		// empty. But a transport/auth failure (the command never ran, e.g.
		// a WinRM 401) must NOT be masked as "no binding": that sent
		// operators chasing a missing appid when the real problem was that
		// discovery could not authenticate to the host at all.
		var exitErr *WinRMExitError
		if errors.As(err, &exitErr) {
			return sslBinding{}, nil
		}
		return sslBinding{}, fmt.Errorf("query existing binding at %s: %w", ipPort, err)
	}
	var b sslBinding
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		key, val, ok := splitBindingLine(scanner.Text())
		if !ok {
			continue
		}
		switch {
		case strings.EqualFold(key, "Certificate Hash"):
			b.certHash = val
		case strings.EqualFold(key, "Application ID"):
			b.appID = val
		case strings.EqualFold(key, "Certificate Store Name"):
			b.storeName = val
		}
	}
	b.existed = b.certHash != "" && b.appID != ""
	if err := validatePriorBinding(b); err != nil {
		return sslBinding{}, fmt.Errorf("existing binding at %s: %w", ipPort, err)
	}
	return b, nil
}

// validatePriorBinding pins the values read back from the host to the shapes
// netsh prints, because they are reused as netsh arguments (the inherited
// appid, and the restore on rollback) and must meet the same bar as
// validateIISRequestFields. Checked before anything on the host is changed.
func validatePriorBinding(b sslBinding) error {
	if b.certHash != "" && !iisCertHashPattern.MatchString(b.certHash) {
		return fmt.Errorf("certificate hash is not hex")
	}
	if b.appID != "" && !iisAppIDPattern.MatchString(b.appID) {
		return fmt.Errorf("application id is not a GUID")
	}
	if b.storeName != "" && !iisStoreNamePattern.MatchString(b.storeName) {
		return fmt.Errorf("certificate store name is not alphanumeric")
	}
	return nil
}

// splitBindingLine splits a "Label    : value" line from netsh's output.
// Only the first colon is treated as the separator so values that contain
// colons themselves (e.g. an "IP:port" value like "0.0.0.0:443") don't
// confuse the label; callers only look up labels that never contain one.
func splitBindingLine(line string) (key, val string, ok bool) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	val = strings.TrimSpace(line[idx+1:])
	if key == "" || val == "" {
		return "", "", false
	}
	return key, val, true
}

// elevationRequired reports whether err is Windows saying the account
// AUTHENTICATED FINE but is not a local Administrator. That is a different
// operator action from a bad credential, and W18-10 exists because the two
// were indistinguishable.
//
// Matching is on the NUMERIC Win32 code, never the English sentence. netsh
// prints "SSL Certificate add failed, Error: 5" and certutil
// "0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED)", but the accompanying prose
// ("The requested operation requires elevation (Run as administrator)") is
// LOCALIZED — on a German or Japanese Windows Server it is translated, and a
// prose-keyed detector would silently stop working in exactly the estates we
// most want it to work in.
//
// This only ever decorates an error message; no control flow depends on it,
// so a false positive costs a misleading hint and never a wrong action.
func elevationRequired(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, code := range []string{"Error: 5", "0x80070005", "WIN32: 5"} {
		if strings.Contains(s, code) {
			return true
		}
	}
	return false
}

// elevationHint appends the operator-facing explanation to a privileged-op
// failure. The read/write asymmetry it names is REAL and was captured on the
// live W18 host: a non-administrator can enumerate Cert:\LocalMachine\My and
// run `netsh http show sslcert` successfully, and only the WRITES fail. So
// the same credential that cannot install can still discover, and telling an
// operator to "check the password" would send them after a password that is
// already correct.
func elevationHint(op string, err error) error {
	if !elevationRequired(err) {
		return err
	}
	return fmt.Errorf("%w (the credential authenticated, but the account is not a local Administrator: %s requires elevation. "+
		"Note WinRM DISCOVERY of this host does NOT need elevation — reads succeed for a standard user — so this credential can still be used for discovery_mode=winrm)", err, op)
}

// setBinding deletes the current sslcert binding at ipPort (if prior.existed)
// and adds one pointing at the renewed cert. If the add fails after the
// delete succeeded, it immediately restores the prior binding so the
// endpoint is never left without any SSL binding at all.
// It reports whether the live binding was actually MODIFIED, so callers do
// not claim a rollback that never had anything to roll back.
func (in *IISInstaller) setBinding(ctx context.Context, ipPort, certHash, appID, store string, prior sslBinding) (touched bool, err error) {
	deleted := false
	if prior.existed {
		// netsh cannot replace a binding in place, so the old one goes
		// first. W18-10: the delete's own result is now KEPT rather than
		// discarded, because whether it succeeded is the only reliable
		// way to know if the host was modified at all.
		if _, derr := in.exec.Run(ctx, "netsh", "http", "delete", "sslcert", "ipport="+ipPort); derr == nil {
			deleted = true
		}
	}
	_, err = in.exec.Run(ctx, "netsh", "http", "add", "sslcert",
		"ipport="+ipPort, "certhash="+certHash, "appid="+appID, "certstorename="+store)
	if err == nil {
		return true, nil
	}
	if !deleted {
		// Nothing was removed, so the prior binding is STILL SERVING and
		// there is nothing to restore. Attempting a restore here and
		// reporting its failure told the operator "restore prior sslcert
		// binding failed" — which by restorePriorBinding's own contract
		// means the host is serving nothing. It inverted the truth in the
		// most alarming possible direction. Observed for real with a
		// non-administrator account, where delete and add BOTH fail with
		// Error: 5 before anything is modified.
		return false, err
	}
	if rerr := in.restorePriorBinding(ctx, ipPort, store, prior); rerr != nil {
		return true, rerr
	}
	return true, err
}

// restorePriorBinding deletes whatever is currently bound at ipPort and, if
// prior.existed, re-adds exactly what was captured before this install
// started. Best-effort: errors are not surfaced, matching Installer.rollback's
// "restore what existed before" contract for file-based targets.
// It returns an error when the prior state could NOT be put back. Callers
// must not report RolledBack on that error: the binding is then neither
// the new certificate nor the old one, and saying "rolled back" would tell
// the operator the host is fine when it is serving nothing. Same honesty
// rule the F5 and K8s pushers follow.
func (in *IISInstaller) restorePriorBinding(ctx context.Context, ipPort, store string, prior sslBinding) error {
	// Deleting a binding that is not there is not a failure, so this one
	// stays best-effort — but it is the ADD below that decides whether the
	// host is back where it started.
	_, _ = in.exec.Run(ctx, "netsh", "http", "delete", "sslcert", "ipport="+ipPort) //nolint:errcheck // absent binding is not an error
	if !prior.existed {
		return nil
	}
	priorStore := prior.storeName
	if priorStore == "" {
		priorStore = store
	}
	if _, err := in.exec.Run(ctx, "netsh", "http", "add", "sslcert",
		"ipport="+ipPort, "certhash="+prior.certHash, "appid="+prior.appID, "certstorename="+priorStore); err != nil {
		return fmt.Errorf("restore prior sslcert binding on %s: %w", ipPort, err)
	}
	return nil
}

// importCert builds a password-protected PFX from the renewed cert+key ON
// THE HUB, stages only that one file in a fresh ACL-locked directory,
// imports it with certutil, and returns the SHA-1 thumbprint netsh needs
// for certhash=. It used to stage the plaintext key DER and merge the two
// on the host with a PowerShell script that called ImportPkcs8PrivateKey --
// a .NET Core API that Windows PowerShell 5.1 (every powershell.exe) does
// not have, so it could never have worked; captured live 2026-09-10. The
// pure-Go encoder also means the private key never touches the host's
// disk unencrypted. LegacyDES (3DES + SHA-1 MAC) is what every certutil
// since Server 2008 accepts, including FIPS-mode hosts that reject RC2.
// The staging directory is removed immediately after import; the temp
// password never leaves this function.
func (in *IISInstaller) importCert(ctx context.Context, store string, certPEM, keyPEM []byte) (thumbprint string, err error) {
	certDER, err := certDERFromPEM(certPEM)
	if err != nil {
		return "", err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("iis install: parse certificate: %w", err)
	}
	keyDER, _, err := normalizeKeyToPKCS8(keyPEM)
	if err != nil {
		return "", err
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return "", fmt.Errorf("iis install: parse private key: %w", err)
	}
	thumbprint = thumbprintSHA1(certDER)

	token, err := randomToken(8)
	if err != nil {
		return "", fmt.Errorf("generate staging token: %w", err)
	}
	password, err := randomToken(16)
	if err != nil {
		return "", fmt.Errorf("generate pfx password: %w", err)
	}
	pfxBytes, err := pkcs12.LegacyDES.Encode(privateKey, cert, nil, password)
	if err != nil {
		return "", fmt.Errorf("build pfx: %w", err)
	}

	stageDir := winJoin(in.tempDir, "kk-iis-stage-"+token)
	if err := in.createLockedStageDir(ctx, stageDir); err != nil {
		return "", err
	}
	defer func() { _, _ = in.exec.Run(ctx, "cmd", "/C", "rmdir", "/S", "/Q", stageDir) }()

	pfxPath := winJoin(stageDir, "bundle.pfx")
	if err := in.exec.WriteFile(pfxPath, pfxBytes, 0o600); err != nil {
		return "", fmt.Errorf("stage pfx: %w", err)
	}

	if _, err := in.exec.Run(ctx, "certutil", "-f", "-p", password, "-importpfx", store, pfxPath); err != nil {
		return "", fmt.Errorf("certutil importpfx: %w", err)
	}

	return thumbprint, nil
}

// createLockedStageDir creates a fresh, empty directory at dir and strips
// its inherited permissions, granting access only to SYSTEM and
// Administrators via icacls. This runs BEFORE any key bytes are written
// (importCert only calls WriteFile after this returns successfully), so the
// key is never briefly readable under whatever ACL dir's parent happened to
// inherit. On any failure, including the icacls step, the (possibly
// unlocked, but still empty) directory is removed rather than left behind.
func (in *IISInstaller) createLockedStageDir(ctx context.Context, dir string) error {
	if _, err := in.exec.Run(ctx, "cmd", "/C", "mkdir", dir); err != nil {
		return fmt.Errorf("create stage dir: %w", err)
	}
	if _, err := in.exec.Run(ctx, "icacls", dir, "/inheritance:r",
		"/grant:r", sidLocalSystem+":(OI)(CI)F", sidAdministrators+":(OI)(CI)F"); err != nil {
		// The directory exists but is NOT locked down. If cleanup also
		// fails, say so — an unrestricted staging directory is exactly what
		// the ACL step was protecting against, and silence would leave it
		// there unnoticed.
		if _, rmErr := in.exec.Run(ctx, "cmd", "/C", "rmdir", "/S", "/Q", dir); rmErr != nil {
			return fmt.Errorf("restrict stage dir acl: %w (and the unrestricted directory %s could not be removed: %v)", err, dir, rmErr)
		}
		return fmt.Errorf("restrict stage dir acl: %w", err)
	}
	return nil
}

// certDERFromPEM extracts the raw DER bytes of a "CERTIFICATE" PEM block.
func certDERFromPEM(certPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("iis install: no CERTIFICATE PEM block found")
	}
	return block.Bytes, nil
}

// normalizeKeyToPKCS8 decodes a private key PEM block of any of the formats
// this codebase emits (SEC1 "EC PRIVATE KEY" from agentclient's ACME
// renewer, PKCS#1 "RSA PRIVATE KEY", or generic PKCS#8 "PRIVATE KEY") and
// re-marshals it as PKCS#8 DER, the one format both RSA.ImportPkcs8PrivateKey
// and ECDsa.ImportPkcs8PrivateKey accept. It also reports the key's
// algorithm so the PowerShell script knows which .NET type to construct.
func normalizeKeyToPKCS8(keyPEM []byte) (der []byte, alg string, err error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, "", fmt.Errorf("iis install: no PEM block found in key")
	}

	var signer crypto.Signer
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("iis install: parse EC key: %w", err)
		}
		signer, alg = key, "ECDSA"
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("iis install: parse RSA key: %w", err)
		}
		signer, alg = key, "RSA"
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("iis install: parse PKCS8 key: %w", err)
		}
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			signer, alg = k, "ECDSA"
		case *rsa.PrivateKey:
			signer, alg = k, "RSA"
		default:
			return nil, "", fmt.Errorf("iis install: unsupported PKCS8 key type %T", key)
		}
	default:
		return nil, "", fmt.Errorf("iis install: unsupported key PEM block type %q", block.Type)
	}

	der, err = x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, "", fmt.Errorf("iis install: marshal pkcs8: %w", err)
	}
	return der, alg, nil
}

// thumbprintSHA1 returns the uppercase-hex SHA-1 of a DER-encoded
// certificate — the same value Windows exposes as a cert's "Thumbprint" and
// the form netsh's certhash= parameter expects.
func thumbprintSHA1(certDER []byte) string {
	sum := sha1.Sum(certDER)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// randomToken returns n random bytes as hex, used both for unpredictable
// staging filenames and the transient PFX password.
func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// winJoin builds a REMOTE Windows path.
//
// path/filepath uses the HOST's separator, so joining on a Linux hub
// produced "C:\\Windows\\Temp/kk-iis-stage-x" — mixed separators for a
// path that certutil and `cmd /C rmdir` have to parse. Now that this
// installer drives Windows remotely over WinRM rather than only running
// on Windows, the separator is a property of the TARGET, not of us.
func winJoin(parts ...string) string {
	cleaned := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimRight(p, `\/`)
		if p != "" {
			cleaned = append(cleaned, p)
		}
	}
	return strings.Join(cleaned, `\`)
}

// rollback puts the prior binding back and reports whether it actually
// succeeded, along with the detail to surface.
//
// It exists so no caller can report RolledBack: true after a restore that
// failed. A host whose binding is neither the new certificate nor the old
// one is serving nothing, and telling the operator it was rolled back
// sends them to look somewhere else. Same rule as the F5 and K8s pushers.
func (in *IISInstaller) rollback(ctx context.Context, ipPort, store string, prior sslBinding, detail string) (bool, string) {
	if err := in.restorePriorBinding(ctx, ipPort, store, prior); err != nil {
		return false, detail + "; ROLLBACK FAILED (the binding may serve neither certificate): " + err.Error()
	}
	// Get the restored binding live too, mirroring installer.go's
	// reload-after-rollback for nginx/apache. Best-effort by design: the
	// binding is already correct on disk, so a failed reload only delays
	// it taking effect — it does not change what was restored.
	_, _ = in.exec.Run(ctx, "iisreset", "/noforce") //nolint:errcheck // see above: outcome does not depend on it
	return true, detail
}

var (
	iisAppIDPattern     = regexp.MustCompile(`^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$`)
	iisStoreNamePattern = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
	iisCertHashPattern  = regexp.MustCompile(`^[0-9A-Fa-f]{40,64}$`)
)

// validateIISRequestFields pins the request fields that become netsh and
// certutil arguments to their documented shapes. They come from the target's
// credential payload and travel to the host as a cmd.exe command line over
// WinRM, where a value like "0.0.0.0:443&calc" would run a second command.
func validateIISRequestFields(req IISInstallRequest) error {
	host, port, err := net.SplitHostPort(req.IPPort)
	if err != nil || net.ParseIP(host) == nil {
		return fmt.Errorf("iis install: ipport %q must be IP:port", req.IPPort)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("iis install: ipport %q has an invalid port", req.IPPort)
	}
	if req.AppID != "" && !iisAppIDPattern.MatchString(req.AppID) {
		return fmt.Errorf("iis install: appid must be a GUID")
	}
	if req.StoreName != "" && !iisStoreNamePattern.MatchString(req.StoreName) {
		return fmt.Errorf("iis install: store name must be alphanumeric")
	}
	return nil
}
