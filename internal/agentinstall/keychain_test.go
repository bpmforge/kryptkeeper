// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

const testStage = "/tmp/kk-keychain.Ab12Cd34"

// macExecutor is a fake macOS target: it records every command and write,
// and answers mktemp/find-certificate like the real tools.
type macExecutor struct {
	files     map[string][]byte
	ran       []string
	listing   string           // find-certificate -Z output
	mktempOut string           // what mktemp prints
	fail      map[string]error // command prefix -> error
}

func newMacExecutor() *macExecutor {
	return &macExecutor{files: map[string][]byte{}, mktempOut: testStage + "\n", fail: map[string]error{}}
}

func (f *macExecutor) Exists(path string) bool { _, ok := f.files[path]; return ok }
func (f *macExecutor) ReadFile(path string) ([]byte, error) {
	return f.files[path], nil
}
func (f *macExecutor) WriteFile(path string, content []byte, _ os.FileMode) error {
	f.files[path] = append([]byte(nil), content...)
	f.ran = append(f.ran, "WRITE "+path)
	return nil
}
func (f *macExecutor) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.ran = append(f.ran, cmd)
	for prefix, err := range f.fail {
		if strings.HasPrefix(cmd, prefix) {
			return []byte("refused"), err
		}
	}
	switch {
	case strings.HasPrefix(cmd, "mktemp"):
		return []byte(f.mktempOut), nil
	case strings.Contains(cmd, "find-certificate"):
		return []byte(f.listing), nil
	}
	return nil, nil
}

func (f *macExecutor) index(prefix string) int {
	return slices.IndexFunc(f.ran, func(c string) bool { return strings.HasPrefix(c, prefix) })
}

// macIdentity is a root CA and a leaf it issued, with the leaf's key.
type macIdentity struct {
	root, leaf *x509.Certificate
	certPEM    []byte
	keyPEM     []byte
}

func newMacIdentity(t *testing.T) macIdentity {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "mac01.corp.example"},
		DNSNames: []string{"mac01.corp.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	return macIdentity{root: root, leaf: leaf, certPEM: certPEM, keyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
}

func listingFor(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return "keychain: \"/Library/Keychains/System.keychain\"\nversion: 512\nSHA-256 hash: " + strings.ToUpper(hex.EncodeToString(sum[:])) + "\nSHA-1 hash: 00\n"
}

// bundlePassword pulls the -P argument out of the recorded import command.
func bundlePassword(t *testing.T, f *macExecutor) string {
	t.Helper()
	i := f.index("sudo -n /usr/bin/security import")
	if i < 0 {
		t.Fatal("no import command")
	}
	fields := strings.Fields(f.ran[i])
	j := slices.Index(fields, "-P")
	if j < 0 || j+1 >= len(fields) {
		t.Fatal("import has no -P")
	}
	return fields[j+1]
}

func TestKeychainInstallPlacesAndTrusts(t *testing.T) {
	id := newMacIdentity(t)
	f := newMacExecutor()
	f.listing = listingFor(id.leaf)

	res, err := NewKeychainInstaller(f).Install(context.Background(), KeychainInstallRequest{CertPEM: id.certPEM, KeyPEM: id.keyPEM})
	if err != nil {
		t.Fatalf("install: %v (%+v)", err, res)
	}
	if !res.Installed || res.Outcome != OutcomeInstalled {
		t.Fatalf("result %+v", res)
	}

	// The private directory exists before any key bytes are written, and
	// the whole directory is removed last.
	mk, write := f.index("mktemp -d /tmp/kk-keychain."), f.index("WRITE "+testStage+"/identity.p12")
	if mk < 0 || write < 0 || mk > write {
		t.Fatalf("stage dir must be created before the bundle is written: %v", f.ran)
	}
	if f.ran[len(f.ran)-1] != "rm -rf "+testStage {
		t.Fatalf("last command %q, want the stage dir removed", f.ran[len(f.ran)-1])
	}

	imp := f.ran[f.index("sudo -n /usr/bin/security import")]
	for _, want := range []string{"-k /Library/Keychains/System.keychain", "-f pkcs12", " -x"} {
		if !strings.Contains(imp, want) {
			t.Fatalf("import %q lacks %q", imp, want)
		}
	}
	// The bundle holds exactly this leaf, its key and the chain.
	key, leaf, chain, err := pkcs12.DecodeChain(f.files[testStage+"/identity.p12"], bundlePassword(t, f))
	if err != nil {
		t.Fatalf("bundle does not decode: %v", err)
	}
	if !leaf.Equal(id.leaf) || len(chain) != 1 || !chain[0].Equal(id.root) {
		t.Fatal("bundle holds the wrong certificates")
	}
	if !key.(*ecdsa.PrivateKey).PublicKey.Equal(id.leaf.PublicKey) {
		t.Fatal("bundle key does not match the leaf")
	}

	trust := f.index("sudo -n /usr/bin/security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain " + testStage + "/root-0.pem")
	verify := f.index("/usr/bin/security verify-cert -c " + testStage + "/leaf.pem")
	if trust < 0 || verify < 0 || verify < trust {
		t.Fatalf("want root trusted then leaf verified: %v", f.ran)
	}
}

func TestKeychainImportFailureRedactsPasswordAndCleansUp(t *testing.T) {
	id := newMacIdentity(t)
	f := newMacExecutor()
	f.fail["sudo -n /usr/bin/security import"] = errors.New("placeholder")
	// Make the error quote the command line, as the SSH executor does.
	inst := NewKeychainInstaller(quotingExecutor{f})
	res, err := inst.Install(context.Background(), KeychainInstallRequest{CertPEM: id.certPEM, KeyPEM: id.keyPEM})
	if err == nil || res.Outcome != OutcomeCertImportFailed || res.Installed {
		t.Fatalf("got %+v, %v", res, err)
	}
	pw := bundlePassword(t, f)
	if strings.Contains(res.Detail, pw) || strings.Contains(err.Error(), pw) {
		t.Fatal("bundle password leaked into the error")
	}
	if f.ran[len(f.ran)-1] != "rm -rf "+testStage {
		t.Fatal("stage dir not removed after a failed import")
	}
	if f.index("sudo -n /usr/bin/security add-trusted-cert") >= 0 {
		t.Fatal("trust attempted after a failed import")
	}
}

// quotingExecutor makes Run errors quote the full command, like SSHExecutor.
type quotingExecutor struct{ *macExecutor }

func (q quotingExecutor) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := q.macExecutor.Run(ctx, name, args...)
	if err != nil {
		return out, errors.New("ssh executor: run \"" + name + " " + strings.Join(args, " ") + "\": exit 1")
	}
	return out, err
}

func TestKeychainTrustFailuresAreReported(t *testing.T) {
	for name, setup := range map[string]func(*macExecutor){
		"trust refused": func(f *macExecutor) {
			f.fail["sudo -n /usr/bin/security add-trusted-cert"] = errors.New("SecTrustSettingsSetTrustSettings: no user interaction was possible")
		},
		"leaf does not verify": func(f *macExecutor) {
			f.fail["/usr/bin/security verify-cert"] = errors.New("CSSMERR_TP_NOT_TRUSTED")
		},
	} {
		t.Run(name, func(t *testing.T) {
			id := newMacIdentity(t)
			f := newMacExecutor()
			f.listing = listingFor(id.leaf)
			setup(f)
			res, err := NewKeychainInstaller(f).Install(context.Background(), KeychainInstallRequest{CertPEM: id.certPEM, KeyPEM: id.keyPEM})
			if err == nil || !res.Installed || res.Outcome != OutcomeTrustFailed || res.Detail == "" {
				t.Fatalf("got %+v, %v", res, err)
			}
			if f.ran[len(f.ran)-1] != "rm -rf "+testStage {
				t.Fatal("stage dir not removed")
			}
		})
	}
}

func TestKeychainImportNotFoundAfterwards(t *testing.T) {
	id := newMacIdentity(t)
	f := newMacExecutor()
	f.listing = listingFor(id.root) // the leaf never showed up
	res, err := NewKeychainInstaller(f).Install(context.Background(), KeychainInstallRequest{CertPEM: id.certPEM, KeyPEM: id.keyPEM})
	if err == nil || res.Outcome != OutcomeCertImportFailed {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestKeychainRefusesChainWithoutRoot(t *testing.T) {
	id := newMacIdentity(t)
	f := newMacExecutor()
	f.listing = listingFor(id.leaf)
	leafOnly := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.leaf.Raw})
	res, err := NewKeychainInstaller(f).Install(context.Background(), KeychainInstallRequest{CertPEM: leafOnly, KeyPEM: id.keyPEM})
	if err == nil || res.Outcome != OutcomeTrustFailed {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestKeychainRejectsBadInputBeforeTouchingTheHost(t *testing.T) {
	id := newMacIdentity(t)
	other := newMacIdentity(t)
	for name, req := range map[string]KeychainInstallRequest{
		"key for a different leaf": {CertPEM: id.certPEM, KeyPEM: other.keyPEM},
		"no certificate":           {CertPEM: []byte("junk"), KeyPEM: id.keyPEM},
	} {
		f := newMacExecutor()
		if _, err := NewKeychainInstaller(f).Install(context.Background(), req); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if len(f.ran) != 0 {
			t.Errorf("%s: touched the host: %v", name, f.ran)
		}
	}
}

// A surprising mktemp answer must never become an rm -rf target.
func TestKeychainRefusesUnexpectedStageDir(t *testing.T) {
	id := newMacIdentity(t)
	for _, out := range []string{"/\n", "/tmp\n", "/tmp/kk-keychain.x/../../etc\n", ""} {
		f := newMacExecutor()
		f.mktempOut = out
		res, err := NewKeychainInstaller(f).Install(context.Background(), KeychainInstallRequest{CertPEM: id.certPEM, KeyPEM: id.keyPEM})
		if err == nil || res.Outcome != OutcomeWriteFailed {
			t.Fatalf("mktemp %q: got %+v, %v", out, res, err)
		}
		for _, c := range f.ran {
			if strings.HasPrefix(c, "rm ") || strings.HasPrefix(c, "WRITE") {
				t.Fatalf("mktemp %q: ran %q", out, c)
			}
		}
	}
}

func TestKeychainVerifyServedCertificate(t *testing.T) {
	id := newMacIdentity(t)
	sum := sha256.Sum256(id.leaf.Raw)
	fp := hex.EncodeToString(sum[:])
	for name, tc := range map[string]struct {
		served  string
		outcome string
		ok      bool
	}{
		"match":    {fp, OutcomeInstalledVerified, true},
		"mismatch": {strings.Repeat("0", 64), OutcomeVerifyFailed, false},
	} {
		f := newMacExecutor()
		f.listing = listingFor(id.leaf)
		inst := NewKeychainInstaller(f).WithVerifier(func(context.Context, string) (string, error) { return tc.served, nil })
		res, err := inst.Install(context.Background(), KeychainInstallRequest{CertPEM: id.certPEM, KeyPEM: id.keyPEM,
			VerifyHostPort: "mac01.corp.example:443", ExpectedFingerprint: fp})
		if (err == nil) != tc.ok || res.Outcome != tc.outcome {
			t.Errorf("%s: got %+v, %v", name, res, err)
		}
	}
}
