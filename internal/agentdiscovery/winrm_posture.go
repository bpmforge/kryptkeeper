// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"crypto/sha1" // #nosec G505 -- Windows identifies certificates by SHA-1 thumbprint; this is a lookup key, not a security check
	"crypto/x509"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// W34-12: Windows install posture, the counterpart of the Linux posture pass.
// For every LocalMachine\My certificate that has a private key the host
// reports who may read the key file, which http.sys or IIS binding serves the
// certificate and under which identity the serving site runs. The key itself
// is never touched: the script only lists a key file's ACL, and it contains no
// call that opens the key or exports it (asserted by a test).
//
// Behaviour that cannot be proven without a Windows host is tagged
// "W34-20-verify" so the live run knows what to check.

// FileKindCNGKey marks a Windows private-key container file in discovered_files.
const FileKindCNGKey = "cng_key"

// Well-known principals whose read access to a key file is KEY_WORLD_READABLE.
var worldReadablePrincipals = []string{"everyone", "builtin\\users", "nt authority\\authenticated users", "users", "authenticated users"}

// Identities that are the Windows analogue of root for SERVICE_RUNS_AS_ROOT.
var privilegedWinAccounts = []string{"localsystem", "nt authority\\system", "system", "administrator", "builtin\\administrators"}

const (
	winKeyMarker    = "__KK_KEY__"
	winIISMarker    = "__KK_IIS__"
	winSvcMarker    = "__KK_SVC__"
	winDoneMarker   = "__KK_POSTURE_DONE__"
	winNetshBegin   = "__KK_NETSH_BEGIN__"
	winNetshEnd     = "__KK_NETSH_END__"
	iisAppID        = "{4dc3e181-e14b-4a21-b022-59fc669b0914}" // W34-20-verify: the Application ID IIS registers its https bindings under
	winRMHTTPSPort  = 5986                                     // W34-20-verify: a binding on this port is treated as the WinRM listener
	maxWinKeyRows   = 500
	maxWinPostureIn = 1 << 20
)

// winPostureScript lists, per machine certificate with a private key, the key
// file and the principals with read access, the http.sys bindings (raw netsh
// text, parsed in Go) and the IIS HTTPS bindings with their app-pool identity.
// It never opens, exports or copies a key.
const winPostureScript = `$ErrorActionPreference='SilentlyContinue';` +
	`Get-ChildItem Cert:\LocalMachine\My|Where-Object{$_.HasPrivateKey}|ForEach-Object{` +
	`$t=$_.Thumbprint;$u=$null;foreach($l in (certutil -v -store My $t)){if($l -match 'Unique container name:\s*(\S+)'){$u=$Matches[1];break}};` +
	`if($u){$f=Get-ChildItem "$env:ProgramData\Microsoft\Crypto" -Recurse -Filter $u -File|Select-Object -First 1;` +
	`if($f){$r=@();foreach($a in (Get-Acl $f.FullName).Access){if($a.AccessControlType -eq 'Allow' -and ([int]$a.FileSystemRights -band 0x120089) -ne 0){$r+=$a.IdentityReference.Value}};` +
	`Write-Output ("__KK_KEY__` + "`t" + `$t` + "`t" + `"+$f.FullName+"` + "`t" + `"+($r -join ';'))}}};` +
	`Write-Output '__KK_NETSH_BEGIN__';netsh http show sslcert;Write-Output '__KK_NETSH_END__';` +
	`if(Get-Module -ListAvailable WebAdministration){Import-Module WebAdministration;Get-Website|ForEach-Object{$s=$_;$p=Get-Item "IIS:\AppPools\$($s.applicationPool)";` +
	`$id=[string]$p.processModel.identityType;if($id -eq 'SpecificUser'){$id=$p.processModel.userName};` +
	`foreach($b in $s.bindings.Collection){if($b.protocol -eq 'https'){Write-Output ("__KK_IIS__` + "`t" + `$($s.name)` + "`t" + `$($b.bindingInformation)` + "`t" + `$($b.certificateHash)` + "`t" + `$($s.applicationPool)` + "`t" + `$id")}}}};` +
	`Get-NetTCPConnection -State Listen|Where-Object{$_.OwningProcess -ne 4}|ForEach-Object{$c=$_;$s=Get-CimInstance Win32_Service -Filter "ProcessId=$($c.OwningProcess)"|Select-Object -First 1;` +
	`if($s){Write-Output ("__KK_SVC__` + "`t" + `$($c.LocalPort)` + "`t" + `$($s.Name)` + "`t" + `$($s.StartName)")}};` +
	`Write-Output '__KK_POSTURE_DONE__'`

var reNetshLine = regexp.MustCompile(`^(IP:port|Hostname:port|Certificate Hash|Application ID)\s*:\s*(.*)$`)

// WinKeyACL is a key file and the principals allowed to read it.
type WinKeyACL struct {
	Thumbprint     string
	Path           string
	ReadPrincipals []string
}

// WinBinding is one http.sys certificate binding from netsh.
type WinBinding struct {
	IPPort     string
	Port       int
	Thumbprint string
	AppID      string
}

// WinIISBinding is an IIS HTTPS binding with the identity its app pool runs as.
type WinIISBinding struct {
	Site       string
	Binding    string
	Thumbprint string
	AppPool    string
	Identity   string
}

// WinListenerService is the service that owns a listening TCP port and the
// account it logs on as.
type WinListenerService struct {
	Port    int
	Service string
	Account string
}

// WinPosture is the parsed posture output.
type WinPosture struct {
	Keys     []WinKeyACL
	Bindings []WinBinding
	IIS      []WinIISBinding
	Services []WinListenerService
	// Complete is true when the script ran to its end marker, so an empty
	// result means "no keys" and not "the script died".
	Complete bool
}

// ParseWinPosture reads the posture script's output; lines it does not
// recognise are ignored, so host noise cannot fail a scan.
func ParseWinPosture(out string) WinPosture {
	var p WinPosture
	inNetsh := false
	var cur WinBinding
	flush := func() {
		if cur.Thumbprint != "" {
			p.Bindings = append(p.Bindings, cur)
		}
		cur = WinBinding{}
	}
	if len(out) > maxWinPostureIn {
		out = out[:maxWinPostureIn]
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		trim := strings.TrimSpace(line)
		switch {
		case trim == winDoneMarker:
			p.Complete = true
		case trim == winNetshBegin:
			inNetsh = true
		case trim == winNetshEnd:
			flush()
			inNetsh = false
		case inNetsh:
			m := reNetshLine.FindStringSubmatch(trim)
			if m == nil {
				continue
			}
			k, v := m[1], strings.TrimSpace(m[2])
			switch k {
			case "IP:port", "Hostname:port":
				flush()
				cur.IPPort = v
				if _, port, err := net.SplitHostPort(v); err == nil {
					cur.Port, _ = strconv.Atoi(port)
				}
			case "Certificate Hash":
				cur.Thumbprint = strings.ToUpper(v)
			case "Application ID":
				cur.AppID = strings.ToLower(v)
			}
		case strings.HasPrefix(line, winKeyMarker+"\t"):
			f := strings.Split(line, "\t")
			if len(f) >= 3 && len(p.Keys) < maxWinKeyRows {
				k := WinKeyACL{Thumbprint: strings.ToUpper(strings.TrimSpace(f[1])), Path: strings.TrimSpace(f[2])}
				if len(f) >= 4 {
					for _, pr := range strings.Split(f[3], ";") {
						if pr = strings.TrimSpace(pr); pr != "" {
							k.ReadPrincipals = append(k.ReadPrincipals, pr)
						}
					}
				}
				p.Keys = append(p.Keys, k)
			}
		case strings.HasPrefix(line, winSvcMarker+"\t"):
			f := strings.Split(line, "\t")
			if port, err := strconv.Atoi(strings.TrimSpace(f[1])); err == nil && len(f) >= 4 {
				p.Services = append(p.Services, WinListenerService{Port: port, Service: strings.TrimSpace(f[2]), Account: strings.TrimSpace(f[3])})
			}
		case strings.HasPrefix(line, winIISMarker+"\t"):
			f := strings.Split(line, "\t")
			if len(f) >= 6 {
				p.IIS = append(p.IIS, WinIISBinding{Site: f[1], Binding: f[2], Thumbprint: strings.ToUpper(strings.TrimSpace(f[3])),
					AppPool: f[4], Identity: strings.TrimSpace(f[5])})
			}
		}
	}
	flush()
	return p
}

// winThumbprint is the SHA-1 thumbprint Windows keys its stores by.
func winThumbprint(c *x509.Certificate) string {
	sum := sha1.Sum(c.Raw) // #nosec G401 -- identifier, see import
	return strings.ToUpper(fmt.Sprintf("%x", sum))
}

func containsFold(list []string, s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, x := range list {
		if s == x || strings.HasSuffix(s, "\\"+x) {
			return true
		}
	}
	return false
}

// WinBindingTech names the technology serving an http.sys binding.
func WinBindingTech(b WinBinding) string {
	switch {
	case b.AppID == iisAppID:
		return "iis"
	case b.Port == winRMHTTPSPort:
		return "winrm"
	case b.AppID != "":
		return "other:" + strings.Trim(b.AppID, "{}")
	}
	return "other"
}

// WindowsFileFacts maps the posture onto the same FileFact vocabulary the
// Linux pass uses. Each key file is one fact (kind cng_key) linked to the
// certificates whose thumbprint matches; the binding or IIS site supplies the
// service, and its identity decides SERVICE_RUNS_AS_ROOT. Nothing here has an
// owner uid: Windows ACLs have no uid, so UID/GID stay UnknownID.
func WindowsFileFacts(p WinPosture, thumbToFingerprint map[string]string) []FileFact {
	iisByThumb := map[string]WinIISBinding{}
	for _, b := range p.IIS {
		iisByThumb[b.Thumbprint] = b
	}
	bindByThumb := map[string]WinBinding{}
	for _, b := range p.Bindings {
		bindByThumb[b.Thumbprint] = b
	}
	svcByPort := map[int]WinListenerService{}
	for _, sv := range p.Services {
		svcByPort[sv.Port] = sv
	}
	var out []FileFact
	for _, k := range p.Keys {
		f := FileFact{Path: k.Path, Kind: FileKindCNGKey, UID: UnknownID, GID: UnknownID, ServiceUID: UnknownID,
			Statted: true, Posture: PostureStandard}
		if fp, ok := thumbToFingerprint[k.Thumbprint]; ok {
			f.CertFingerprints = []string{fp}
		}
		for _, pr := range k.ReadPrincipals {
			if containsFold(worldReadablePrincipals, pr) {
				f.Findings = append(f.Findings, FindingKeyWorldReadable+": "+pr+" can read the key file "+k.Path)
				break
			}
		}
		if iis, ok := iisByThumb[k.Thumbprint]; ok {
			f.ServiceTech, f.ServiceName = "iis", iis.AppPool
			// IIS is a Microsoft server: its own identity is not flagged here
			// (SERVICE_RUNS_AS_ROOT is for non-Microsoft application servers).
		} else if b, ok := bindByThumb[k.Thumbprint]; ok {
			f.ServiceTech = WinBindingTech(b)
			if sv, ok := svcByPort[b.Port]; ok {
				applyServiceIdentity(&f, sv.Service, f.ServiceTech, sv.Account)
			}
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// applyServiceIdentity raises SERVICE_RUNS_AS_ROOT for a non-Microsoft service
// that runs as LocalSystem or Administrator. The service is tied to a
// certificate through the listening port of its binding. W34-20-verify:
// http.sys owns the sockets of http.sys bindings (PID 4, skipped by the
// script), so on a real host this fires only for a service that listens on a
// bound port itself.
func applyServiceIdentity(f *FileFact, serviceName, tech, account string) {
	if tech == "iis" || tech == "winrm" || !containsFold(privilegedWinAccounts, account) {
		return
	}
	f.ServiceName, f.ServiceTech = serviceName, tech
	f.Findings = append(f.Findings, FindingServiceRunsAsRoot+": "+serviceName+" runs as "+account)
	f.Posture = PostureRootService
}
