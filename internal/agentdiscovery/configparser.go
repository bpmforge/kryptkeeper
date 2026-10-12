// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"kryptkeeper/internal/agentclient"
)

// DefaultConfigPaths are common locations for web server and service configs.
var DefaultConfigPaths = []string{
	"/etc/nginx",
	"/etc/apache2",
	"/etc/httpd",
	"/etc/ssl",
	"/usr/local/etc/nginx",
	"/usr/local/etc/apache2",
}

var (
	// nginx: ssl_certificate /path/to/cert.pem;  (the trailing \s avoids matching ssl_certificate_key)
	reNginxCert = regexp.MustCompile(`(?i)^\s*ssl_certificate\s+([^;#\s]+)`)
	// nginx: ssl_certificate_key /path/to/key.pem;
	reNginxKey = regexp.MustCompile(`(?i)^\s*ssl_certificate_key\s+([^;#\s]+)`)
	// nginx: server_name a.example.com b.example.com;
	reNginxServerName = regexp.MustCompile(`(?i)^\s*server_name\s+([^;#]+)`)
	// nginx: listen 443 ssl;  /  listen 0.0.0.0:8443 ssl;
	reNginxListen = regexp.MustCompile(`(?i)^\s*listen\s+(\S+)`)
	// Apache: SSLCertificateFile /path/to/cert.pem
	reApacheCert = regexp.MustCompile(`(?i)^\s*SSLCertificateFile\s+(\S+)`)
	// Apache: SSLCertificateKeyFile /path/to/key.pem
	reApacheKey = regexp.MustCompile(`(?i)^\s*SSLCertificateKeyFile\s+(\S+)`)
	// Apache: ServerName host.example.com
	reApacheServerName = regexp.MustCompile(`(?i)^\s*ServerName\s+(\S+)`)
	// Apache: <VirtualHost *:443>
	reApacheVHost = regexp.MustCompile(`(?i)<VirtualHost[^>]*:(\d+)`)
	// nginx: server {  (start of a server block)
	reNginxServer = regexp.MustCompile(`^\s*server\s*\{`)
	// HAProxy: crt /path/to/cert.pem (bind line)
	reHAProxyCert = regexp.MustCompile(`(?i)\bcrt\s+(\S+\.pem)`)
)

// WalkConfigCerts scans web server config files in configRoots for certificate
// path references, then parses each referenced cert file.
// Errors opening individual files are silently skipped.
func WalkConfigCerts(configRoots []string) ([]agentclient.DiscoveredCert, error) {
	certPaths := findCertPathsInConfigs(configRoots)

	seen := make(map[string]struct{})
	var out []agentclient.DiscoveredCert

	for _, p := range certPaths {
		certs, err := certsFromFile(p)
		if err != nil {
			continue
		}
		for _, c := range certs {
			if _, dup := seen[c.Fingerprint]; !dup {
				seen[c.Fingerprint] = struct{}{}
				out = append(out, c)
			}
		}
	}
	return out, nil
}

// FindCertPathsInConfigs returns the set of certificate file paths referenced
// in web server config files under the given roots.
func FindCertPathsInConfigs(configRoots []string) []string {
	return findCertPathsInConfigs(configRoots)
}

func findCertPathsInConfigs(configRoots []string) []string {
	seen := make(map[string]struct{})
	var out []string

	for _, root := range configRoots {
		info, err := os.Stat(root)
		if err != nil {
			continue
		}

		if !info.IsDir() {
			for _, p := range extractCertPathsFromFile(root) {
				if _, dup := seen[p]; !dup {
					seen[p] = struct{}{}
					out = append(out, p)
				}
			}
			continue
		}

		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error { // partial results are used as-is; walk errors are non-fatal here
			if err != nil || d.IsDir() {
				return nil
			}
			if !isConfigFile(path) {
				return nil
			}
			for _, p := range extractCertPathsFromFile(path) {
				if _, dup := seen[p]; !dup {
					seen[p] = struct{}{}
					out = append(out, p)
				}
			}
			return nil
		})
	}
	return out
}

// isConfigFile returns true for file extensions common to web server configs.
func isConfigFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".conf", ".cfg", ".vhost", ".site":
		return true
	}
	// Also match bare filenames common in nginx/apache (e.g. "default", "nginx.conf")
	base := filepath.Base(path)
	return strings.HasSuffix(base, ".conf") || strings.Contains(base, "nginx") || strings.Contains(base, "apache")
}

// extractCertPathsFromFile returns all certificate file paths referenced in a config file.
func extractCertPathsFromFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		for _, re := range []*regexp.Regexp{reNginxCert, reApacheCert, reHAProxyCert} {
			if m := re.FindStringSubmatch(line); len(m) > 1 {
				p := strings.Trim(m[1], `"'`)
				if filepath.IsAbs(p) {
					out = append(out, p)
				}
			}
		}
	}
	return out
}

// WalkEndpoints scans web server configs under configRoots for installable TLS
// endpoints, pairing each cert with its key, server name, and listen port
// within a server / VirtualHost block. This is the v1.3 install contract — it
// tells the Hub where a renewed cert must be written and where to verify it.
func WalkEndpoints(configRoots []string) []agentclient.Endpoint {
	seen := make(map[string]struct{})
	var out []agentclient.Endpoint
	for _, cfg := range collectConfigFiles(configRoots) {
		for _, ep := range extractEndpointsFromFile(cfg) {
			key := string(ep.ServerType) + "|" + ep.CertPath + "|" + ep.ConfigPath
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, ep)
		}
	}
	return out
}

// collectConfigFiles returns the set of config file paths under the given roots.
func collectConfigFiles(configRoots []string) []string {
	var out []string
	for _, root := range configRoots {
		info, err := os.Stat(root)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if isConfigFile(root) {
				out = append(out, root)
			}
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error { // partial results are used as-is; walk errors are non-fatal here
			if err != nil || d.IsDir() {
				return nil
			}
			if isConfigFile(path) {
				out = append(out, path)
			}
			return nil
		})
	}
	return out
}

// extractEndpointsFromFile parses a single config file into Endpoint records,
// tracking nginx `server { }` blocks (via brace depth) and Apache
// `<VirtualHost>` blocks. One endpoint is emitted per block that has a cert.
func extractEndpointsFromFile(path string) []agentclient.Endpoint {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []agentclient.Endpoint
	var cur agentclient.Endpoint
	have := false // currently inside a block we're collecting
	apache := false
	depth := 0 // nginx brace depth relative to the open server block

	flush := func() {
		if have && cur.CertPath != "" {
			cur.ConfigPath = path
			out = append(out, cur)
		}
		cur = agentclient.Endpoint{}
		have = false
		apache = false
		depth = 0
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()

		// Apache VirtualHost block.
		if m := reApacheVHost.FindStringSubmatch(line); m != nil {
			flush()
			have, apache = true, true
			cur = agentclient.Endpoint{ServerType: agentclient.ServerApache}
			if p, perr := strconv.Atoi(m[1]); perr == nil {
				cur.ListenPort = p
			}
			continue
		}
		if apache && strings.Contains(strings.ToLower(line), "</virtualhost>") {
			flush()
			continue
		}

		// nginx server block.
		if reNginxServer.MatchString(line) {
			flush()
			have, apache = true, false
			cur = agentclient.Endpoint{ServerType: agentclient.ServerNginx}
			depth = 1
			continue
		}

		if have && !apache {
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth <= 0 {
				applyEndpointDirectives(&cur, line, apache)
				flush()
				continue
			}
		}

		if have {
			applyEndpointDirectives(&cur, line, apache)
		}
	}
	flush()
	return out
}

// applyEndpointDirectives updates ep with any cert/key/server-name/port
// directive found on the line, for the active server type.
func applyEndpointDirectives(ep *agentclient.Endpoint, line string, apache bool) {
	if apache {
		if m := reApacheCert.FindStringSubmatch(line); m != nil {
			ep.CertPath = strings.Trim(m[1], `"'`)
		}
		if m := reApacheKey.FindStringSubmatch(line); m != nil {
			ep.KeyPath = strings.Trim(m[1], `"'`)
		}
		if m := reApacheServerName.FindStringSubmatch(line); m != nil && ep.ServerName == "" {
			ep.ServerName = strings.Trim(m[1], `"'`)
		}
		return
	}
	if m := reNginxCert.FindStringSubmatch(line); m != nil {
		ep.CertPath = strings.Trim(m[1], `"'`)
	}
	if m := reNginxKey.FindStringSubmatch(line); m != nil {
		ep.KeyPath = strings.Trim(m[1], `"'`)
	}
	if m := reNginxServerName.FindStringSubmatch(line); m != nil && ep.ServerName == "" {
		ep.ServerName = firstToken(strings.Trim(strings.TrimSpace(m[1]), `"'`))
	}
	if m := reNginxListen.FindStringSubmatch(line); m != nil && ep.ListenPort == 0 {
		ep.ListenPort = parseListenPort(m[1])
	}
}

// firstToken returns the first whitespace-separated token of s.
func firstToken(s string) string {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

// parseListenPort extracts the port from an nginx listen value, e.g. "443",
// "0.0.0.0:8443", "[::]:443". Returns 0 if no numeric port is found.
func parseListenPort(v string) int {
	v = strings.Trim(v, `"'`)
	if i := strings.LastIndex(v, ":"); i >= 0 {
		v = v[i+1:]
	}
	// strip any trailing non-digits (e.g. "443;" shouldn't occur post-regex, but be safe)
	digits := strings.TrimFunc(v, func(r rune) bool { return r < '0' || r > '9' })
	if n, err := strconv.Atoi(digits); err == nil {
		return n
	}
	return 0
}
