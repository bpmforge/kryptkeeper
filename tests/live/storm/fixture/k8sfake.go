// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Fake Kubernetes Secrets API plus per-target TLS verify listeners for the
// W27-34 storm test. TEST-ONLY: it speaks just the calls
// internal/agentinstall/k8s.go makes (GET, POST, PUT, DELETE on Secrets) and
// serves, on port base+i, whatever certificate the hub last stored in secret
// "s<i>", which is exactly what the hub's verify-after-install dial checks.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type k8sFake struct {
	token string

	mu      sync.Mutex
	secrets map[string]map[string]any // "ns/name" -> Secret object
	certs   map[string]*tls.Certificate
	version int
}

func newK8sFake(token string) *k8sFake {
	return &k8sFake{token: token, secrets: map[string]map[string]any{}, certs: map[string]*tls.Certificate{}}
}

func (k *k8sFake) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+k.token {
			status(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		// /api/v1/namespaces/<ns>/secrets[/<name>]
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 5 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "namespaces" || parts[4] != "secrets" {
			status(w, http.StatusNotFound, "NotFound")
			return
		}
		ns, name := parts[3], ""
		if len(parts) == 6 {
			name = parts[5]
		}
		switch {
		case r.Method == http.MethodPost && name == "":
			obj, ok := readSecret(w, r)
			if !ok {
				return
			}
			n, _ := obj["metadata"].(map[string]any)["name"].(string)
			if n == "" {
				status(w, http.StatusBadRequest, "BadRequest")
				return
			}
			k.mu.Lock()
			if _, exists := k.secrets[ns+"/"+n]; exists {
				k.mu.Unlock()
				status(w, http.StatusConflict, "AlreadyExists")
				return
			}
			k.storeLocked(ns, n, obj)
			k.mu.Unlock()
			writeObj(w, http.StatusCreated, obj)
		case r.Method == http.MethodPut && name != "":
			obj, ok := readSecret(w, r)
			if !ok {
				return
			}
			k.mu.Lock()
			if _, exists := k.secrets[ns+"/"+name]; !exists {
				k.mu.Unlock()
				status(w, http.StatusNotFound, "NotFound")
				return
			}
			k.storeLocked(ns, name, obj)
			k.mu.Unlock()
			writeObj(w, http.StatusOK, obj)
		case r.Method == http.MethodGet && name != "":
			k.mu.Lock()
			obj, ok := k.secrets[ns+"/"+name]
			k.mu.Unlock()
			if !ok {
				status(w, http.StatusNotFound, "NotFound")
				return
			}
			writeObj(w, http.StatusOK, obj)
		case r.Method == http.MethodDelete && name != "":
			k.mu.Lock()
			delete(k.secrets, ns+"/"+name)
			delete(k.certs, name)
			k.mu.Unlock()
			status(w, http.StatusOK, "Success")
		default:
			status(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
		}
	})
}

// storeLocked records the Secret and, when it holds a usable TLS pair, makes
// it the certificate the secret's verify listener serves.
func (k *k8sFake) storeLocked(ns, name string, obj map[string]any) {
	k.version++
	meta, _ := obj["metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
		obj["metadata"] = meta
	}
	meta["resourceVersion"] = strconv.Itoa(k.version)
	k.secrets[ns+"/"+name] = obj
	data, _ := obj["data"].(map[string]any)
	crt, _ := data["tls.crt"].(string)
	key, _ := data["tls.key"].(string)
	crtPEM, e1 := base64.StdEncoding.DecodeString(crt)
	keyPEM, e2 := base64.StdEncoding.DecodeString(key)
	if e1 != nil || e2 != nil {
		return
	}
	if pair, err := tls.X509KeyPair(crtPEM, keyPEM); err == nil {
		k.certs[name] = &pair
	}
}

func (k *k8sFake) servedCert(name string) *tls.Certificate {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.certs[name]
}

func readSecret(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var obj map[string]any
	if err != nil || json.Unmarshal(raw, &obj) != nil {
		status(w, http.StatusBadRequest, "BadRequest")
		return nil, false
	}
	return obj, true
}

func writeObj(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func status(w http.ResponseWriter, code int, reason string) {
	writeObj(w, code, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": reason, "code": code})
}

// placeholderCert is what a verify listener serves before the first push, so
// the hub's pre-push state is a real, different certificate.
func placeholderCert(cn string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// serveVerifyListeners opens count TLS listeners on basePort..basePort+count-1;
// listener i serves secret "s<i>". It returns the listeners so tests can close them.
func (k *k8sFake) serveVerifyListeners(host string, basePort, count int) ([]net.Listener, error) {
	placeholder, err := placeholderCert("unprovisioned")
	if err != nil {
		return nil, err
	}
	var lns []net.Listener
	for i := 0; i < count; i++ {
		secret := fmt.Sprintf("s%d", i)
		cfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				if c := k.servedCert(secret); c != nil {
					return c, nil
				}
				return placeholder, nil
			},
		}
		ln, err := tls.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(basePort+i)), cfg)
		if err != nil {
			for _, l := range lns {
				_ = l.Close()
			}
			return nil, err
		}
		lns = append(lns, ln)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					if c.SetDeadline(time.Now().Add(10*time.Second)) != nil {
						return
					}
					if c.(*tls.Conn).Handshake() != nil {
						return
					}
				}()
			}
		}()
	}
	return lns, nil
}
