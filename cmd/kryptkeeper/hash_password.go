// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"kryptkeeper/internal/bootstrap"
)

// hashPasswordAndExit implements `kryptkeeper --hash-password` (A2A7-002): it
// reads the password from stdin (so it never lands in argv or shell history)
// and prints the Argon2id PHC string for APP_AUTH_LOGIN_PASSWORD_HASH. The
// optional APP_AUTH_LOGIN_PASSWORD_PEPPER is applied exactly as the login
// handler will apply it.
func hashPasswordAndExit() {
	hash, err := hashPasswordFrom(os.Stdin, os.Getenv("APP_AUTH_LOGIN_PASSWORD_PEPPER"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "--hash-password: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hash)
	os.Exit(0)
}

func hashPasswordFrom(in io.Reader, pepper string) (string, error) {
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read password: %w", err)
	}
	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		return "", fmt.Errorf("empty password on stdin")
	}
	return bootstrap.HashLoginPassword(password, strings.TrimSpace(pepper))
}
