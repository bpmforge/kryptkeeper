// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Local-login password verifier (A2A7-002 / A02-2). The operator's
// APP_AUTH_LOGIN_PASSWORD_HASH is now an Argon2id PHC string. Hashes made by
// the old scheme (hex HMAC-SHA256 keyed by the pepper, ~3M guesses/s/core)
// still verify, and the first successful login upgrades them in memory.
//
// The cost is the OWASP Password Storage Cheat Sheet's minimum Argon2id
// configuration (19 MiB, t=2, p=1), not keystore's 64 MiB/p=4: this endpoint
// is unauthenticated, so the cost an anonymous caller can force per request
// is capped further by loginKDFConcurrency in auth_login_state.go.
const (
	argon2idPHCPrefix = "$argon2id$"
	loginArgonTime    = 2
	loginArgonMemKiB  = 19 * 1024
	loginArgonThreads = 1
	loginArgonSaltLen = 16
	loginArgonKeyLen  = 32

	// Upper bounds on parameters read back from the stored string, so a
	// mistyped or hostile config value cannot make every login allocate
	// gigabytes.
	maxLoginArgonMemKiB  = 512 * 1024
	maxLoginArgonTime    = 10
	maxLoginArgonThreads = 16
)

type argon2idParams struct {
	memKiB  uint32
	time    uint32
	threads uint8
}

// loginPasswordPreimage applies the optional pepper as an HMAC pre-step, so a
// leaked hash alone is not enough to start an offline guess when the pepper
// lives elsewhere (it usually shares the hash's environment, so this is a
// bonus, not the defence: the work factor is).
func loginPasswordPreimage(password, pepper string) []byte {
	if pepper == "" {
		return []byte(password)
	}
	mac := hmac.New(sha256.New, []byte(pepper))
	_, _ = mac.Write([]byte(password))
	return mac.Sum(nil)
}

// HashLoginPassword returns the PHC-encoded Argon2id string an operator puts
// in APP_AUTH_LOGIN_PASSWORD_HASH.
func HashLoginPassword(password, pepper string) (string, error) {
	salt := make([]byte, loginArgonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}
	params := argon2idParams{memKiB: loginArgonMemKiB, time: loginArgonTime, threads: loginArgonThreads}
	key := argon2.IDKey(loginPasswordPreimage(password, pepper), salt, params.time, params.memKiB, params.threads, loginArgonKeyLen)
	return encodeArgon2idPHC(params, salt, key), nil
}

func encodeArgon2idPHC(p argon2idParams, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.memKiB, p.time, p.threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

func parseArgon2idPHC(encoded string) (argon2idParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, key
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return argon2idParams{}, nil, nil, fmt.Errorf("not an argon2id PHC string")
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return argon2idParams{}, nil, nil, fmt.Errorf("unsupported argon2 version")
	}
	var m, t, th uint64
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return argon2idParams{}, nil, nil, fmt.Errorf("bad argon2 parameter")
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return argon2idParams{}, nil, nil, fmt.Errorf("bad argon2 parameter")
		}
		switch k {
		case "m":
			m = n
		case "t":
			t = n
		case "p":
			th = n
		default:
			return argon2idParams{}, nil, nil, fmt.Errorf("unknown argon2 parameter")
		}
	}
	if m < 8 || m > maxLoginArgonMemKiB || t < 1 || t > maxLoginArgonTime || th < 1 || th > maxLoginArgonThreads {
		return argon2idParams{}, nil, nil, fmt.Errorf("argon2 parameters out of range")
	}
	p := argon2idParams{memKiB: uint32(m), time: uint32(t), threads: uint8(th)}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return argon2idParams{}, nil, nil, fmt.Errorf("bad argon2 salt")
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return argon2idParams{}, nil, nil, fmt.Errorf("bad argon2 key")
	}
	return p, salt, key, nil
}

func isArgon2idHash(stored string) bool {
	return strings.HasPrefix(strings.TrimSpace(stored), argon2idPHCPrefix)
}

// verifyLoginPassword checks password against stored in constant time. legacy
// is true when stored is the old hex HMAC-SHA256 form, which the caller should
// replace with HashLoginPassword's output after a successful match. A stored
// Argon2id string that fails to parse never matches.
func verifyLoginPassword(password, pepper, stored string) (ok bool, legacy bool) {
	stored = strings.TrimSpace(stored)
	if !isArgon2idHash(stored) {
		computed := apiKeyVerifier(password, pepper)
		return subtle.ConstantTimeCompare([]byte(computed), []byte(stored)) == 1, true
	}
	params, salt, want, err := parseArgon2idPHC(stored)
	if err != nil {
		return false, false
	}
	got := argon2.IDKey(loginPasswordPreimage(password, pepper), salt, params.time, params.memKiB, params.threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, false
}
