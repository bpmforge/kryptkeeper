// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command kryptkeeper-audit-verify checks Kryptkeeper audit-log
// transparency material offline. It never touches the network: an
// auditor saves the API responses, pins the signing public key out of
// band, and runs this against the files.
//
// Exit codes: 0 verified, 1 verification failed, 2 usage or I/O error.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"kryptkeeper/internal/audittrust"
	"kryptkeeper/internal/logging"
)

func main() {
	logging.Setup(logging.ConfigFromEnv(os.Getenv))
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// usageError marks problems with arguments or files (exit 2), as opposed
// to a cryptographic failure (exit 1).
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: kryptkeeper-audit-verify record|pair [flags]")
		return 2
	}
	var err error
	switch args[0] {
	case "record":
		err = runRecord(args[1:], stdout, stderr)
	case "pair":
		err = runPair(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown subcommand %q (want record or pair)\n", args[0])
		return 2
	}
	var ue usageError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ue):
		fmt.Fprintln(stderr, "error:", ue.msg)
		return 2
	default:
		fmt.Fprintln(stdout, "FAIL:", err)
		return 1
	}
}

func runRecord(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("record", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pubArg := fs.String("pubkey", "", "pinned Ed25519 public key: base64 or @file (required)")
	cpPath := fs.String("checkpoint", "", "checkpoint response file")
	entryPath := fs.String("entry", "", "audit entry JSON file")
	index := fs.Int("index", -1, "leaf index of the entry")
	proofPath := fs.String("proof", "", "inclusion proof response file")
	if err := fs.Parse(args); err != nil {
		return usageError{err.Error()}
	}
	pub, err := loadPubKey(*pubArg)
	if err != nil {
		return err
	}
	if *cpPath == "" || *entryPath == "" || *proofPath == "" || *index < 0 {
		return usageError{"--checkpoint, --entry, --index and --proof are required"}
	}
	cp, err := loadCheckpoint(*cpPath)
	if err != nil {
		return err
	}
	entry, err := loadEnvelope(*entryPath)
	if err != nil {
		return err
	}
	proof, err := loadProof(*proofPath, "audit_path")
	if err != nil {
		return err
	}
	leaf, err := audittrust.CanonicalLeaf(entry)
	if err != nil {
		return usageError{err.Error()}
	}
	if err := audittrust.VerifyRecord(pub, cp, leaf, *index, proof); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "OK record %d is included in checkpoint of size %d\n", *index, cp.Size)
	return nil
}

func runPair(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pubArg := fs.String("pubkey", "", "pinned Ed25519 public key: base64 or @file (required)")
	oldPath := fs.String("old", "", "older checkpoint response file")
	newPath := fs.String("new", "", "newer checkpoint response file")
	proofPath := fs.String("proof", "", "consistency proof response file")
	if err := fs.Parse(args); err != nil {
		return usageError{err.Error()}
	}
	pub, err := loadPubKey(*pubArg)
	if err != nil {
		return err
	}
	if *oldPath == "" || *newPath == "" || *proofPath == "" {
		return usageError{"--old, --new and --proof are required"}
	}
	older, err := loadCheckpoint(*oldPath)
	if err != nil {
		return err
	}
	newer, err := loadCheckpoint(*newPath)
	if err != nil {
		return err
	}
	proof, err := loadProof(*proofPath, "proof")
	if err != nil {
		return err
	}
	if err := audittrust.VerifyPair(pub, older, newer, proof); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "OK checkpoint %d is a consistent prefix of checkpoint %d\n", older.Size, newer.Size)
	return nil
}

// loadPubKey takes the key the auditor pinned out of band. It is
// deliberately never read from the checkpoint file: a forger could
// self-sign and ship their own key alongside.
func loadPubKey(arg string) (ed25519.PublicKey, error) {
	if strings.TrimSpace(arg) == "" {
		return nil, usageError{"--pubkey is required (pin the key out of band)"}
	}
	val := arg
	if strings.HasPrefix(arg, "@") {
		raw, err := os.ReadFile(arg[1:])
		if err != nil {
			return nil, usageError{"read pubkey: " + err.Error()}
		}
		val = string(raw)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(val))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, usageError{fmt.Sprintf("--pubkey must be %d base64-encoded bytes", ed25519.PublicKeySize)}
	}
	return ed25519.PublicKey(raw), nil
}

// loadEnvelope reads a saved API response, unwrapping {"data":...} when
// present so both raw objects and enveloped responses are accepted.
func loadEnvelope(path string) (json.RawMessage, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, usageError{err.Error()}
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &env) == nil && len(env.Data) > 0 {
		return env.Data, nil
	}
	if !json.Valid(raw) {
		return nil, usageError{path + " is not valid JSON"}
	}
	return raw, nil
}

func loadCheckpoint(path string) (audittrust.SignedCheckpoint, error) {
	var cp audittrust.SignedCheckpoint
	raw, err := loadEnvelope(path)
	if err != nil {
		return cp, err
	}
	if err := json.Unmarshal(raw, &cp); err != nil {
		return cp, usageError{path + ": " + err.Error()}
	}
	return cp, nil
}

func loadProof(path, field string) ([][32]byte, error) {
	raw, err := loadEnvelope(path)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, usageError{path + ": " + err.Error()}
	}
	var b64 []string
	if err := json.Unmarshal(m[field], &b64); err != nil {
		return nil, usageError{fmt.Sprintf("%s: missing %q array", path, field)}
	}
	proof, err := audittrust.DecodeProof(b64)
	if err != nil {
		return nil, usageError{path + ": " + err.Error()}
	}
	return proof, nil
}
