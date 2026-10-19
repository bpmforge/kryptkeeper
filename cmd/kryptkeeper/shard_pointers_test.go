// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"math/big"
	"slices"
	"testing"

	"kryptkeeper/internal/crl"
)

func TestShardPointersReplaceOnlyDefaultURL(t *testing.T) {
	const pub = "http://crl.example"
	serial := new(big.Int).Lsh(big.NewInt(1), 127) // upper half -> shard 2 of 4
	want := crl.ShardURL(pub, "ca-1", 2)

	def := func(caID string) ([]string, []string) {
		return []string{pub + "/crl/" + caID + ".crl"}, []string{pub + "/ocsp"}
	}
	crlURLs, ocsp := shardPointers(def, pub, 4)("ca-1", serial)
	if !slices.Equal(crlURLs, []string{want}) || !slices.Equal(ocsp, []string{pub + "/ocsp"}) {
		t.Fatalf("default not replaced: %v %v", crlURLs, ocsp)
	}

	own := func(string) ([]string, []string) {
		return []string{"http://own.example/a.crl"}, []string{"http://own.example/ocsp"}
	}
	crlURLs, ocsp = shardPointers(own, pub, 4)("ca-1", serial)
	if !slices.Equal(crlURLs, []string{"http://own.example/a.crl"}) || !slices.Equal(ocsp, []string{"http://own.example/ocsp"}) {
		t.Fatalf("operator DPs touched: %v %v", crlURLs, ocsp)
	}
}
