// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9111", "listen address")
	flag.Parse()
	log.Fatal(http.ListenAndServe(*addr, Handler()))
}
