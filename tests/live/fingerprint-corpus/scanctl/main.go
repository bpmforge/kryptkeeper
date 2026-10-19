// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// scanctl is the W34-20 corpus harness's scanner front end. It runs the real
// discovery scanner against named hosts on a container network, compares each
// endpoint's fingerprint with expected.json and prints the recall report; it
// also serves the two protocol stand-ins (Kubernetes API, WinRM/http.sys) the
// corpus cannot get as real products.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/discovery/scanner"
)

type expectation struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
	Tech string `json:"tech"`
	// Tier is the lowest scan that must find it: "full" or "deep".
	Tier string `json:"tier"`
	// TLSStack is the library behind an implicit-TLS listener, when the corpus
	// knows it; only checked in deep scans.
	TLSStack string `json:"tls_stack,omitempty"`
	Note     string `json:"note,omitempty"`
}

type expectedFile struct {
	Entries []expectation `json:"entries"`
}

type row struct {
	Name       string                       `json:"name"`
	Endpoint   string                       `json:"endpoint"`
	Expected   string                       `json:"expected"`
	Got        string                       `json:"got"`
	Confidence string                       `json:"confidence"`
	Platform   string                       `json:"platform"`
	TLSStack   string                       `json:"tls_stack"`
	Status     string                       `json:"status"` // correct | wrong | missed | skipped
	Evidence   []scanner.Evidence           `json:"evidence,omitempty"`
	Findings   []string                     `json:"findings,omitempty"`
	Stack      *scanner.TLSStackObservation `json:"tls_observation,omitempty"`
}

type report struct {
	Mode            string         `json:"mode"`
	Rows            []row          `json:"rows"`
	Unexpected      []row          `json:"unexpected"`
	Expected        int            `json:"expected"`
	Correct         int            `json:"correct"`
	Wrong           int            `json:"wrong"`
	Missed          int            `json:"missed"`
	Skipped         int            `json:"skipped"`
	Recall          float64        `json:"recall"`
	Precision       float64        `json:"precision"`
	Confidence      map[string]int `json:"confidence_distribution"`
	WrongHigh       int            `json:"wrong_high"`
	CorrectByConf   map[string]int `json:"correct_by_confidence"`
	WrongHighDetail []string       `json:"wrong_high_detail,omitempty"`
	StackExpected   int            `json:"stack_expected"`
	StackCorrect    int            `json:"stack_correct"`
	StackUnknown    int            `json:"stack_unknown"`
	StackWrong      int            `json:"stack_wrong"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: scanctl scan|standin ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "standin":
		os.Exit(runStandin(os.Args[2:]))
	case "wait":
		os.Exit(runWait(os.Args[2:]))
	default:
		fmt.Fprintln(os.Stderr, "unknown command", os.Args[1])
		os.Exit(2)
	}
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	mode := fs.String("mode", "full", "full or deep")
	expectedPath := fs.String("expected", "expected.json", "ground truth")
	skip := fs.String("skip", "", "comma-separated entry names that could not be started")
	out := fs.String("out", "", "write the JSON report here")
	timeout := fs.Duration("timeout", 8*time.Second, "per-connection timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	raw, err := os.ReadFile(*expectedPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var exp expectedFile
	if err := json.Unmarshal(raw, &exp); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	skipped := map[string]bool{}
	for _, n := range strings.Split(*skip, ",") {
		if n != "" {
			skipped[n] = true
		}
	}

	hosts := map[string]bool{}
	for _, e := range exp.Entries {
		if !skipped[e.Name] {
			hosts[e.Host] = true
		}
	}
	var targets []string
	for h := range hosts {
		targets = append(targets, h)
	}
	sort.Strings(targets)

	cfg := scanner.ScanConfig{Targets: targets, Concurrency: 20, Timeout: *timeout}
	switch *mode {
	case "full":
		cfg.Ports = scanner.PortsForScanType("full")
		cfg.ActiveProbes = true
	case "deep":
		cfg.Deep = true
		cfg.DeepPortLo, cfg.DeepPortHi = 1, 9999
	default:
		fmt.Fprintln(os.Stderr, "mode must be full or deep")
		return 2
	}
	res := scanner.New(cfg).Scan(context.Background(), "corpus-"+*mode)

	byKey := map[string]scanner.DiscoveredEndpoint{}
	for _, ep := range res.Endpoints {
		byKey[fmt.Sprintf("%s:%d", ep.Host, ep.Port)] = ep
	}
	rep := report{Mode: *mode, Confidence: map[string]int{}, CorrectByConf: map[string]int{}}
	seen := map[string]bool{}
	claims, correct := 0, 0
	for _, e := range exp.Entries {
		key := fmt.Sprintf("%s:%d", e.Host, e.Port)
		r := row{Name: e.Name, Endpoint: key, Expected: e.Tech}
		seen[key] = true
		if skipped[e.Name] {
			r.Status = "skipped"
			rep.Skipped++
			rep.Rows = append(rep.Rows, r)
			continue
		}
		rep.Expected++
		ep, ok := byKey[key]
		if !ok || ep.Fingerprint == nil {
			r.Status = "missed"
			rep.Missed++
			rep.Rows = append(rep.Rows, r)
			continue
		}
		fillRow(&r, ep)
		if *mode == "deep" && ep.Certs != nil {
			if obs, ok := scanner.ObserveTLSStack(context.Background(), e.Host, e.Port, *timeout); ok {
				r.Stack = &obs
			}
		}
		if *mode == "deep" && e.TLSStack != "" {
			rep.StackExpected++
			switch r.TLSStack {
			case e.TLSStack:
				rep.StackCorrect++
			case "unknown", "":
				rep.StackUnknown++
			default:
				rep.StackWrong++
			}
		}
		if r.Got != scanner.TechUnknown {
			claims++
		}
		rep.Confidence[r.Confidence]++
		if r.Got == e.Tech {
			r.Status = "correct"
			rep.Correct++
			correct++
			rep.CorrectByConf[r.Confidence]++
		} else {
			r.Status = "wrong"
			if r.Got == scanner.TechUnknown {
				r.Status = "missed"
				rep.Missed++
			} else {
				rep.Wrong++
				if r.Confidence == scanner.ConfidenceHigh {
					rep.WrongHigh++
					rep.WrongHighDetail = append(rep.WrongHighDetail, fmt.Sprintf("%s expected %s got %s", key, e.Tech, r.Got))
				}
			}
		}
		rep.Rows = append(rep.Rows, r)
	}
	for key, ep := range byKey {
		if seen[key] || ep.Fingerprint == nil {
			continue
		}
		r := row{Endpoint: key}
		fillRow(&r, ep)
		if r.Got != scanner.TechUnknown {
			claims++
			rep.Unexpected = append(rep.Unexpected, r)
			if r.Confidence == scanner.ConfidenceHigh {
				rep.WrongHigh++
				rep.WrongHighDetail = append(rep.WrongHighDetail, fmt.Sprintf("%s unexpected endpoint claimed %s", key, r.Got))
			}
		}
	}
	if rep.Expected > 0 {
		rep.Recall = float64(rep.Correct) / float64(rep.Expected)
	}
	if claims > 0 {
		rep.Precision = float64(correct) / float64(claims)
	}
	sort.Slice(rep.Unexpected, func(i, j int) bool { return rep.Unexpected[i].Endpoint < rep.Unexpected[j].Endpoint })

	printReport(rep)
	if *out != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	return 0
}

func fillRow(r *row, ep scanner.DiscoveredEndpoint) {
	fp := ep.Fingerprint
	r.Got, r.Confidence, r.Platform, r.TLSStack = fp.Tech, fp.Confidence, fp.Platform, fp.TLSStack
	r.Evidence = fp.Evidence
	r.Findings = ep.Findings
}

func printReport(rep report) {
	fmt.Printf("mode=%s expected=%d correct=%d wrong=%d missed=%d skipped=%d recall=%.3f precision=%.3f wrong_high=%d\n",
		rep.Mode, rep.Expected, rep.Correct, rep.Wrong, rep.Missed, rep.Skipped, rep.Recall, rep.Precision, rep.WrongHigh)
	fmt.Printf("confidence distribution: high=%d medium=%d low=%d (correct: high=%d medium=%d low=%d)\n",
		rep.Confidence["high"], rep.Confidence["medium"], rep.Confidence["low"],
		rep.CorrectByConf["high"], rep.CorrectByConf["medium"], rep.CorrectByConf["low"])
	if rep.StackExpected > 0 {
		fmt.Printf("tls stack (deep): expected=%d correct=%d unknown=%d wrong=%d\n", rep.StackExpected, rep.StackCorrect, rep.StackUnknown, rep.StackWrong)
	}
	for _, r := range rep.Rows {
		fmt.Printf("  %-9s %-14s %-22s expected=%-16s got=%-16s conf=%-6s platform=%-9s stack=%s\n",
			strings.ToUpper(r.Status), r.Name, r.Endpoint, r.Expected, r.Got, r.Confidence, r.Platform, r.TLSStack)
	}
	for _, r := range rep.Unexpected {
		fmt.Printf("  UNEXPECTED %-22s got=%s conf=%s\n", r.Endpoint, r.Got, r.Confidence)
	}
}

// --- stand-ins ---

func runStandin(args []string) int {
	fs := flag.NewFlagSet("standin", flag.ExitOnError)
	kind := fs.String("kind", "", "k8s or winrm")
	addr := fs.String("addr", ":6443", "listen address")
	cert := fs.String("cert", "", "certificate PEM")
	key := fs.String("key", "", "key PEM")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var h http.HandlerFunc
	switch *kind {
	case "k8s":
		// What kube-apiserver answers an anonymous request with.
		h = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}`)
		}
	case "winrm":
		// What WinRM on http.sys answers an unauthenticated request with.
		h = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
			w.Header().Add("WWW-Authenticate", "Negotiate")
			w.Header().Add("WWW-Authenticate", "Basic realm=\"WSMAN\"")
			w.WriteHeader(http.StatusUnauthorized)
		}
	default:
		fmt.Fprintln(os.Stderr, "kind must be k8s or winrm")
		return 2
	}
	srv := &http.Server{Addr: *addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if err := srv.ListenAndServeTLS(*cert, *key); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// runWait polls host:port pairs until they accept a TCP connection or the
// deadline passes, then prints the pairs that never did (one per line) and
// exits 0 either way: a service that cannot start is a skip, not a crash.
func runWait(args []string) int {
	fs := flag.NewFlagSet("wait", flag.ExitOnError)
	targets := fs.String("targets", "", "comma-separated host:port")
	limit := fs.Duration("timeout", 120*time.Second, "overall deadline")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	deadline := time.Now().Add(*limit)
	var (
		mu   sync.Mutex
		down []string
		wg   sync.WaitGroup
	)
	for _, t := range strings.Split(*targets, ",") {
		if t == "" {
			continue
		}
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			// Every target gets at least one attempt, however long the others took.
			for {
				c, err := net.DialTimeout("tcp", t, 2*time.Second)
				if err == nil {
					c.Close()
					return
				}
				if time.Now().After(deadline) {
					mu.Lock()
					down = append(down, t)
					mu.Unlock()
					return
				}
				time.Sleep(time.Second)
			}
		}(t)
	}
	wg.Wait()
	sort.Strings(down)
	for _, t := range down {
		fmt.Println(t)
	}
	return 0
}
