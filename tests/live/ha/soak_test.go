// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ha_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goocsp "golang.org/x/crypto/ocsp"
)

// soakPlan is the W23-29 timeline. Offsets are from the start of the timed
// phase, after the 50 probe serials are issued and primed.
type soakPlan struct {
	Mode         string          `json:"mode"`
	Total        int             `json:"issuance_target"`
	HardStop     time.Duration   `json:"-"`
	Tick         time.Duration   `json:"-"`
	KillAt       time.Duration   `json:"-"`
	RestartAt    time.Duration   `json:"-"`
	PGAt         time.Duration   `json:"-"`
	PartitionAt  time.Duration   `json:"-"`
	PartitionEnd time.Duration   `json:"-"`
	RevokeAt     []time.Duration `json:"-"`
}

func fullPlan() soakPlan {
	p := soakPlan{Mode: "full", Total: 10000, HardStop: 36 * time.Minute, Tick: 180 * time.Millisecond,
		KillAt: 8 * time.Minute, RestartAt: 9 * time.Minute, PGAt: 15 * time.Minute,
		PartitionAt: 22 * time.Minute, PartitionEnd: 23*time.Minute + 30*time.Second}
	for m := 5; m <= 30; m += 5 {
		p.RevokeAt = append(p.RevokeAt, time.Duration(m)*time.Minute)
	}
	return p
}

// shortPlan is the plumbing dry-run. A needs about 15 s to boot on a loaded
// host and refuses to start while Postgres is down, so the Postgres restart
// is placed well after A's restart.
func shortPlan() soakPlan {
	p := soakPlan{Mode: "short", Total: 200, HardStop: 120 * time.Second, Tick: 250 * time.Millisecond,
		KillAt: 10 * time.Second, RestartAt: 14 * time.Second, PGAt: 35 * time.Second,
		PartitionAt: 50 * time.Second, PartitionEnd: 60 * time.Second}
	for _, s := range []int{5, 20, 30, 45, 65, 75} {
		p.RevokeAt = append(p.RevokeAt, time.Duration(s)*time.Second)
	}
	return p
}

type soakEvent struct {
	ElapsedS float64 `json:"elapsed_s"`
	UTC      string  `json:"utc"`
	Name     string  `json:"name"`
	Detail   string  `json:"detail,omitempty"`
}

type availability struct {
	OK       int64    `json:"ok"`
	Total    int64    `json:"total"`
	Percent  float64  `json:"percent"`
	FailedAt []string `json:"failure_windows,omitempty"`
}

type revokeProbe struct {
	PlannedAtS float64 `json:"planned_at_s"`
	Attempts   int     `json:"revoke_attempts"`
	LatencyS   float64 `json:"latency_s"`
	Visible    bool    `json:"visible_on_b"`
	Note       string  `json:"note,omitempty"`
}

type readyzChange struct {
	ElapsedS float64 `json:"elapsed_s"`
	Replica  string  `json:"replica"`
	Code     int     `json:"code"`
}

type soakResult struct {
	Env    map[string]string `json:"env"`
	Plan   soakPlan          `json:"plan"`
	Events []soakEvent       `json:"events"`

	DurationS float64 `json:"duration_s"`
	Issuance  struct {
		Target           int                `json:"target"`
		Successes        int64              `json:"successes"`
		Failures         map[string]int     `json:"failures_by_class"`
		SkippedNoReplica int64              `json:"ticks_skipped_no_ready_replica"`
		DroppedTicks     int64              `json:"ticks_dropped_workers_busy"`
		RowsInDB         int                `json:"certificates_rows_for_ca"`
		RowsWithoutReply int                `json:"rows_beyond_successes_and_primed"`
		PartialRows      int                `json:"partial_rows_raw_cert_b64_null"`
		DuplicateSerials int                `json:"duplicate_serial_groups"`
		LatencyMs        map[string]float64 `json:"success_latency_ms"`
		FailuresPerMin   map[string]int     `json:"failures_per_minute"`
		ErrorKinds       map[string]int     `json:"error_kinds"`
	} `json:"issuance"`

	AvailBalancerCombined availability `json:"availability_balancer_primed_combined"`
	AvailBalancerCRL      availability `json:"availability_balancer_crl"`
	AvailBalancerOCSP     availability `json:"availability_balancer_ocsp_primed"`
	AvailDirectCombined   availability `json:"availability_direct_primed_combined"`
	AvailUnprimedOCSP     availability `json:"availability_balancer_ocsp_unprimed"`

	Revocation struct {
		Probes []revokeProbe `json:"probes"`
		MaxS   float64       `json:"max_s"`
		P50S   float64       `json:"p50_s"`
	} `json:"revocation_visibility"`

	DuplicateRenewalRowsExamined int `json:"renewal_rows_examined"`
	AlertRowsExamined            int `json:"alert_rows_examined"`

	ReadyzChanges []readyzChange `json:"readyz_changes"`
	Loadavg       struct {
		Start   string   `json:"start"`
		End     string   `json:"end"`
		Peak1   float64  `json:"peak_1min"`
		Samples []string `json:"samples_every_60s"`
	} `json:"loadavg"`

	Pass map[string]*bool `json:"pass"`
}

func sh(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func boolp(b bool) *bool { return &b }

func TestHASoak(t *testing.T) {
	e := loadEnv(t, "KK_HA_SOAK")
	plan := fullPlan()
	if os.Getenv("KK_HA_SOAK_SHORT") == "1" {
		plan = shortPlan()
	}
	a, b := newHub("A", e.aURL, e.token, 20*time.Second), newHub("B", e.bURL, e.token, 20*time.Second)
	f := setupFixture(t, a, b)
	db := openDB(t, e.dsn)

	res := &soakResult{Plan: plan, Pass: map[string]*bool{}}
	res.Issuance.Target = plan.Total
	res.Issuance.Failures = map[string]int{}
	res.Issuance.FailuresPerMin = map[string]int{}
	res.Issuance.ErrorKinds = map[string]int{}
	var resMu sync.Mutex // guards res.Events and res.Issuance.Failures

	var t0 time.Time
	elapsed := func() float64 { return math.Round(time.Since(t0).Seconds()*10) / 10 }
	mark := func(name, detail string) {
		resMu.Lock()
		res.Events = append(res.Events, soakEvent{ElapsedS: elapsed(), UTC: time.Now().UTC().Format(time.RFC3339), Name: name, Detail: detail})
		resMu.Unlock()
		t.Logf("[t+%6.1fs] %s %s", elapsed(), name, detail)
	}

	// ---- prime 50 serials on both replicas before t=0 --------------------
	primed := make([]*big.Int, 0, 50)
	probeHC := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 32}}
	for i := 0; i < 50; i++ {
		is, st, body, err := f.issue(a, fmt.Sprintf("ha-soak-primed-%d", i))
		if err != nil || st != http.StatusCreated {
			t.Fatalf("priming issuance %d: %d %v %.200s", i, st, err, body)
		}
		primed = append(primed, is.serial)
	}
	for _, s := range primed {
		for _, h := range []*hub{a, b} {
			if st, ok, err := f.ocspStatus(probeHC, h.base, s); err != nil || !ok || st != goocsp.Good {
				t.Fatalf("priming OCSP on %s for %s: status %d ok %v err %v", h.name, s, st, ok, err)
			}
		}
	}
	for _, h := range []*hub{a, b} {
		if err := f.crlFetch(probeHC, h.base); err != nil {
			t.Fatalf("priming CRL on %s: %v", h.name, err)
		}
	}

	t0 = time.Now()
	bal := newBalancer(a, b)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go bal.run(ctx)

	// Environment: captured for the report.
	res.Env = map[string]string{
		"utc_start": time.Now().UTC().Format(time.RFC3339), "go": runtime.Version(),
		"commit": sh("git", "rev-parse", "--short", "HEAD"), "uname": sh("uname", "-a"),
		"cpu": sh("sysctl", "-n", "machdep.cpu.brand_string"), "cores": strconv.Itoa(runtime.NumCPU()),
		"os": sh("sw_vers", "-productVersion"), "podman": sh("podman", "--version"),
		"podman_machine": sh("podman", "machine", "list", "--format", "{{.Name}} cpus={{.CPUs}} mem={{.Memory}} disk={{.DiskSize}}"),
		"image_id":       sh("podman", "image", "inspect", "--format", "{{.Id}}", "localhost/kryptkeeper:kkha-w23"),
		"hub_version":    sh("podman", "image", "inspect", "--format", "{{index .Config.Labels \"org.opencontainers.image.title\"}}", "localhost/kryptkeeper:kkha-w23"),
		"poll_minutes":   strconv.Itoa(e.pollMinutes), "revocation_sync_interval": "2s",
	}
	if mem, err := strconv.ParseInt(sh("sysctl", "-n", "hw.memsize"), 10, 64); err == nil {
		res.Env["ram_gb"] = strconv.FormatInt(mem>>30, 10)
	}
	var pgv string
	if err := db.QueryRow(`SELECT version()`).Scan(&pgv); err == nil {
		res.Env["postgres"] = pgv
	}
	if out, err := podman("ps", "--format", "{{.Names}} {{.Image}}"); err == nil {
		res.Env["running_containers_on_host"] = strconv.Itoa(len(strings.Split(out, "\n")))
	}

	// ---- load average sampler ---------------------------------------------
	parseLoad := func(s string) float64 {
		fs := strings.Fields(strings.Trim(s, "{} "))
		if len(fs) == 0 {
			return 0
		}
		v, _ := strconv.ParseFloat(fs[0], 64)
		return v
	}
	res.Loadavg.Start = sh("sysctl", "-n", "vm.loadavg")
	res.Loadavg.Peak1 = parseLoad(res.Loadavg.Start)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tk := time.NewTicker(60 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				l := sh("sysctl", "-n", "vm.loadavg")
				resMu.Lock()
				res.Loadavg.Samples = append(res.Loadavg.Samples, strings.Trim(l, "{} "))
				if v := parseLoad(l); v > res.Loadavg.Peak1 {
					res.Loadavg.Peak1 = v
				}
				resMu.Unlock()
			}
		}
	}()

	// ---- /readyz recorder (status codes, so 503 is told from a dead socket) --
	wg.Add(1)
	go func() {
		defer wg.Done()
		hc := &http.Client{Timeout: 2 * time.Second}
		last := map[string]int{"A": -1, "B": -1}
		tk := time.NewTicker(500 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
			}
			for _, h := range []*hub{a, b} {
				code := 0
				if resp, err := hc.Get(h.base + "/readyz"); err == nil {
					code = resp.StatusCode
					_ = resp.Body.Close()
				}
				if last[h.name] != code {
					last[h.name] = code
					resMu.Lock()
					res.ReadyzChanges = append(res.ReadyzChanges, readyzChange{ElapsedS: elapsed(), Replica: h.name, Code: code})
					resMu.Unlock()
				}
			}
		}
	}()

	// ---- availability probers ---------------------------------------------
	type counter struct {
		ok, total atomic.Int64
		mu        sync.Mutex
		fails     []float64
	}
	var cBalCRL, cBalOCSP, cDirCRL, cDirOCSP, cUnprimed counter
	record := func(c *counter, ok bool) {
		c.total.Add(1)
		if ok {
			c.ok.Add(1)
			return
		}
		c.mu.Lock()
		if len(c.fails) < 20000 {
			c.fails = append(c.fails, elapsed())
		}
		c.mu.Unlock()
	}
	var directRR atomic.Uint64
	direct := func(try func(h *hub) bool) bool {
		hubs := []*hub{a, b}
		i := directRR.Add(1)
		for k := uint64(0); k < 2; k++ { // one failover, like an L4 balancer
			if try(hubs[(i+k)%2]) {
				return true
			}
		}
		return false
	}
	unprimedQ := make(chan *big.Int, 8192)
	var probeSeq atomic.Uint64
	wg.Add(1)
	go func() {
		defer wg.Done()
		tk := time.NewTicker(500 * time.Millisecond)
		defer tk.Stop()
		var pw sync.WaitGroup
		defer pw.Wait()
		tick := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
			}
			tick++
			serial := primed[int(probeSeq.Add(1))%len(primed)]
			pw.Add(4)
			go func() {
				defer pw.Done()
				r := bal.pick()
				record(&cBalCRL, r != nil && f.crlFetch(probeHC, r.base) == nil)
			}()
			go func() {
				defer pw.Done()
				r := bal.pick()
				ok := false
				if r != nil {
					st, o, _ := f.ocspStatus(probeHC, r.base, serial)
					ok = o && st == goocsp.Good
				}
				record(&cBalOCSP, ok)
			}()
			go func() {
				defer pw.Done()
				record(&cDirCRL, direct(func(h *hub) bool { return f.crlFetch(probeHC, h.base) == nil }))
			}()
			go func() {
				defer pw.Done()
				record(&cDirOCSP, direct(func(h *hub) bool {
					st, o, _ := f.ocspStatus(probeHC, h.base, serial)
					return o && st == goocsp.Good
				}))
			}()
			if tick%2 == 0 { // one never-queried serial per second: forces the DB lookup
				select {
				case s := <-unprimedQ:
					pw.Add(1)
					go func() {
						defer pw.Done()
						r := bal.pick()
						ok := false
						if r != nil {
							st, o, _ := f.ocspStatus(probeHC, r.base, s)
							ok = o && st == goocsp.Good
						}
						record(&cUnprimed, ok)
					}()
				default:
				}
			}
		}
	}()

	// ---- issuance ---------------------------------------------------------
	mark("soak_start", fmt.Sprintf("mode=%s target=%d tick=%s", plan.Mode, plan.Total, plan.Tick))
	var successes, skipped, dropped atomic.Int64
	classify := func(st int, err error) string {
		switch {
		case st == 0 && err != nil && (strings.Contains(err.Error(), "deadline") || strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "Timeout")):
			return "timeout"
		case st == 0:
			return "connection"
		case st >= 500:
			return "5xx"
		case st >= 400:
			return "4xx"
		default:
			return fmt.Sprintf("http_%d", st)
		}
	}
	sampleErr := map[string]string{}
	var latencies []float64
	jobs := make(chan int)
	var iw sync.WaitGroup
	for w := 0; w < 8; w++ {
		iw.Add(1)
		go func() {
			defer iw.Done()
			for i := range jobs {
				r := bal.pick()
				if r == nil {
					skipped.Add(1)
					continue
				}
				began := time.Now()
				is, st, body, err := f.issue(r.hub, fmt.Sprintf("ha-soak-%d", i))
				took := time.Since(began)
				if err == nil && st == http.StatusCreated {
					successes.Add(1)
					resMu.Lock()
					latencies = append(latencies, float64(took.Microseconds())/1000)
					resMu.Unlock()
					select {
					case unprimedQ <- is.serial:
					default:
					}
					continue
				}
				cls := classify(st, err)
				resMu.Lock()
				res.Issuance.Failures[cls]++
				res.Issuance.FailuresPerMin[fmt.Sprintf("m%02d", int(time.Since(t0).Minutes()))]++
				res.Issuance.ErrorKinds[errKind(r.name, st, err)]++
				if _, ok := sampleErr[cls]; !ok {
					msg := fmt.Sprintf("replica %s HTTP %d err=%v body=%.160s", r.name, st, err, body)
					sampleErr[cls] = msg
				}
				resMu.Unlock()
			}
		}()
	}
	stopIssuing := make(chan struct{})
	var issuerDone sync.WaitGroup
	issuerDone.Add(1)
	go func() {
		defer issuerDone.Done()
		defer close(jobs)
		tk := time.NewTicker(plan.Tick)
		defer tk.Stop()
		hard := time.After(plan.HardStop)
		i := 0
		for successes.Load() < int64(plan.Total) {
			select {
			case <-stopIssuing:
				return
			case <-hard:
				mark("issuance_hard_stop", fmt.Sprintf("successes=%d", successes.Load()))
				return
			case <-tk.C:
				select {
				case jobs <- i:
					i++
				default:
					dropped.Add(1)
				}
			}
		}
		mark("issuance_target_reached", fmt.Sprintf("successes=%d", successes.Load()))
	}()

	// ---- injectors --------------------------------------------------------
	var injWG sync.WaitGroup
	at := func(d time.Duration, fn func()) {
		injWG.Add(1)
		go func() {
			defer injWG.Done()
			select {
			case <-time.After(time.Until(t0.Add(d))):
				fn()
			case <-ctx.Done():
			}
		}()
	}
	// run logs the injector at the moment it was issued, with how long the
	// podman call took (on a loaded host a kill can take seconds).
	run := func(name string, args ...string) bool {
		began := elapsed()
		start := time.Now()
		out, err := podman(args...)
		d := fmt.Sprintf("podman %s (took %s)", strings.Join(args, " "), time.Since(start).Round(time.Millisecond))
		if err != nil {
			d += fmt.Sprintf(" FAILED: %v %.120s", err, out)
		}
		resMu.Lock()
		res.Events = append(res.Events, soakEvent{ElapsedS: began, UTC: start.UTC().Format(time.RFC3339), Name: name, Detail: d})
		resMu.Unlock()
		t.Logf("[t+%6.1fs] %s %s", began, name, d)
		return err == nil
	}
	// Kill and restart are one sequence: the restart waits for the kill to
	// return, or a slow kill would land after the start and leave A dead.
	at(plan.KillAt, func() {
		run("kill_replica_A", "kill", "-s", "KILL", e.container("kk-a"))
		time.Sleep(time.Until(t0.Add(plan.RestartAt)))
		for try := 0; try < 3; try++ {
			if run("restart_replica_A", "start", e.container("kk-a")) {
				return
			}
			time.Sleep(2 * time.Second)
		}
	})
	at(plan.PGAt, func() {
		// Simulated failover: an abrupt restart (connections drop, in-flight
		// transactions abort); there is no standby and no promotion.
		run("postgres_restart_abrupt", "restart", "-t", "0", e.container("postgres"))
	})
	at(plan.PartitionAt, func() {
		run("partition_begin_B", "network", "disconnect", e.project+"_db", e.container("kk-b"))
	})
	at(plan.PartitionEnd, func() {
		run("partition_end_B", "network", "connect", e.project+"_db", e.container("kk-b"))
	})

	// ---- revocation visibility probes -------------------------------------
	probes := make([]revokeProbe, len(plan.RevokeAt))
	for i, d := range plan.RevokeAt {
		i, d := i, d
		probes[i] = revokeProbe{PlannedAtS: d.Seconds()}
		at(d, func() {
			p := &probes[i]
			var is issued
			var revokedSent time.Time
			deadline := time.Now().Add(120 * time.Second)
			for time.Now().Before(deadline) {
				p.Attempts++
				var st int
				var err error
				is, st, _, err = f.issue(a, fmt.Sprintf("ha-soak-revoke-%d", i))
				if err != nil || st != http.StatusCreated {
					time.Sleep(2 * time.Second)
					continue
				}
				// Warm B's OCSP cache so the measurement is an invalidation, not a first fill.
				if s, ok, _ := f.ocspStatus(probeHC, b.base, is.serial); ok && s != goocsp.Good {
					p.Note = "serial not Good before revoke"
					return
				}
				revokedSent = time.Now()
				rst, _, rerr := a.do(http.MethodPost, "/api/v1/certificates/"+is.fingerprint+"/revoke",
					map[string]any{"reason_code": 1, "reason_text": "ha soak"})
				if rerr == nil && rst/100 == 2 {
					break
				}
				revokedSent = time.Time{}
				time.Sleep(2 * time.Second)
			}
			if revokedSent.IsZero() {
				p.Note = "could not issue and revoke on A within 120 s"
				return
			}
			until := revokedSent.Add(120 * time.Second)
			for time.Now().Before(until) {
				if s, ok, _ := f.ocspStatus(probeHC, b.base, is.serial); ok && s == goocsp.Revoked {
					p.Visible = true
					p.LatencyS = math.Round(time.Since(revokedSent).Seconds()*100) / 100
					mark("revocation_visible_on_B", fmt.Sprintf("probe %d latency %.2fs attempts %d", i+1, p.LatencyS, p.Attempts))
					return
				}
				time.Sleep(time.Second)
			}
			p.Note = "not visible on B within 120 s"
		})
	}

	// ---- wait for everything ----------------------------------------------
	issuerDone.Wait()
	iw.Wait()
	injWG.Wait()
	mark("soak_end_of_schedule", fmt.Sprintf("successes=%d", successes.Load()))
	// Give the replicas a moment to settle before the final readiness check.
	settle, scancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer scancel()
	_ = waitFor(settle, time.Second, func() (bool, error) { return a.ready() && b.ready(), nil })
	cancel()
	wg.Wait()
	res.DurationS = elapsed()
	res.Loadavg.End = sh("sysctl", "-n", "vm.loadavg")
	res.Env["utc_end"] = time.Now().UTC().Format(time.RFC3339)
	res.Env["a_ready_at_end"] = strconv.FormatBool(a.ready())
	res.Env["b_ready_at_end"] = strconv.FormatBool(b.ready())

	// ---- collect and assert -----------------------------------------------
	res.Issuance.Successes = successes.Load()
	res.Issuance.SkippedNoReplica = skipped.Load()
	if len(latencies) > 0 {
		sort.Float64s(latencies)
		q := func(p float64) float64 { return math.Round(latencies[int(p*float64(len(latencies)-1))]*10) / 10 }
		res.Issuance.LatencyMs = map[string]float64{"p50": q(0.5), "p95": q(0.95), "p99": q(0.99), "max": q(1)}
	}
	res.Issuance.DroppedTicks = dropped.Load()
	for cls, msg := range sampleErr {
		t.Logf("sample %s failure: %s", cls, msg)
	}
	fill := func(av *availability, cs ...*counter) {
		for _, c := range cs {
			av.OK += c.ok.Load()
			av.Total += c.total.Load()
			c.mu.Lock()
			if len(c.fails) > 0 {
				av.FailedAt = append(av.FailedAt, failureWindows(c.fails)...)
			}
			c.mu.Unlock()
		}
		if av.Total > 0 {
			av.Percent = math.Round(float64(av.OK)/float64(av.Total)*100000) / 1000
		}
	}
	fill(&res.AvailBalancerCRL, &cBalCRL)
	fill(&res.AvailBalancerOCSP, &cBalOCSP)
	fill(&res.AvailBalancerCombined, &cBalCRL, &cBalOCSP)
	fill(&res.AvailDirectCombined, &cDirCRL, &cDirOCSP)
	fill(&res.AvailUnprimedOCSP, &cUnprimed)

	dups, err := queryDups(db, qDupSerials)
	if err != nil {
		t.Errorf("duplicate-serial query: %v", err)
	}
	res.Issuance.DuplicateSerials = len(dups)
	if res.Issuance.RowsInDB, err = queryCount(db, `SELECT COUNT(*) FROM certificates WHERE ca_id=$1`, f.caID); err != nil {
		t.Errorf("row count: %v", err)
	}
	res.Issuance.RowsWithoutReply = res.Issuance.RowsInDB - 50 - int(res.Issuance.Successes)
	if res.Issuance.PartialRows, err = queryCount(db, `SELECT COUNT(*) FROM certificates WHERE raw_cert_b64 IS NULL`); err != nil {
		t.Errorf("partial-row count: %v", err)
	}
	renewals, alerts := assertNoDuplicateRenewalsOrAlerts(t, db)
	res.DuplicateRenewalRowsExamined, res.AlertRowsExamined = renewals, alerts

	lat := []float64{}
	allVisible := len(probes) > 0
	for _, p := range probes {
		if p.Visible {
			lat = append(lat, p.LatencyS)
		} else {
			allVisible = false
		}
	}
	res.Revocation.Probes = probes
	if len(lat) > 0 {
		sort.Float64s(lat)
		res.Revocation.MaxS = lat[len(lat)-1]
		res.Revocation.P50S = lat[len(lat)/2]
	}

	// B must report 503 (not a dead socket) while partitioned from Postgres.
	partB503 := false
	var partStart, partEnd float64
	for _, ev := range res.Events {
		switch ev.Name {
		case "partition_begin_B":
			partStart = ev.ElapsedS
		case "partition_end_B":
			partEnd = ev.ElapsedS
		}
	}
	for _, c := range res.ReadyzChanges {
		if c.Replica == "B" && c.Code == http.StatusServiceUnavailable && c.ElapsedS >= partStart && c.ElapsedS <= partEnd+30 {
			partB503 = true
		}
	}

	res.Pass["zero_duplicate_serials"] = boolp(res.Issuance.DuplicateSerials == 0)
	res.Pass["zero_partial_rows"] = boolp(res.Issuance.PartialRows == 0)
	res.Pass["issuance_target_reached"] = boolp(res.Issuance.Successes >= int64(plan.Total))
	res.Pass["availability_primed_ge_99_9"] = boolp(res.AvailBalancerCombined.Percent >= 99.9)
	res.Pass["revocation_visible_lt_60s"] = boolp(allVisible && res.Revocation.MaxS < 60)
	res.Pass["partition_b_readyz_503"] = boolp(partB503)
	res.Pass["both_ready_at_end"] = boolp(a.ready() && b.ready())

	out := os.Getenv("KK_HA_RESULT_OUT")
	if out == "" {
		out = "soak-result.json"
	}
	if bs, err := json.MarshalIndent(res, "", "  "); err != nil {
		t.Errorf("marshal result: %v", err)
	} else if err := os.WriteFile(out, append(bs, '\n'), 0o644); err != nil {
		t.Errorf("write %s: %v", out, err)
	}

	t.Logf("issuance: %d/%d successes, failures %v, skipped(no ready replica) %d, dropped ticks %d, rows %d (beyond successes %d), partial %d, duplicate groups %d",
		res.Issuance.Successes, plan.Total, res.Issuance.Failures, res.Issuance.SkippedNoReplica, res.Issuance.DroppedTicks,
		res.Issuance.RowsInDB, res.Issuance.RowsWithoutReply, res.Issuance.PartialRows, res.Issuance.DuplicateSerials)
	t.Logf("availability via balancer (CRL+OCSP primed): %d/%d = %.3f%% (CRL %.3f%%, OCSP %.3f%%); direct with failover %.3f%%; OCSP unprimed %d/%d = %.3f%%",
		res.AvailBalancerCombined.OK, res.AvailBalancerCombined.Total, res.AvailBalancerCombined.Percent,
		res.AvailBalancerCRL.Percent, res.AvailBalancerOCSP.Percent, res.AvailDirectCombined.Percent,
		res.AvailUnprimedOCSP.OK, res.AvailUnprimedOCSP.Total, res.AvailUnprimedOCSP.Percent)
	t.Logf("revocation visible on B: max %.2fs p50 %.2fs over %d probes", res.Revocation.MaxS, res.Revocation.P50S, len(probes))
	t.Logf("duplicate renewal/alert queries examined %d renewal rows, %d alert rows", renewals, alerts)

	if res.Issuance.DuplicateSerials != 0 {
		t.Errorf("duplicate (ca_id, serial) groups: %v", dups)
	}
	if res.Issuance.PartialRows != 0 {
		t.Errorf("%d certificates rows have raw_cert_b64 NULL", res.Issuance.PartialRows)
	}
	if res.Issuance.Successes < int64(plan.Total) {
		t.Errorf("only %d of %d issuances succeeded by the hard stop", res.Issuance.Successes, plan.Total)
	}
	if res.AvailBalancerCombined.Percent < 99.9 {
		t.Errorf("CRL/OCSP availability via balancer (primed serials) %.3f%% < 99.9%% (failure windows: %v)", res.AvailBalancerCombined.Percent, res.AvailBalancerCombined.FailedAt)
	}
	if !allVisible || res.Revocation.MaxS >= 60 {
		t.Errorf("revocation visibility on B: max %.2fs, all visible=%v, probes %+v", res.Revocation.MaxS, allVisible, probes)
	}
	if !partB503 {
		t.Errorf("replica B never reported /readyz 503 during the partition window [%.1f, %.1f]s; changes: %+v", partStart, partEnd, res.ReadyzChanges)
	}
	if !a.ready() || !b.ready() {
		t.Errorf("a replica is not ready at the end of the soak")
	}
}

// failureWindows folds sorted failure timestamps into "start-end (n)" ranges
// where consecutive failures are less than 3 s apart.
func failureWindows(ts []float64) []string {
	sort.Float64s(ts)
	var out []string
	start, prev, n := ts[0], ts[0], 1
	flush := func() { out = append(out, fmt.Sprintf("t+%.0fs..t+%.0fs (%d)", start, prev, n)) }
	for _, x := range ts[1:] {
		if x-prev < 3 {
			prev = x
			n++
			continue
		}
		flush()
		start, prev, n = x, x, 1
	}
	flush()
	return out
}

var digits = regexp.MustCompile(`[0-9]+`)

// errKind names a failure by replica, status and the error with numbers
// (ports, durations) removed, so equal causes count together.
func errKind(replica string, st int, err error) string {
	msg := ""
	if err != nil {
		msg = digits.ReplaceAllString(err.Error(), "N")
		if i := strings.Index(msg, "\": "); i >= 0 {
			msg = msg[i+3:]
		}
	}
	return fmt.Sprintf("%s HTTP %d %s", replica, st, msg)
}
