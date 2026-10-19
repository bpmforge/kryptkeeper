// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

// D-290-A: a store whose database is configured but cannot be opened is a
// fault, not a mode. Agent tokens, break-glass elevations and access-review
// evidence must never silently land in process memory (lost on restart,
// diverging across HA replicas). The store is reported down, its routes
// answer 503, the open is retried, and /readyz reports not ready until it
// recovers. Memory is only available when named explicitly.

// storeUnavailableMessage is the uniform 503 body; the cause is logged
// server-side only (it can carry DSN fragments and driver text).
const storeUnavailableMessage = "service temporarily unavailable"

var errStoreUnavailable = errors.New("backing store unavailable")

// storeRetryInterval throttles reopen attempts so a down database costs one
// dial per interval, not one per request.
const storeRetryInterval = 10 * time.Second

// memoryProviderRequested reports whether the operator asked for the
// in-memory adapter by name (the S-40 value set). Anything else, including
// unset, means the database.
func memoryProviderRequested(envName, what string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envName))) {
	case "file", "memory", "inmemory":
		logging.Warnf("%s: in-memory (%s=memory) — state is not persisted, is not shared between replicas and is lost on restart; do not use outside tests/offline dev", what, envName)
		return true
	}
	return false
}

// lazyStore holds a store that may not be open yet. Construction opens it
// once synchronously; while it is down, get() and ready() answer
// errStoreUnavailable and kick a throttled background reopen.
type lazyStore[S any] struct {
	name       string
	open       func() (S, error) // logs its own cause; the error is not surfaced
	onUp       func(S)
	retryEvery time.Duration
	now        func() time.Time

	mu      sync.Mutex
	inner   S
	up      bool
	trying  bool
	lastTry time.Time
	failed  bool
}

func newLazyStore[S any](name string, open func() (S, error), onUp func(S)) *lazyStore[S] {
	l := &lazyStore[S]{name: name, open: open, onUp: onUp, retryEvery: storeRetryInterval, now: time.Now}
	l.attempt()
	return l
}

func (l *lazyStore[S]) attempt() {
	inner, err := l.open()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.trying = false
	l.lastTry = l.now()
	if err != nil {
		l.failed = true
		l.up = false
		return
	}
	if l.failed {
		logging.Infof("%s store recovered; serving again", l.name)
	}
	l.failed = false
	l.inner, l.up = inner, true
	if l.onUp != nil {
		l.onUp(inner)
	}
}

func (l *lazyStore[S]) get() (S, error) {
	l.mu.Lock()
	if l.up {
		s := l.inner
		l.mu.Unlock()
		return s, nil
	}
	kick := !l.trying && l.now().Sub(l.lastTry) >= l.retryEvery
	if kick {
		l.trying = true
	}
	l.mu.Unlock()
	if kick {
		go l.attempt()
	}
	var zero S
	return zero, errStoreUnavailable
}

// ready is the readiness probe and the route gate: it never dials inline.
func (l *lazyStore[S]) ready() error {
	_, err := l.get()
	return err
}

// storeReadiness is implemented by the lazy store wrappers.
type storeReadiness interface{ ready() error }

// routeRegistrar is the part of *http.ServeMux the feature route builders use,
// so a gate can wrap every route of a feature.
type routeRegistrar interface {
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// gatedRoutes answers 503 on every route it registers while ready reports an
// error.
type gatedRoutes struct {
	mux   routeRegistrar
	ready func() error
}

func (g gatedRoutes) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	g.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if g.ready() != nil {
			writeServiceUnavailable(w, storeUnavailableMessage)
			return
		}
		h(w, r)
	})
}

// gateRoutes gates mux on store's readiness when it has one (the lazy
// wrappers); plain in-memory stores need no gate.
func gateRoutes(mux routeRegistrar, store any) routeRegistrar {
	if r, ok := store.(storeReadiness); ok {
		return gatedRoutes{mux: mux, ready: r.ready}
	}
	return mux
}

// requiredStores are the stores /readyz must see up. They hang off the
// Authenticator because the governance routes are mounted from a call site
// that has no ServerConfig, and a package-level list would be new global state.
type requiredStores struct {
	mu     sync.Mutex
	probes []func() error
}

func (a *Authenticator) requireStore(store any) {
	r, ok := store.(storeReadiness)
	if !ok || a == nil {
		return
	}
	a.required.mu.Lock()
	a.required.probes = append(a.required.probes, r.ready)
	a.required.mu.Unlock()
}

// requiredStoresReady returns the first required store that is down.
func (a *Authenticator) requiredStoresReady() error {
	a.required.mu.Lock()
	probes := append([]func() error(nil), a.required.probes...)
	a.required.mu.Unlock()
	for _, p := range probes {
		if err := p(); err != nil {
			return err
		}
	}
	return nil
}
