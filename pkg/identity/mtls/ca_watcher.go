// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// ca_watcher.go provides hot-reload support for mTLS CA bundles.
// It watches a CA bundle file and reloads the x509.CertPool when the
// content changes, with no pod restart. See D1 (ENT-KEYROT-1).
package mtls

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/mikeappsec/lightweightauth/pkg/keyrotation"
)

// CABundleWatcher watches a CA bundle file and hot-reloads the CertPool
// whenever the file changes on disk.
type CABundleWatcher struct {
	mu       sync.RWMutex
	pool     *x509.CertPool
	path     string
	watcher  *fsnotify.Watcher
	lastLoad time.Time
	onReload func(pool *x509.CertPool, err error) // optional callback
}

// NewCABundleWatcher creates a watcher that loads the CA bundle at path
// and reloads on file-system changes. Call Close() when done.
func NewCABundleWatcher(path string, onReload func(*x509.CertPool, error)) (*CABundleWatcher, error) {
	w := &CABundleWatcher{path: path, onReload: onReload}

	if err := w.load(); err != nil {
		return nil, fmt.Errorf("initial CA bundle load: %w", err)
	}

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("fsnotify: %w", err)
	}
	if err := fsw.Add(path); err != nil {
		fsw.Close()
		return nil, fmt.Errorf("watch %s: %w", path, err)
	}
	w.watcher = fsw
	go w.watchLoop()
	return w, nil
}

// Pool returns the current CertPool (safe for concurrent use).
func (w *CABundleWatcher) Pool() *x509.CertPool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.pool
}

// Close stops the file watcher.
func (w *CABundleWatcher) Close() error {
	if w.watcher != nil {
		return w.watcher.Close()
	}
	return nil
}

func (w *CABundleWatcher) load() error {
	data, err := os.ReadFile(w.path)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	var count int
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue // skip malformed certs
		}
		pool.AddCert(cert)
		count++
	}
	if count == 0 {
		return fmt.Errorf("no valid certificates in %s", w.path)
	}
	w.mu.Lock()
	w.pool = pool
	w.lastLoad = time.Now()
	w.mu.Unlock()
	return nil
}

func (w *CABundleWatcher) watchLoop() {
	for {
		select {
		case ev, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}
			err := w.load()
			if w.onReload != nil {
				w.onReload(w.Pool(), err)
			}
			if err == nil {
				keyrotation.Metrics.RefreshTotal.WithLabelValues("mtls", "success").Inc()
			} else {
				keyrotation.Metrics.RefreshTotal.WithLabelValues("mtls", "error").Inc()
			}
		case _, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			// fsnotify errors are informational; log would go here.
		}
	}
}
