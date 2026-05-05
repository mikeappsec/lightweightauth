// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package connpool

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"sync"
	"time"
)

// HTTPConfig describes a pooled HTTP client configuration.
type HTTPConfig struct {
	// BaseURL is used as the pool key (same base = same client).
	BaseURL string

	// Timeout is the overall request timeout.
	Timeout time.Duration

	// TLS enables TLS with minimum 1.2.
	TLS bool

	// InsecureSkipVerify disables certificate verification (dev only).
	InsecureSkipVerify bool
}

func httpKey(cfg HTTPConfig) string {
	h := sha256.New()
	hashField(h, []byte(cfg.BaseURL))
	hashField(h, []byte(cfg.Timeout.String()))
	if cfg.TLS {
		h.Write([]byte("tls"))
	}
	if cfg.InsecureSkipVerify {
		h.Write([]byte("insecure"))
	}
	return "http:" + hex.EncodeToString(h.Sum(nil))[:16]
}

var httpPool = struct {
	mu      sync.Mutex
	clients map[string]*http.Client
}{clients: map[string]*http.Client{}}

// GetHTTP returns a shared *http.Client for the given config. Clients
// targeting the same BaseURL share a connection pool, reducing TCP/TLS
// handshake overhead across config reloads.
//
// The returned client MUST NOT have its Transport closed by callers.
func GetHTTP(cfg HTTPConfig) *http.Client {
	key := httpKey(cfg)

	httpPool.mu.Lock()
	defer httpPool.mu.Unlock()

	if c, ok := httpPool.clients[key]; ok {
		return c
	}

	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	if cfg.TLS || cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		}
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	httpPool.clients[key] = client
	return client
}
