// Package server hosts the transport adapters that translate between an
// inbound transport (HTTP, native gRPC, Envoy ext_authz) and the internal
// pipeline.Engine. See docs/ARCHITECTURE.md.
package server

import (
	"sync/atomic"

	"github.com/mikeappsec/lightweightauth/internal/pipeline"
)

// EngineHolder is what every server adapter holds. The config layer swaps
// the pointer atomically on hot-reload; request paths use Load().
type EngineHolder struct {
	p atomic.Pointer[pipeline.Engine]
}

// NewEngineHolder constructs a holder pre-loaded with eng.
func NewEngineHolder(eng *pipeline.Engine) *EngineHolder {
	h := &EngineHolder{}
	h.p.Store(eng)
	return h
}

// Load returns the current Engine. Never returns nil after the holder has
// been initialized.
func (h *EngineHolder) Load() *pipeline.Engine { return h.p.Load() }

// Swap atomically installs a new Engine.
func (h *EngineHolder) Swap(eng *pipeline.Engine) { h.p.Store(eng) }
