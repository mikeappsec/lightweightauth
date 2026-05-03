// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package wasm

import (
	"context"
	"fmt"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// Mutator adapts a WASM module to the module.ResponseMutator interface.
type Mutator struct {
	mod *Module
}

// NewMutator wraps a compiled WASM module as a ResponseMutator.
func NewMutator(mod *Module) *Mutator {
	return &Mutator{mod: mod}
}

func (m *Mutator) Name() string { return m.mod.name }

// Mutate calls the guest "mutate" export with the serialized request,
// identity, and decision.
func (m *Mutator) Mutate(ctx context.Context, r *module.Request, id *module.Identity, d *module.Decision) error {
	req := mutateRequest{
		Method:          r.Method,
		Host:            r.Host,
		Path:            r.Path,
		Headers:         r.Headers,
		Subject:         id.Subject,
		Claims:          id.Claims,
		Allow:           d.Allow,
		ResponseHeaders: d.ResponseHeaders,
		UpstreamHeaders: d.UpstreamHeaders,
	}

	var resp mutateResponse
	if err := m.mod.callJSON(ctx, "mutate", &req, &resp); err != nil {
		return fmt.Errorf("wasm mutator %q: %w", m.mod.name, err)
	}

	if resp.Error != "" {
		return fmt.Errorf("wasm mutator %q: %s", m.mod.name, resp.Error)
	}

	// Apply header mutations from the guest.
	if len(resp.ResponseHeaders) > 0 {
		if d.ResponseHeaders == nil {
			d.ResponseHeaders = make(map[string]string)
		}
		for k, v := range resp.ResponseHeaders {
			d.ResponseHeaders[k] = v
		}
	}
	if len(resp.UpstreamHeaders) > 0 {
		if d.UpstreamHeaders == nil {
			d.UpstreamHeaders = make(map[string]string)
		}
		for k, v := range resp.UpstreamHeaders {
			d.UpstreamHeaders[k] = v
		}
	}
	return nil
}

// mutateRequest is the JSON payload sent to the WASM guest.
type mutateRequest struct {
	Method          string              `json:"method"`
	Host            string              `json:"host"`
	Path            string              `json:"path"`
	Headers         map[string][]string `json:"headers"`
	Subject         string              `json:"subject"`
	Claims          map[string]any      `json:"claims"`
	Allow           bool                `json:"allow"`
	ResponseHeaders map[string]string   `json:"response_headers,omitempty"`
	UpstreamHeaders map[string]string   `json:"upstream_headers,omitempty"`
}

// mutateResponse is the JSON payload returned by the WASM guest.
type mutateResponse struct {
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	UpstreamHeaders map[string]string `json:"upstream_headers,omitempty"`
	Error           string            `json:"error,omitempty"`
}
