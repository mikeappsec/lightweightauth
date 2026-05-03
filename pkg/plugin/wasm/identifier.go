// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package wasm

import (
	"context"
	"fmt"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// Identifier adapts a WASM module to the module.Identifier interface.
type Identifier struct {
	mod *Module
}

// NewIdentifier wraps a compiled WASM module as an Identifier.
func NewIdentifier(mod *Module) *Identifier {
	return &Identifier{mod: mod}
}

func (i *Identifier) Name() string { return i.mod.name }

// Identify calls the guest "identify" export with the serialized request.
func (i *Identifier) Identify(ctx context.Context, r *module.Request) (*module.Identity, error) {
	req := identifyRequest{
		Method:  r.Method,
		Host:    r.Host,
		Path:    r.Path,
		Headers: r.Headers,
	}

	var resp identifyResponse
	if err := i.mod.callJSON(ctx, "identify", &req, &resp); err != nil {
		return nil, fmt.Errorf("wasm identifier %q: %w", i.mod.name, err)
	}

	if resp.NoMatch {
		return nil, module.ErrNoMatch
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("wasm identifier %q: %s", i.mod.name, resp.Error)
	}

	return &module.Identity{
		Subject: resp.Subject,
		Claims:  resp.Claims,
		Source:  i.mod.name,
	}, nil
}

// identifyRequest is the JSON payload sent to the WASM guest.
type identifyRequest struct {
	Method  string              `json:"method"`
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
}

// identifyResponse is the JSON payload returned by the WASM guest.
type identifyResponse struct {
	Subject string         `json:"subject,omitempty"`
	Claims  map[string]any `json:"claims,omitempty"`
	NoMatch bool           `json:"no_match,omitempty"`
	Error   string         `json:"error,omitempty"`
}
