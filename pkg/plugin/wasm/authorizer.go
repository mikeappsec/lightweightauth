// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package wasm

import (
	"context"
	"fmt"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// Authorizer adapts a WASM module to the module.Authorizer interface.
type Authorizer struct {
	mod *Module
}

// NewAuthorizer wraps a compiled WASM module as an Authorizer.
func NewAuthorizer(mod *Module) *Authorizer {
	return &Authorizer{mod: mod}
}

func (a *Authorizer) Name() string { return a.mod.name }

// Authorize calls the guest "authorize" export with the serialized request
// and identity.
func (a *Authorizer) Authorize(ctx context.Context, r *module.Request, id *module.Identity) (*module.Decision, error) {
	req := authorizeRequest{
		Method:  r.Method,
		Host:    r.Host,
		Path:    r.Path,
		Headers: r.Headers,
		Subject: id.Subject,
		Claims:  id.Claims,
	}

	var resp authorizeResponse
	if err := a.mod.callJSON(ctx, "authorize", &req, &resp); err != nil {
		return nil, fmt.Errorf("wasm authorizer %q: %w", a.mod.name, err)
	}

	if resp.Error != "" {
		return nil, fmt.Errorf("wasm authorizer %q: %s", a.mod.name, resp.Error)
	}

	return &module.Decision{
		Allow:  resp.Allow,
		Status: resp.Status,
		Reason: resp.Reason,
	}, nil
}

// authorizeRequest is the JSON payload sent to the WASM guest.
type authorizeRequest struct {
	Method  string              `json:"method"`
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
	Subject string              `json:"subject"`
	Claims  map[string]any      `json:"claims"`
}

// authorizeResponse is the JSON payload returned by the WASM guest.
type authorizeResponse struct {
	Allow  bool   `json:"allow"`
	Status int    `json:"status,omitempty"`
	Reason string `json:"reason,omitempty"`
	Error  string `json:"error,omitempty"`
}
