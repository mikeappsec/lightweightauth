// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package opa is the embedded OPA / Rego authorizer (DESIGN.md §5).
//
// Config shape:
//
//	authorizers:
//	  - name: opa
//	    type: opa
//	    config:
//	      query: data.authz.allow      # default
//	      rego: |
//	        package authz
//	        default allow = false
//	        allow { input.identity.claims.role == "admin" }
//
// The Rego module is compiled once at factory time (config reload makes a
// fresh authorizer). Per-request evaluation runs a prepared query so the
// hot path does no compilation.
//
// `input` exposes:
//
//	input.identity = {subject, claims, source}
//	input.request  = {method, host, path, headers, tenantId}
//	input.context  = arbitrary map populated by earlier pipeline stages
package opa

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

const defaultQuery = "data.authz.allow"

type authorizer struct {
	name     string
	prepared rego.PreparedEvalQuery
}

func (a *authorizer) Name() string { return a.name }

func (a *authorizer) Authorize(ctx context.Context, r *module.Request, id *module.Identity) (*module.Decision, error) {
	input := buildInput(r, id)
	rs, err := a.prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("%w: opa eval: %v", module.ErrUpstream, err)
	}
	if !rs.Allowed() {
		return &module.Decision{
			Allow:  false,
			Status: 403,
			Reason: fmt.Sprintf("opa: query %q denied", defaultQuery),
		}, nil
	}
	return &module.Decision{Allow: true}, nil
}

func buildInput(r *module.Request, id *module.Identity) map[string]any {
	idIn := map[string]any{}
	if id != nil {
		idIn["subject"] = id.Subject
		idIn["source"] = id.Source
		if id.Claims != nil {
			idIn["claims"] = id.Claims
		} else {
			idIn["claims"] = map[string]any{}
		}
	}
	reqIn := map[string]any{
		"method":   r.Method,
		"host":     r.Host,
		"path":     r.Path,
		"tenantId": r.TenantID,
	}
	if r.Headers != nil {
		// Flatten to first-value strings; OPA-side rules rarely care
		// about repeated headers.
		hdrs := make(map[string]string, len(r.Headers))
		for k, vs := range r.Headers {
			if len(vs) > 0 {
				hdrs[k] = vs[0]
			}
		}
		reqIn["headers"] = hdrs
	}
	ctxIn := r.Context
	if ctxIn == nil {
		ctxIn = map[string]any{}
	}
	return map[string]any{
		"identity": idIn,
		"request":  reqIn,
		"context":  ctxIn,
	}
}

func factory(name string, raw map[string]any) (module.Authorizer, error) {
	src, _ := raw["rego"].(string)
	if src == "" {
		return nil, fmt.Errorf("%w: opa %q: rego source is required", module.ErrConfig, name)
	}
	query, _ := raw["query"].(string)
	if query == "" {
		query = defaultQuery
	}
	r := rego.New(
		rego.Query(query),
		rego.Module(fmt.Sprintf("%s.rego", name), src),
	)
	prepared, err := r.PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("%w: opa %q: compile: %v", module.ErrConfig, name, err)
	}
	return &authorizer{name: name, prepared: prepared}, nil
}

func init() { module.RegisterAuthorizer("opa", factory) }
