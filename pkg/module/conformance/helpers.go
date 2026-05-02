// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"fmt"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func mustNotPanic(t *testing.T, what string) {
	t.Helper()
	if r := recover(); r != nil {
		t.Fatalf("%s panicked: %v", what, r)
	}
}

func panicErr(r any) error {
	return fmt.Errorf("panic: %v", r)
}

// cloneRequest returns a shallow copy with deep-copied maps so the harness
// can hand a fresh *Request to every parallel goroutine without sharing
// the Headers / Context maps.
func cloneRequest(r *module.Request) *module.Request {
	if r == nil {
		return nil
	}
	cp := *r
	if r.Headers != nil {
		cp.Headers = make(map[string][]string, len(r.Headers))
		for k, v := range r.Headers {
			vs := make([]string, len(v))
			copy(vs, v)
			cp.Headers[k] = vs
		}
	}
	if r.Context != nil {
		cp.Context = make(map[string]any, len(r.Context))
		for k, v := range r.Context {
			cp.Context[k] = v
		}
	}
	if r.Body != nil {
		cp.Body = append([]byte(nil), r.Body...)
	}
	return &cp
}

func cloneIdentity(id *module.Identity) *module.Identity {
	if id == nil {
		return nil
	}
	cp := *id
	if id.Claims != nil {
		cp.Claims = make(map[string]any, len(id.Claims))
		for k, v := range id.Claims {
			cp.Claims[k] = v
		}
	}
	return &cp
}

func cloneDecision(d *module.Decision) *module.Decision {
	if d == nil {
		return nil
	}
	cp := *d
	if d.ResponseHeaders != nil {
		cp.ResponseHeaders = make(map[string]string, len(d.ResponseHeaders))
		for k, v := range d.ResponseHeaders {
			cp.ResponseHeaders[k] = v
		}
	}
	if d.UpstreamHeaders != nil {
		cp.UpstreamHeaders = make(map[string]string, len(d.UpstreamHeaders))
		for k, v := range d.UpstreamHeaders {
			cp.UpstreamHeaders[k] = v
		}
	}
	return &cp
}
