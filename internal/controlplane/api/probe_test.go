// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHandleProbeURL_RejectsHostnameResolvingToLoopback is a regression
// test for the SSRF gap where isBlockedHost only checked IP literals and a
// static hostname list, never resolving DNS — so an attacker-controlled
// hostname that wasn't itself an IP literal or on the static list, but
// resolved to a loopback/link-local/metadata address, passed straight
// through. "localhost" is not in ssrf.go's isMetadataHost static list, so
// blocking it here can only happen via validateHost's actual net.LookupIP
// resolution path, not a string match — this exercises the real fix. It
// resolves via the OS hosts mechanism, so no live network access is needed.
func TestHandleProbeURL_RejectsHostnameResolvingToLoopback(t *testing.T) {
	t.Parallel()
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/v1/controlplane/probe/url?url=https://localhost/", nil)
	w := httptest.NewRecorder()
	s.handleProbeURL(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (localhost resolves to loopback and must be rejected)", w.Code, http.StatusBadRequest)
	}
}

func TestHandleProbeURL_RejectsIPLiteralMetadataHost(t *testing.T) {
	t.Parallel()
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/v1/controlplane/probe/url?url=https://169.254.169.254/latest/meta-data/", nil)
	w := httptest.NewRecorder()
	s.handleProbeURL(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (metadata IP literal must be rejected)", w.Code, http.StatusBadRequest)
	}
}

func TestHandleProbeURL_RejectsIPLiteralLoopback(t *testing.T) {
	t.Parallel()
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/v1/controlplane/probe/url?url=https://127.0.0.1/", nil)
	w := httptest.NewRecorder()
	s.handleProbeURL(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (loopback IP literal must be rejected)", w.Code, http.StatusBadRequest)
	}
}

func TestHandleProbeURL_RejectsNonHTTPS(t *testing.T) {
	t.Parallel()
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/v1/controlplane/probe/url?url=http://example.com/", nil)
	w := httptest.NewRecorder()
	s.handleProbeURL(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (non-https must be rejected)", w.Code, http.StatusBadRequest)
	}
}

func TestHandleProbeURL_MissingURLParam(t *testing.T) {
	t.Parallel()
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/v1/controlplane/probe/url", nil)
	w := httptest.NewRecorder()
	s.handleProbeURL(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}
