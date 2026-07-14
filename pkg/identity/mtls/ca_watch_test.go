// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package mtls

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// TestMTLS_CAWatch_HotReload starts an mtls identifier with watchCAFile:
// true, rewrites the CA bundle file on disk (simulating a CA rotation),
// and asserts a cert from the new CA is accepted — and a cert from the old
// CA is rejected — without rebuilding the identifier. This is the
// regression test for wiring CABundleWatcher into the live factory: prior
// to this, factory() always called the static, one-shot loadCAPool() and
// a CA file change on disk had no effect until process restart.
func TestMTLS_CAWatch_HotReload(t *testing.T) {
	t.Parallel()
	caPEM1, leafPEM1, _ := makeCAandLeaf(t, "CA-One", "alice", "")
	caPEM2, leafPEM2, _ := makeCAandLeaf(t, "CA-Two", "bob", "")

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, []byte(caPEM1), 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}

	id, err := factory("mtls", map[string]any{
		"trustForwardedClientCert": true,
		"trustedCAFiles":           []any{caFile},
		"watchCAFile":              true,
	}, module.Deps{Ctx: context.Background()})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	xfcc1 := `Cert="` + url.QueryEscape(leafPEM1) + `"`
	if _, err := id.Identify(context.Background(), &module.Request{
		Headers: map[string][]string{"X-Forwarded-Client-Cert": {xfcc1}},
	}); err != nil {
		t.Fatalf("cert from CA1 should be accepted before reload: %v", err)
	}

	// Rewrite the CA file to CA-Two only, simulating a full rotation.
	if err := os.WriteFile(caFile, []byte(caPEM2), 0o600); err != nil {
		t.Fatalf("rewrite ca file: %v", err)
	}

	xfcc2 := `Cert="` + url.QueryEscape(leafPEM2) + `"`
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		_, lastErr = id.Identify(context.Background(), &module.Request{
			Headers: map[string][]string{"X-Forwarded-Client-Cert": {xfcc2}},
		})
		if lastErr == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("cert from CA2 should be accepted after hot-reload (fsnotify event not observed in time): %v", lastErr)
	}

	// The old CA's cert must now be rejected -- the file was replaced,
	// not appended to.
	if _, err := id.Identify(context.Background(), &module.Request{
		Headers: map[string][]string{"X-Forwarded-Client-Cert": {xfcc1}},
	}); !errors.Is(err, module.ErrInvalidCredential) {
		t.Errorf("err = %v, want ErrInvalidCredential (old CA must be rejected after rotation)", err)
	}
}
