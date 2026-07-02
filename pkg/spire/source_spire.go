// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build spire

package spire

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// fetchSVIDFromWorkloadAPI connects to SPIRE and fetches the initial X.509-SVID.
func fetchSVIDFromWorkloadAPI(ctx context.Context, s *Source) error {
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(s.cfg.SocketPath))
	if err != nil {
		return fmt.Errorf("connect to SPIRE agent: %w", err)
	}
	defer client.Close()

	x509Ctx, err := client.FetchX509Context(ctx)
	if err != nil {
		return fmt.Errorf("fetch X.509 context: %w", err)
	}

	if len(x509Ctx.SVIDs) == 0 {
		return fmt.Errorf("no SVIDs received from SPIRE")
	}

	svid := x509Ctx.SVIDs[0]

	// Build tls.Certificate from the SVID.
	tlsCert := &tls.Certificate{
		Certificate: make([][]byte, len(svid.Certificates)),
		PrivateKey:  svid.PrivateKey,
		Leaf:        svid.Certificates[0],
	}
	for i, cert := range svid.Certificates {
		tlsCert.Certificate[i] = cert.Raw
	}

	// Build trust bundle.
	bundle := x509.NewCertPool()
	for _, b := range x509Ctx.Bundles.Bundles() {
		for _, cert := range b.X509Authorities() {
			bundle.AddCert(cert)
		}
	}

	// Validate trust domain if configured.
	spiffeID := svid.ID.String()
	if s.cfg.TrustDomain != "" {
		if svid.ID.TrustDomain().String() != s.cfg.TrustDomain {
			return fmt.Errorf("SVID trust domain %q does not match expected %q",
				svid.ID.TrustDomain(), s.cfg.TrustDomain)
		}
	}

	s.updateSVID(tlsCert, bundle, spiffeID)
	return nil
}

// watchSVIDUpdates uses the SPIRE Workload API to watch for SVID rotation.
func watchSVIDUpdates(ctx context.Context, s *Source) {
	err := workloadapi.WatchX509Context(ctx, &x509Watcher{source: s}, workloadapi.WithAddr(s.cfg.SocketPath))
	if err != nil && ctx.Err() == nil {
		slog.Error("spire: X509 watcher stopped unexpectedly", "error", err)
	}
}

// x509Watcher implements workloadapi.X509ContextWatcher.
type x509Watcher struct {
	source *Source
}

func (w *x509Watcher) OnX509ContextUpdate(x509Ctx *workloadapi.X509Context) {
	if len(x509Ctx.SVIDs) == 0 {
		slog.Warn("spire: received empty SVID update")
		return
	}

	svid := x509Ctx.SVIDs[0]

	tlsCert := &tls.Certificate{
		Certificate: make([][]byte, len(svid.Certificates)),
		PrivateKey:  svid.PrivateKey,
		Leaf:        svid.Certificates[0],
	}
	for i, cert := range svid.Certificates {
		tlsCert.Certificate[i] = cert.Raw
	}

	bundle := x509.NewCertPool()
	for _, b := range x509Ctx.Bundles.Bundles() {
		for _, cert := range b.X509Authorities() {
			bundle.AddCert(cert)
		}
	}

	spiffeID := svid.ID.String()

	// Validate trust domain if configured.
	if w.source.cfg.TrustDomain != "" {
		if svid.ID.TrustDomain().String() != w.source.cfg.TrustDomain {
			slog.Error("spire: received SVID with unexpected trust domain",
				"got", svid.ID.TrustDomain(), "expected", w.source.cfg.TrustDomain)
			return
		}
	}

	w.source.updateSVID(tlsCert, bundle, spiffeID)
}

func (w *x509Watcher) OnX509ContextWatchError(err error) {
	slog.Error("spire: X509 context watch error", "error", err)
}
