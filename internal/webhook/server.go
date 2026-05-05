// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// ServerConfig configures the webhook HTTPS server.
type ServerConfig struct {
	// Addr is the listen address (e.g. ":9443").
	Addr string
	// CertFile is the path to the TLS certificate PEM.
	CertFile string
	// KeyFile is the path to the TLS private key PEM.
	KeyFile string
	// Logger for server events.
	Logger *slog.Logger
}

// Server is the admission webhook HTTPS server.
type Server struct {
	httpServer *http.Server
	log        *slog.Logger
}

// NewServer creates a webhook server with the given handler and TLS config.
func NewServer(cfg ServerConfig, handler http.Handler) (*Server, error) {
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("webhook: certFile and keyFile are required")
	}
	if cfg.Addr == "" {
		cfg.Addr = ":9443"
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("webhook: load TLS keypair: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	mux := http.NewServeMux()
	mux.Handle("/validate-authconfig", handler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	return &Server{
		httpServer: &http.Server{
			Addr:              cfg.Addr,
			Handler:           mux,
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
		log: log,
	}, nil
}

// Start runs the webhook server. Blocks until the context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("webhook server starting", "addr", s.httpServer.Addr)
		// TLS is configured via s.httpServer.TLSConfig, so pass empty
		// cert/key paths to ListenAndServeTLS.
		if err := s.httpServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
