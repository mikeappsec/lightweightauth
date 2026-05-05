// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package connpool

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"
)

// GRPCConfig describes a pooled gRPC connection.
type GRPCConfig struct {
	// Address is the target (host:port or unix://path).
	Address string

	// Insecure disables TLS (dev only).
	Insecure bool

	// TLSCAFile is the CA bundle path for server verification.
	TLSCAFile string

	// TLSCertFile + TLSKeyFile enable mutual TLS.
	TLSCertFile string
	TLSKeyFile  string

	// ServerName overrides the TLS SNI.
	ServerName string
}

func grpcKey(cfg GRPCConfig) string {
	h := sha256.New()
	hashField(h, []byte(cfg.Address))
	hashField(h, []byte(cfg.TLSCAFile))
	hashField(h, []byte(cfg.TLSCertFile))
	hashField(h, []byte(cfg.TLSKeyFile))
	hashField(h, []byte(cfg.ServerName))
	if cfg.Insecure {
		h.Write([]byte("insecure"))
	}
	return "grpc:" + hex.EncodeToString(h.Sum(nil))[:16]
}

var grpcPool = struct {
	mu    sync.Mutex
	conns map[string]*grpc.ClientConn
}{conns: map[string]*grpc.ClientConn{}}

// GetGRPC returns a shared *grpc.ClientConn for the given config.
// Connections targeting the same address + credentials share an HTTP/2
// stream pool. The caller MUST NOT close the returned connection.
func GetGRPC(cfg GRPCConfig, extraOpts ...grpc.DialOption) (*grpc.ClientConn, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("connpool/grpc: address is required")
	}

	key := grpcKey(cfg)

	grpcPool.mu.Lock()
	defer grpcPool.mu.Unlock()

	if cc, ok := grpcPool.conns[key]; ok {
		return cc, nil
	}

	creds, err := buildGRPCCreds(cfg)
	if err != nil {
		return nil, err
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1 << 20)), // 1 MiB
	}
	opts = append(opts, extraOpts...)

	cc, err := grpc.NewClient(cfg.Address, opts...)
	if err != nil {
		return nil, fmt.Errorf("connpool/grpc: dial %s: %w", cfg.Address, err)
	}
	grpcPool.conns[key] = cc
	return cc, nil
}

func buildGRPCCreds(cfg GRPCConfig) (credentials.TransportCredentials, error) {
	if cfg.Insecure {
		return grpcinsecure.NewCredentials(), nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.ServerName != "" {
		tlsCfg.ServerName = cfg.ServerName
	}
	if cfg.TLSCAFile != "" {
		pem, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("connpool/grpc: caFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("connpool/grpc: caFile %q: no PEM certs found", cfg.TLSCAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("connpool/grpc: keypair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return credentials.NewTLS(tlsCfg), nil
}

// ResetGRPCForTest closes and removes all pooled gRPC connections.
func ResetGRPCForTest() {
	grpcPool.mu.Lock()
	defer grpcPool.mu.Unlock()
	for k, cc := range grpcPool.conns {
		cc.Close()
		delete(grpcPool.conns, k)
	}
}
