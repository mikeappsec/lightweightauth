package lwauthd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// buildServerTLS returns a *tls.Config for the HTTP listener, or nil
// when no cert/key were provided (plaintext mode). When clientCAFile
// is set, the server requires every client to present a certificate
// chained to that CA pool — full mTLS.
//
// Misconfigurations (cert without key, client CA without server cert,
// unreadable PEM) are rejected at startup so the listener never boots
// in a half-configured "looks like TLS but isn't" state.
func buildServerTLS(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		if clientCAFile != "" {
			return nil, errors.New("tlsClientCAFile set without tlsCertFile/tlsKeyFile")
		}
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("tlsCertFile and tlsKeyFile must both be set")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if clientCAFile != "" {
		pool, err := loadCAPool(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("load client CA: %w", err)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// buildGRPCServerOptions returns the grpc.ServerOption slice for the
// gRPC listener. When TLS is configured it adds credentials.NewTLS;
// when client CA is also set it requires mTLS. Always sets a
// transport-level MaxRecvMsgSize that matches the application-level
// body cap (F11), so the cap holds whether or not the per-RPC
// adapters get to it first.
func buildGRPCServerOptions(opts Options) ([]grpc.ServerOption, error) {
	tlsCfg, err := buildServerTLS(opts.GRPCTLSCertFile, opts.GRPCTLSKeyFile, opts.GRPCTLSClientCAFile)
	if err != nil {
		return nil, err
	}
	var out []grpc.ServerOption
	if tlsCfg != nil {
		out = append(out, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}
	// Match the HTTP cap. opts.MaxRequestBytes==0 -> 1 MiB default;
	// a negative value disables the cap (test-only) and we leave the
	// gRPC default in place.
	limit := opts.MaxRequestBytes
	if limit == 0 {
		limit = 1 << 20
	}
	if limit > 0 {
		out = append(out, grpc.MaxRecvMsgSize(int(limit)))
	}
	return out, nil
}

// loadCAPool reads a PEM-encoded CA bundle into an *x509.CertPool.
// Empty / non-PEM files are rejected so an operator can't accidentally
// disable client-cert verification by pointing at the wrong path.
func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certificates found in %s", path)
	}
	return pool, nil
}

// nonZeroDur returns d when non-zero, otherwise dflt.
func nonZeroDur(d, dflt time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return dflt
}

// nonZeroInt returns n when non-zero, otherwise dflt.
func nonZeroInt(n, dflt int) int {
	if n > 0 {
		return n
	}
	return dflt
}
