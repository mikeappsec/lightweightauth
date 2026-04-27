// Package lwauthd is the public embedding surface for downstream binaries
// that want to bundle lightweightauth with extra plugins. It re-exports
// just enough of the internal config + server packages so external code
// doesn't need to reach into "internal/".
//
// Usage:
//
//	package main
//
//	import (
//	    _ "github.com/yourorg/lightweightauth/pkg/builtins"
//	    _ "example.com/my-plugins/foo"        // your plugin
//	    "github.com/yourorg/lightweightauth/pkg/lwauthd"
//	)
//
//	func main() { lwauthd.Main() }            // or lwauthd.Run(opts)
package lwauthd

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/yourorg/lightweightauth/internal/config"
	"github.com/yourorg/lightweightauth/internal/pipeline"
	"github.com/yourorg/lightweightauth/internal/server"
)

// Options configure a Run invocation.
type Options struct {
	ConfigPath string
	HTTPAddr   string // "" to disable HTTP. Default ":8080".
	GRPCAddr   string // "" to disable gRPC. Default ":9001".
	Logger     *slog.Logger
}

// LoadEngine reads a YAML AuthConfig file and compiles it into a
// pipeline.Engine using the compile-time module registry. Useful for
// tests that want the engine without a live HTTP server.
func LoadEngine(path string) (*pipeline.Engine, error) {
	ac, err := config.LoadFile(path)
	if err != nil {
		return nil, err
	}
	return config.Compile(ac)
}

// Run boots HTTP and Envoy ext_authz gRPC servers fronting the pipeline.
// It blocks until SIGINT / SIGTERM, then performs a graceful shutdown.
//
// Plugins are registered at init() of their packages — Run does not know
// about them. Just blank-import the plugin package(s) from the binary
// that calls Run.
func Run(opts Options) error {
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	if opts.HTTPAddr == "" {
		opts.HTTPAddr = ":8080"
	}
	if opts.GRPCAddr == "" {
		opts.GRPCAddr = ":9001"
	}

	eng, err := LoadEngine(opts.ConfigPath)
	if err != nil {
		return err
	}
	holder := server.NewEngineHolder(eng)

	errCh := make(chan error, 2)

	// HTTP
	httpSrv := &http.Server{Addr: opts.HTTPAddr, Handler: server.NewHTTPHandler(holder)}
	go func() {
		log.Info("http listening", "addr", opts.HTTPAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// gRPC: Envoy ext_authz + standard health + reflection.
	lis, err := net.Listen("tcp", opts.GRPCAddr)
	if err != nil {
		_ = httpSrv.Close()
		return err
	}
	grpcSrv := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcSrv, server.NewExtAuthzServer(holder))

	hs := health.NewServer()
	hs.SetServingStatus("envoy.service.auth.v3.Authorization", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcSrv, hs)

	reflection.Register(grpcSrv)

	go func() {
		log.Info("grpc listening", "addr", opts.GRPCAddr)
		if err := grpcSrv.Serve(lis); err != nil {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		_ = httpSrv.Close()
		grpcSrv.Stop()
		return err
	case <-stop:
		log.Info("shutting down")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go grpcSrv.GracefulStop()
	return httpSrv.Shutdown(ctx)
}

// Main is a convenience entrypoint that parses the standard --config /
// --http-addr / --grpc-addr flags and calls Run. Equivalent to
// cmd/lwauth's main().
func Main() {
	cfgPath := flag.String("config", "config.yaml", "path to AuthConfig YAML")
	httpAddr := flag.String("http-addr", ":8080", "HTTP listen address ('' to disable)")
	grpcAddr := flag.String("grpc-addr", ":9001", "gRPC listen address ('' to disable)")
	flag.Parse()
	if err := Run(Options{
		ConfigPath: *cfgPath,
		HTTPAddr:   *httpAddr,
		GRPCAddr:   *grpcAddr,
	}); err != nil {
		slog.Error("lwauthd", "err", err)
		os.Exit(1)
	}
}
