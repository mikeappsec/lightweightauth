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
//	    _ "github.com/mikeappsec/lightweightauth/pkg/builtins"
//	    _ "example.com/my-plugins/foo"        // your plugin
//	    "github.com/mikeappsec/lightweightauth/pkg/lwauthd"
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

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/pipeline"
	"github.com/mikeappsec/lightweightauth/internal/server"
)

// Options configure a Run invocation.
type Options struct {
	// ConfigPath points at the AuthConfig YAML to load on startup.
	// Required when WatchNamespace is empty (file mode).
	ConfigPath string

	// HTTPAddr / GRPCAddr — set to "" to disable.
	HTTPAddr string // Default ":8080".
	GRPCAddr string // Default ":9001".

	// WatchConfigFile, if true, starts an fsnotify watcher on
	// ConfigPath that hot-reloads the engine on every change. Cheap;
	// safe to leave on. Default: false (M4 keeps it explicit).
	WatchConfigFile bool

	// WatchNamespace, if non-empty, switches lwauthd into Kubernetes
	// CRD mode: a controller-runtime manager is booted and the
	// AuthConfig identified by AuthConfigName in this namespace is
	// reconciled into the engine on every change. ConfigPath is
	// ignored in this mode (the initial engine starts empty until the
	// first reconcile completes).
	WatchNamespace string
	AuthConfigName string

	Logger *slog.Logger
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

	// Three sources of an Engine, mutually exclusive:
	//   1. WatchNamespace set  -> CRD mode; engine starts empty,
	//      first Reconcile installs it.
	//   2. ConfigPath set      -> file mode; load once, optionally
	//      fsnotify-watch.
	//   3. neither             -> error: nothing to compile.
	var holder *server.EngineHolder
	switch {
	case opts.WatchNamespace != "":
		if opts.ConfigPath != "" && opts.WatchConfigFile {
			return errOptionsConflict
		}
		holder = server.NewEngineHolder(nil)
	case opts.ConfigPath != "":
		eng, err := LoadEngine(opts.ConfigPath)
		if err != nil {
			return err
		}
		holder = server.NewEngineHolder(eng)
	default:
		return errors.New("lwauthd: must set either ConfigPath or WatchNamespace")
	}

	errCh := make(chan error, 3)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if opts.WatchConfigFile && opts.ConfigPath != "" {
		if err := startFileWatcher(ctx, log, opts.ConfigPath, holder); err != nil {
			return err
		}
		log.Info("file watcher started", "path", opts.ConfigPath)
	}
	if opts.WatchNamespace != "" {
		if err := startCRDController(ctx, log, opts, holder, errCh); err != nil {
			return err
		}
	}

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

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	go grpcSrv.GracefulStop()
	return httpSrv.Shutdown(shutdownCtx)
}

// Main is a convenience entrypoint that parses the standard --config /
// --http-addr / --grpc-addr / --watch-* flags and calls Run. Equivalent
// to cmd/lwauth's main().
func Main() {
	cfgPath := flag.String("config", "config.yaml", "path to AuthConfig YAML (file mode)")
	httpAddr := flag.String("http-addr", ":8080", "HTTP listen address ('' to disable)")
	grpcAddr := flag.String("grpc-addr", ":9001", "gRPC listen address ('' to disable)")
	watchFile := flag.Bool("watch-config-file", false, "fsnotify-watch --config and reload on change")
	watchNS := flag.String("watch-namespace", "", "Kubernetes namespace to watch for AuthConfig CRs (enables CRD mode)")
	acName := flag.String("authconfig-name", "default", "name of the AuthConfig CR to reconcile (CRD mode)")
	flag.Parse()
	if err := Run(Options{
		ConfigPath:      *cfgPath,
		HTTPAddr:        *httpAddr,
		GRPCAddr:        *grpcAddr,
		WatchConfigFile: *watchFile,
		WatchNamespace:  *watchNS,
		AuthConfigName:  *acName,
	}); err != nil {
		slog.Error("lwauthd", "err", err)
		os.Exit(1)
	}
}
