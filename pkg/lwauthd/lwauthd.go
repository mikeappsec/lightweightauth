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
	"fmt"
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

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	"github.com/mikeappsec/lightweightauth/internal/admin"
	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/pipeline"
	"github.com/mikeappsec/lightweightauth/internal/server"
	"github.com/mikeappsec/lightweightauth/pkg/buildinfo"
	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"
	"github.com/mikeappsec/lightweightauth/pkg/observability/metrics"
)

// Options configure a Run invocation.
type Options struct {
	// ConfigPath points at the AuthConfig YAML to load on startup.
	// Required when WatchNamespace is empty (file mode).
	ConfigPath string

	// HTTPAddr / GRPCAddr — set to "" to disable.
	HTTPAddr string // Default ":8080".
	GRPCAddr string // Default ":9001".

	// --- Listener hardening ---
	//
	// TLSCertFile / TLSKeyFile enable TLS on the HTTP listener. When
	// both are set, ListenAndServeTLS is used; otherwise the server
	// listens in plaintext (test/dev only).
	TLSCertFile string
	TLSKeyFile  string
	// TLSClientCAFile, when set, requires every HTTP client to present
	// a certificate chained to one of these CAs (mTLS).
	TLSClientCAFile string

	// GRPCTLSCertFile / GRPCTLSKeyFile / GRPCTLSClientCAFile do the
	// same for the gRPC listener (Envoy ext_authz + native Auth +
	// health + reflection).
	GRPCTLSCertFile     string
	GRPCTLSKeyFile      string
	GRPCTLSClientCAFile string

	// EnableReflection registers grpc_reflection on the gRPC server.
	// Defaults to false in production: reflection lets a network-
	// reachable client enumerate every RPC, which is nice in dev and
	// dangerous in prod.
	EnableReflection bool

	// DisableHTTPAuthorize removes /v1/authorize. Operators who only
	// use the gRPC ext_authz path can shrink the public surface.
	DisableHTTPAuthorize bool
	// DisableHTTPMetrics removes /metrics from the public listener.
	DisableHTTPMetrics bool
	// DisableHTTPOpenAPI removes /openapi.json and /openapi.yaml from
	// the public listener. The endpoints sit on the same mux as
	// /metrics, so operators who keep observability internal will
	// usually disable both. DOC-OPENAPI-1.
	DisableHTTPOpenAPI bool

	// Admin configures the admin-plane authentication and
	// authorization model (OPS-ADMIN-1). When Admin.Enabled is true,
	// endpoints under /v1/admin/ are registered on the HTTP listener,
	// protected by mTLS and/or admin JWT with RBAC verbs.
	Admin admin.Config

	// MaxRequestBytes caps inbound /v1/authorize bodies. 0 -> 1 MiB.
	MaxRequestBytes int64

	// HTTP server timeouts. Zero values pick safe defaults.
	HTTPReadHeaderTimeout time.Duration // default 10s
	HTTPReadTimeout       time.Duration // default 30s
	HTTPWriteTimeout      time.Duration // default 30s
	HTTPIdleTimeout       time.Duration // default 120s
	HTTPMaxHeaderBytes    int           // default 1 MiB

	// gRPC server connection-management knobs (F14). Zero values
	// pick safe defaults that match the HTTP listener guards. See
	// [buildGRPCServerOptions] for the wiring; they bound how long
	// an idle / long-lived / silent gRPC connection can hold a
	// server goroutine and FD.
	GRPCKeepaliveMinTime       time.Duration // default 30s  (enforcement: client ping floor)
	GRPCKeepaliveTime          time.Duration // default 1m   (server-initiated ping period)
	GRPCKeepaliveTimeout       time.Duration // default 20s  (server ping ack deadline)
	GRPCMaxConnectionIdle      time.Duration // default 5m   (close idle conns after)
	GRPCMaxConnectionAge       time.Duration // default 30m  (rotate any conn after)
	GRPCMaxConnectionAgeGrace  time.Duration // default 30s  (graceful close window)
	GRPCMaxConcurrentStreams   int           // default 1024 (HTTP/2 streams per conn)

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

	// --- Leader election (ENT-HA-1) ---

	// LeaderElection enables controller-runtime leader election for the
	// CRD reconciler. Only the elected leader runs the reconciler and
	// publishes config; followers receive config via configstream and
	// serve auth requests (active/active).
	LeaderElection bool
	// LeaderElectionID is the Lease resource name. Default "lwauth-controller-leader".
	LeaderElectionID string
	// LeaderElectionNamespace overrides where the Lease lives. Defaults
	// to WatchNamespace.
	LeaderElectionNamespace string
	// LeaseDuration, RenewDeadline, RetryPeriod tune election timing.
	// Defaults: 15s / 10s / 2s (controller-runtime defaults).
	LeaseDuration time.Duration
	RenewDeadline time.Duration
	RetryPeriod   time.Duration

	// ConfigStreamAddr is the gRPC address of the leader's configstream
	// endpoint (e.g. "lwauth-headless:9001"). When LeaderElection is
	// enabled and this pod is not the leader, it subscribes here to
	// receive config snapshots. Required for active/active HA.
	ConfigStreamAddr string
	// ConfigStreamNodeID identifies this pod in the configstream
	// subscription. Defaults to hostname.
	ConfigStreamNodeID string

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
	// K-CRYPTO-2: surface the build identity (version, commit, go
	// runtime, FIPS status) at startup. Operators alerting on a
	// FIPS-only namespace cross-check this against the
	// `lwauth_fips_enabled` Prometheus gauge.
	log.Info("lwauth starting",
		"version", buildinfo.Version,
		"commit", buildinfo.Commit,
		"go_version", buildinfo.GoVersion(),
		"fips_enabled", buildinfo.FIPSEnabled(),
	)
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

	// Observability defaults (M9).
	//
	// Audit: emit one JSON line per terminal decision through the same
	// slog logger Run uses, so audit + operational logs land on the same
	// transport (stderr by default; operators redirect with a Handler).
	// Operators who want a separate audit sink call audit.SetDefault
	// from their main() before invoking Run.
	if audit.Default() == audit.Discard {
		audit.SetDefault(audit.NewSlogSink(log))
	}
	// Cache stats: bind decision-cache live counters to Prometheus once
	// at startup. The closures dereference the current Engine on every
	// scrape, so hot-reload replaces the underlying *cache.Stats
	// transparently. Counters are monotonic across reloads from the
	// scraper's POV — the kernel of an ENG hot-swap doesn't reset
	// previously observed values because we register CounterFuncs that
	// remember nothing themselves.
	registerDecisionCacheStats(holder)
	registerTieredCacheStats(holder)

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
	httpHandler := server.NewHTTPHandlerWithOptions(holder, server.HTTPHandlerOptions{
		MaxRequestBytes:  opts.MaxRequestBytes,
		DisableAuthorize: opts.DisableHTTPAuthorize,
		DisableMetrics:   opts.DisableHTTPMetrics,
		DisableOpenAPI:   opts.DisableHTTPOpenAPI,
	})

	// Admin endpoints (OPS-ADMIN-1). When enabled, /v1/admin/* routes
	// are mounted on the same HTTP listener, guarded by the admin
	// middleware (mTLS or admin JWT + RBAC verbs).
	var finalHandler http.Handler = httpHandler
	if opts.Admin.Enabled {
		opts.Admin.Logger = log
		adminMW, err := admin.NewMiddleware(opts.Admin)
		if err != nil {
			return fmt.Errorf("admin middleware: %w", err)
		}
		adminMux := admin.NewAdminMux(adminMW, nil)
		// Compose: requests starting with /v1/admin/ go to the admin
		// mux; everything else goes to the normal handler.
		combined := http.NewServeMux()
		combined.Handle("/v1/admin/", adminMux)
		combined.Handle("/", httpHandler)
		finalHandler = combined
	}
	httpSrv := &http.Server{
		Addr:              opts.HTTPAddr,
		Handler:           finalHandler,
		ReadHeaderTimeout: nonZeroDur(opts.HTTPReadHeaderTimeout, 10*time.Second),
		ReadTimeout:       nonZeroDur(opts.HTTPReadTimeout, 30*time.Second),
		WriteTimeout:      nonZeroDur(opts.HTTPWriteTimeout, 30*time.Second),
		IdleTimeout:       nonZeroDur(opts.HTTPIdleTimeout, 120*time.Second),
		MaxHeaderBytes:    nonZeroInt(opts.HTTPMaxHeaderBytes, 1<<20),
	}
	httpTLS, err := buildServerTLS(opts.TLSCertFile, opts.TLSKeyFile, opts.TLSClientCAFile)
	if err != nil {
		return fmt.Errorf("http tls: %w", err)
	}
	if httpTLS != nil {
		httpSrv.TLSConfig = httpTLS
	}
	go func() {
		log.Info("http listening", "addr", opts.HTTPAddr, "tls", httpTLS != nil, "mtls", opts.TLSClientCAFile != "")
		var serveErr error
		if httpTLS != nil {
			// Cert/key already loaded into TLSConfig.Certificates; pass
			// empty file paths so net/http doesn't reload them.
			serveErr = httpSrv.ListenAndServeTLS("", "")
		} else {
			serveErr = httpSrv.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
	}()

	// gRPC: Envoy ext_authz + standard health + (optional) reflection.
	lis, err := net.Listen("tcp", opts.GRPCAddr)
	if err != nil {
		_ = httpSrv.Close()
		return err
	}
	grpcOpts, err := buildGRPCServerOptions(opts)
	if err != nil {
		_ = httpSrv.Close()
		_ = lis.Close()
		return fmt.Errorf("grpc tls: %w", err)
	}
	grpcSrv := grpc.NewServer(grpcOpts...)
	authv3.RegisterAuthorizationServer(grpcSrv, &server.ExtAuthzServer{Engines: holder, MaxRequestBytes: opts.MaxRequestBytes})
	authv1.RegisterAuthServer(grpcSrv, &server.NativeAuthServer{Engines: holder, MaxRequestBytes: opts.MaxRequestBytes})

	hs := health.NewServer()
	hs.SetServingStatus("envoy.service.auth.v3.Authorization", healthpb.HealthCheckResponse_SERVING)
	hs.SetServingStatus("lightweightauth.v1.Auth", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcSrv, hs)

	if opts.EnableReflection {
		reflection.Register(grpcSrv)
	}

	go func() {
		log.Info("grpc listening", "addr", opts.GRPCAddr,
			"tls", opts.GRPCTLSCertFile != "",
			"mtls", opts.GRPCTLSClientCAFile != "",
			"reflection", opts.EnableReflection)
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
// --http-addr / --grpc-addr / --watch-* / --tls-* / --enable-reflection
// flags and calls Run. Equivalent to cmd/lwauth's main().
func Main() {
	cfgPath := flag.String("config", "config.yaml", "path to AuthConfig YAML (file mode)")
	httpAddr := flag.String("http-addr", ":8080", "HTTP listen address ('' to disable)")
	grpcAddr := flag.String("grpc-addr", ":9001", "gRPC listen address ('' to disable)")
	watchFile := flag.Bool("watch-config-file", false, "fsnotify-watch --config and reload on change")
	watchNS := flag.String("watch-namespace", "", "Kubernetes namespace to watch for AuthConfig CRs (enables CRD mode)")
	acName := flag.String("authconfig-name", "default", "name of the AuthConfig CR to reconcile (CRD mode)")
	httpCert := flag.String("tls-cert", "", "PEM cert file for HTTP TLS (leave empty for plaintext)")
	httpKey := flag.String("tls-key", "", "PEM key file for HTTP TLS")
	httpClientCA := flag.String("tls-client-ca", "", "PEM CA file; if set, HTTP requires client certs (mTLS)")
	grpcCert := flag.String("grpc-tls-cert", "", "PEM cert file for gRPC TLS")
	grpcKey := flag.String("grpc-tls-key", "", "PEM key file for gRPC TLS")
	grpcClientCA := flag.String("grpc-tls-client-ca", "", "PEM CA file; if set, gRPC requires client certs (mTLS)")
	enableReflection := flag.Bool("enable-reflection", false, "register gRPC reflection (dev only)")
	disableAuthorize := flag.Bool("disable-http-authorize", false, "remove /v1/authorize from the HTTP mux")
	disableMetrics := flag.Bool("disable-http-metrics", false, "remove /metrics from the HTTP mux")
	disableOpenAPI := flag.Bool("disable-http-openapi", false, "remove /openapi.json and /openapi.yaml from the HTTP mux")
	maxBody := flag.Int64("max-request-bytes", 0, "cap on /v1/authorize body bytes (0 -> 1 MiB)")
	printBuildInfo := flag.Bool("print-build-info", false, "print build attributes (version, commit, go runtime, FIPS mode) and exit")
	leaderElect := flag.Bool("leader-election", false, "enable controller leader election (HA mode)")
	leaderID := flag.String("leader-election-id", "lwauth-controller-leader", "Lease resource name for leader election")
	leaderNS := flag.String("leader-election-namespace", "", "namespace for Lease (defaults to --watch-namespace)")
	configStreamAddr := flag.String("config-stream-addr", "", "gRPC address for follower config subscription (e.g. lwauth-headless:9001)")
	configStreamNode := flag.String("config-stream-node-id", "", "node ID for configstream subscription (default: hostname)")
	flag.Parse()
	if *printBuildInfo {
		// Stable single-line format `version=... commit=... go_version=... fips_enabled=...`,
		// chosen so the Makefile's `make fips-verify` target can grep for
		// `fips_enabled=true` portably (no JSON parser needed in CI).
		fmt.Printf("version=%s commit=%s go_version=%s fips_enabled=%t\n",
			buildinfo.Version, buildinfo.Commit, buildinfo.GoVersion(), buildinfo.FIPSEnabled())
		return
	}
	if err := Run(Options{
		ConfigPath:           *cfgPath,
		HTTPAddr:             *httpAddr,
		GRPCAddr:             *grpcAddr,
		WatchConfigFile:      *watchFile,
		WatchNamespace:       *watchNS,
		AuthConfigName:       *acName,
		TLSCertFile:          *httpCert,
		TLSKeyFile:           *httpKey,
		TLSClientCAFile:      *httpClientCA,
		GRPCTLSCertFile:      *grpcCert,
		GRPCTLSKeyFile:       *grpcKey,
		GRPCTLSClientCAFile:  *grpcClientCA,
		EnableReflection:     *enableReflection,
		DisableHTTPAuthorize: *disableAuthorize,
		DisableHTTPMetrics:   *disableMetrics,
		DisableHTTPOpenAPI:   *disableOpenAPI,
		MaxRequestBytes:      *maxBody,
		LeaderElection:       *leaderElect,
		LeaderElectionID:     *leaderID,
		LeaderElectionNamespace: *leaderNS,
		ConfigStreamAddr:     *configStreamAddr,
		ConfigStreamNodeID:   *configStreamNode,
	}); err != nil {
		slog.Error("lwauthd", "err", err)
		os.Exit(1)
	}
}

// registerDecisionCacheStats binds the live atomic counters of the
// engine's decision cache to the process-wide metrics recorder.
//
// It is called once at startup. The closures dereference holder.Load()
// on every scrape, so an Engine swap (CRD reconcile, fsnotify reload)
// updates what Prometheus reads without re-registering. When no engine
// is loaded yet, or caching is disabled in this AuthConfig, the
// closures return 0 and the metric is harmless.
//
// Registration is idempotent across Run invocations in the same
// process: if MustRegister panics with AlreadyRegisteredError we ignore
// the second registration. Tests that exercise Run repeatedly need
// this.
func registerDecisionCacheStats(h *server.EngineHolder) {
	read := func(get func(*pipeline.Engine) uint64) func() uint64 {
		return func() uint64 {
			eng := h.Load()
			if eng == nil {
				return 0
			}
			return get(eng)
		}
	}
	defer func() {
		// MustRegister panics on duplicate. Tests boot Run repeatedly
		// against the default registry; recover so they don't crash.
		_ = recover()
	}()
	metrics.Default().RegisterCacheStats("decision",
		read(func(e *pipeline.Engine) uint64 {
			s := e.DecisionCacheStats()
			if s == nil {
				return 0
			}
			return s.Hits.Load()
		}),
		read(func(e *pipeline.Engine) uint64 {
			s := e.DecisionCacheStats()
			if s == nil {
				return 0
			}
			return s.Misses.Load()
		}),
		read(func(e *pipeline.Engine) uint64 {
			s := e.DecisionCacheStats()
			if s == nil {
				return 0
			}
			return s.Evictions.Load()
		}),
	)
}

// registerTieredCacheStats wires the E1 per-layer (L1/L2) counters into
// Prometheus. When the decision cache is not tiered, the closures return
// 0 and the series are dormant.
func registerTieredCacheStats(h *server.EngineHolder) {
	read := func(get func(*pipeline.Engine) uint64) func() uint64 {
		return func() uint64 {
			eng := h.Load()
			if eng == nil {
				return 0
			}
			return get(eng)
		}
	}
	defer func() {
		_ = recover() // duplicate registration across tests
	}()
	metrics.Default().RegisterTieredCacheStats("decision",
		read(func(e *pipeline.Engine) uint64 {
			s := e.DecisionCacheTieredStats()
			if s == nil {
				return 0
			}
			return s.L1Hits.Load()
		}),
		read(func(e *pipeline.Engine) uint64 {
			s := e.DecisionCacheTieredStats()
			if s == nil {
				return 0
			}
			return s.L1Misses.Load()
		}),
		read(func(e *pipeline.Engine) uint64 {
			s := e.DecisionCacheTieredStats()
			if s == nil {
				return 0
			}
			return s.L2Hits.Load()
		}),
		read(func(e *pipeline.Engine) uint64 {
			s := e.DecisionCacheTieredStats()
			if s == nil {
				return 0
			}
			return s.L2Misses.Load()
		}),
	)
}
