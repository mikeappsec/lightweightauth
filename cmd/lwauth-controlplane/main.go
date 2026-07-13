// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Command lwauth-controlplane is the stateless management service for
// LightweightAuth. It provides a REST API, WebSocket streams, and an
// embedded SolidJS UI for managing lwauth instances across clusters.
//
// Architecture: This is a stateless API gateway / dashboard layer.
// It does NOT participate in:
//   - cluster consensus or leader election
//   - CRD reconciliation (that's cmd/lwauth-operator)
//   - distributed lock ownership
//
// If the control plane dies, the cluster continues operating normally.
// If the operator dies, the control plane still serves UI/API.
// CRDs in etcd are the source of truth; this service just reads/writes them.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	// Register all built-in module types so the wizard module catalogue
	// and provisioner validation know about jwt, rbac, cel, header-add, etc.
	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"

	cpapi "github.com/mikeappsec/lightweightauth/internal/controlplane/api"
"github.com/mikeappsec/lightweightauth/internal/controlplane/alerting"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/analytics"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/auth"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/configmgmt"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/discovery"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/metrics"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/middleware"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/multicluster"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/routes"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/streaming"
	"github.com/mikeappsec/lightweightauth/pkg/buildinfo"
	"github.com/mikeappsec/lightweightauth/ui"
)

func main() {
	opts := zap.Options{Development: os.Getenv("DEBUG") == "1"}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	logger := ctrl.Log.WithName("lwauth-controlplane")

	// Parse configuration.
	cfg := loadConfig()

	// Create a direct k8s client (no manager, no leader election, no reconcilers).
	// The control plane is stateless — it reads/writes CRDs but does NOT reconcile them.
	s := buildScheme()
	kubeClient, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: s})
	if err != nil {
		logger.Error(err, "unable to create kubernetes client")
		os.Exit(1)
	}

	// Instance registry.
	registry := discovery.NewRegistry()

	// Multi-cluster manager.
	clusterMgr := multicluster.NewManager(registry)

	// Config version store.
	configStore := configmgmt.NewStore()

	// Route store.
	routeStore := routes.NewStore(registry)

	// Metrics aggregator.
	aggregator := metrics.NewAggregator(registry)

	// Streaming hub.
	streamHub := streaming.NewHub(registry, aggregator)
	streamHub.AllowedOrigin = cfg.ConsoleOrigin

	// Alerting engine (Phase 2). Pulls rule evaluations from
	// Prometheus and Loki when configured; degrades to a readonly
	// catalog with running rule definitions but no firings when the
	// backends are unset. Operators wire PROMETHEUS_URL /
	// LOKI_URL via the Helm chart's alerting block.
	promClient := &alerting.PromClient{BaseURL: cfg.PrometheusURL}
	lokiClient := &alerting.LokiClient{BaseURL: cfg.LokiURL}
	alertSink := alerting.NewMultiSink(
		alerting.NewAuditSink(),
		alerting.NewWebhookSink(cfg.AlertWebhookURL),
	)
	alertEngine := alerting.NewEngine(cfg.ClusterName, promClient, lokiClient, alertSink, nil)
	rulesLoader := alerting.NewConfigMapLoader(kubeClient, cfg.AlertRulesNamespace, alertEngine)

	// Analytics service (Phase 4) — shares the same Prom + Loki
	// clients as the alerting engine so there's one connection pool
	// per backend. Degrades to 503 when the backends are unconfigured.
	analyticsService := analytics.NewService(promClient, lokiClient, cfg.ClusterName)

	// Decision collector.
	decisionCollector := streaming.NewDecisionCollector(registry, streamHub)

	// Discovery watcher (auto-discovery for the local cluster).
	watcher := discovery.NewKubernetesWatcher(kubeClient, registry, discovery.KubernetesDiscoveryConfig{
		Cluster: cfg.ClusterName,
	})

	// Health checker.
	healthChecker := discovery.NewHealthChecker(registry)

	// REST API server. WithAlerting wires the Phase 2 alert endpoints;
	// local-dev pipelines and units run without it (the api package's
	// methods nil-check the engine).
	apiServer := cpapi.NewServer(registry, clusterMgr, configStore, routeStore, aggregator, streamHub, kubeClient, cfg.DefaultImage)
	apiServer = apiServer.WithAlerting(alertEngine, rulesLoader)
	apiServer = apiServer.WithAnalytics(analyticsService)
	apiServer.AllowedOrigin = cfg.ConsoleOrigin

	// Wire the HTTP mux: API + embedded UI.
	mux := http.NewServeMux()
	mux.Handle("/v1/controlplane/", apiServer.Mux)

	// Node reverse proxy — any path under /v1/proxy/{cluster}/{name}/ is
	// forwarded to the corresponding registered node. This endpoint is NOT
	// behind the CP session gate (the node enforces its own auth). Nodes are
	// ClusterIP services and are not reachable externally without going through
	// this proxy.
	mux.Handle("/v1/proxy/", apiServer.ProxyHandler())

	// Console login (single preconfigured admin, cookie session).
	authMgr := auth.NewManager(auth.Config{
		Enabled:      cfg.AuthEnabled,
		Username:     cfg.AuthUsername,
		PasswordHash: cfg.AuthPasswordHash,
		SessionTTL:   cfg.AuthSessionTTL,
		Secure:       cfg.AuthCookieSecure,
	})
	if cfg.AuthEnabled && cfg.AuthPasswordHash == "" {
		logger.Error(errors.New("CP_AUTH_ENABLED=true but no password hash set"),
			"console login is enabled but CP_AUTH_PASSWORD_HASH(_FILE) is empty; logins will fail")
	}
	mux.HandleFunc("POST /v1/controlplane/auth/login", authMgr.HandleLogin)
	mux.HandleFunc("POST /v1/controlplane/auth/logout", authMgr.HandleLogout)
	mux.HandleFunc("GET /v1/controlplane/auth/session", authMgr.HandleSession)

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Deploy-identity endpoint: distinguishes "process is up" (/healthz)
	// from "expected commit is running". Unauthenticated by design, same
	// tier as /healthz — the deployed image is public on GHCR so this
	// discloses nothing beyond what's already visible there.
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"version": buildinfo.Version,
			"commit":  buildinfo.Commit,
			"date":    buildinfo.Date,
			"go":      buildinfo.GoVersion(),
		})
	})
	mux.Handle("/", ui.Handler())

	// Apply middleware stack: rate limiting → session login → auth/RBAC → audit logging.
	auditLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	rbacCfg := middleware.DefaultRBACConfig()
	rbacCfg.Enabled = os.Getenv("CP_RBAC_ENABLED") == "true"
	rlCfg := middleware.DefaultRateLimitConfig()
	rlCfg.Enabled = os.Getenv("CP_RATELIMIT_DISABLED") != "true"

	var handler http.Handler = mux
	handler = middleware.AuditLog(auditLogger)(handler)
	handler = middleware.Auth(rbacCfg)(handler)
	handler = authMgr.Middleware(handler)
	handler = middleware.RateLimit(rlCfg)(handler)

	httpServer := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start all components.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start discovery watcher.
	go watcher.Run(ctx)

	// Start health checker.
	go healthChecker.Run(ctx)

	// Start route health probes.
	go routeStore.RunHealthProbes(ctx)

	// Start metrics aggregator.
	go aggregator.Run(ctx)

	// Start streaming hub.
	go streamHub.Run(ctx)

	// Start decision collector.
	go decisionCollector.Run(ctx)

	// Start alerting engine (Phase 2). Polls Prometheus/Loki every
	// 15s, evaluates the active rule catalog, transitions alerts,
	// fans out to sinks + WS subscribers. Degraded backends no-op
	// silently — the loop runs unconditionally so config becomes
	// active the moment an operator wires PROMETHEUS_URL.
	go alertEngine.Run(ctx)
	// ConfigMap loader — polls lwauth-alerting-rules every 30s and
	// applies merge(defaults, overrides) to the engine live.
	go rulesLoader.Run(ctx)

	// Start HTTP API server.
	go func() {
		slog.Info("starting API server", "addr", cfg.APIAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error(err, "API server failed")
			cancel()
		}
	}()

	// Block until shutdown.
	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error(err, "HTTP server shutdown error")
	}
}

// config holds the control-plane configuration.
type config struct {
	APIAddr      string
	ClusterName  string
	DefaultImage string

	// Console login (single preconfigured admin).
	AuthEnabled      bool
	AuthUsername     string
	AuthPasswordHash string
	AuthCookieSecure bool
	AuthSessionTTL   time.Duration

	// Alerting (Phase 2). Empty URLs degrade silently — the rule
	// catalog still runs but no rule fires. The ConfigMap loader
	// reads overrides from AlertRulesNamespace (defaults to the CP
	// pod's namespace or "default" in local-dev).
	PrometheusURL     string
	LokiURL           string
	AlertWebhookURL   string
	AlertRulesNamespace string

	// ConsoleOrigin is the trusted origin for WebSocket upgrades
	// (e.g. "https://lwauth.example.com"). Empty = dev mode (any origin).
	ConsoleOrigin string
}

func loadConfig() config {
	// Password hash may come inline or from a mounted secret file.
	hash := os.Getenv("CP_AUTH_PASSWORD_HASH")
	if hash == "" {
		if f := os.Getenv("CP_AUTH_PASSWORD_HASH_FILE"); f != "" {
			if b, err := os.ReadFile(f); err == nil {
				hash = strings.TrimSpace(string(b))
			}
		}
	}
	ttl := 12 * time.Hour
	if v := os.Getenv("CP_AUTH_SESSION_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			ttl = d
		}
	}
	return config{
		APIAddr:      envOrDefault("CP_API_ADDR", ":8443"),
		ClusterName:  envOrDefault("CP_CLUSTER_NAME", "local"),
		DefaultImage: envOrDefault("CP_DEFAULT_IMAGE", ""),

		AuthEnabled:      os.Getenv("CP_AUTH_ENABLED") == "true",
		AuthUsername:     envOrDefault("CP_AUTH_USERNAME", "admin"),
		AuthPasswordHash: hash,
		// Secure cookie by default; set CP_AUTH_COOKIE_SECURE=false for local HTTP.
		AuthCookieSecure: os.Getenv("CP_AUTH_COOKIE_SECURE") != "false",
		AuthSessionTTL:   ttl,

		PrometheusURL:       envOrDefault("PROMETHEUS_URL", ""),
		LokiURL:            envOrDefault("LOKI_URL", ""),
		AlertWebhookURL:    envOrDefault("ALERT_WEBHOOK_URL", ""),
		// In-cluster the CP pod runs in the project's lwauth-system
		// namespace; default to that. Local-dev falls back to "default".
		AlertRulesNamespace: envOrDefault("ALERT_RULES_NAMESPACE", "default"),
		ConsoleOrigin:       envOrDefault("CP_CONSOLE_ORIGIN", ""),
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func buildScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	return s
}
