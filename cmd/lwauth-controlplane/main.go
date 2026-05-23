// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Command lwauth-controlplane is the management control plane for
// LightweightAuth. It provides a REST API, WebSocket streams, and an
// embedded SolidJS UI for managing lwauth instances across clusters.
//
// This binary shares internal/ and pkg/ with cmd/lwauth (same Go
// module) but compiles to its own binary and deploys as a separate Pod.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1alpha1 "github.com/mikeappsec/lightweightauth/api/crd/v1alpha1"
	"github.com/mikeappsec/lightweightauth/internal/controlplane"
	cpapi "github.com/mikeappsec/lightweightauth/internal/controlplane/api"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/configmgmt"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/discovery"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/metrics"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/multicluster"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/routes"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/streaming"
	"github.com/mikeappsec/lightweightauth/ui"
)

func main() {
	opts := zap.Options{Development: os.Getenv("DEBUG") == "1"}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	logger := ctrl.Log.WithName("lwauth-controlplane")

	// Parse configuration.
	cfg := loadConfig()

	// Setup controller-runtime manager.
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme(),
		Metrics: metricsserver.Options{
			BindAddress: cfg.MetricsAddr,
		},
		HealthProbeBindAddress: cfg.HealthAddr,
		LeaderElection:         cfg.LeaderElect,
		LeaderElectionID:       "lwauth-controlplane-leader",
	})
	if err != nil {
		logger.Error(err, "unable to create manager")
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

	// Decision collector.
	decisionCollector := streaming.NewDecisionCollector(registry, streamHub)

	// Register reconcilers.
	if err := (&controlplane.InstanceReconciler{
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		DefaultImage: cfg.DefaultImage,
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "unable to setup InstanceReconciler")
		os.Exit(1)
	}

	if err := (&controlplane.ProxyRouteReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Registry: registry,
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "unable to setup ProxyRouteReconciler")
		os.Exit(1)
	}

	// Health probes for the manager.
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		logger.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		logger.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	// Discovery watcher (auto-discovery for the local cluster).
	watcher := discovery.NewKubernetesWatcher(mgr.GetClient(), registry, discovery.KubernetesDiscoveryConfig{
		Cluster: cfg.ClusterName,
	})

	// Health checker.
	healthChecker := discovery.NewHealthChecker(registry)

	// REST API server.
	apiServer := cpapi.NewServer(registry, clusterMgr, configStore, routeStore, aggregator, streamHub)

	// Wire the HTTP mux: API + embedded UI.
	mux := http.NewServeMux()
	mux.Handle("/v1/controlplane/", apiServer.Mux)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/", ui.Handler())

	httpServer := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start all components.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start manager in background.
	go func() {
		logger.Info("starting controller-runtime manager")
		if err := mgr.Start(ctx); err != nil {
			logger.Error(err, "manager exited with error")
			cancel()
		}
	}()

	// Wait for cache sync before starting discovery.
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		logger.Error(nil, "cache sync failed")
		os.Exit(1)
	}

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
	MetricsAddr  string
	HealthAddr   string
	ClusterName  string
	DefaultImage string
	LeaderElect  bool
}

func loadConfig() config {
	return config{
		APIAddr:      envOrDefault("CP_API_ADDR", ":8443"),
		MetricsAddr:  envOrDefault("CP_METRICS_ADDR", ":9090"),
		HealthAddr:   envOrDefault("CP_HEALTH_ADDR", ":8082"),
		ClusterName:  envOrDefault("CP_CLUSTER_NAME", "local"),
		DefaultImage: envOrDefault("CP_DEFAULT_IMAGE", "ghcr.io/mikeappsec/lightweightauth:latest"),
		LeaderElect:  os.Getenv("CP_LEADER_ELECT") == "true",
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func scheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(v1alpha1.AddToScheme(s))
	return s
}
