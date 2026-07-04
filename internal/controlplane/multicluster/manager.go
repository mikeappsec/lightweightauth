// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package multicluster manages controller-runtime managers for remote clusters.
package multicluster

import (
	"context"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/mikeappsec/lightweightauth/internal/controlplane/discovery"
)

// ClusterConfig describes a remote cluster the control plane manages.
type ClusterConfig struct {
	// Name is the user-facing cluster name.
	Name string `json:"name"`
	// APIServer is the Kubernetes API server URL.
	APIServer string `json:"apiServer,omitempty"`
	// Token is a bearer token for authentication.
	Token string `json:"token,omitempty"`
	// CABundle is the PEM-encoded CA for the API server.
	CABundle string `json:"caBundle,omitempty"`
	// KubeconfigPath is an alternative to APIServer/Token/CABundle.
	KubeconfigPath string `json:"kubeconfigPath,omitempty"`
	// KubeconfigContext selects a context within the kubeconfig.
	KubeconfigContext string `json:"kubeconfigContext,omitempty"`
}

// clusterEntry tracks a running remote cluster watcher.
type clusterEntry struct {
	Config  ClusterConfig
	Cancel  context.CancelFunc
	Watcher *discovery.KubernetesWatcher
}

// Manager manages multiple remote cluster connections and spawns
// discovery watchers for each.
type Manager struct {
	mu       sync.RWMutex
	clusters map[string]*clusterEntry
	registry *discovery.Registry
}

// NewManager creates a multi-cluster manager.
func NewManager(registry *discovery.Registry) *Manager {
	return &Manager{
		clusters: make(map[string]*clusterEntry),
		registry: registry,
	}
}

// Add registers a remote cluster and starts a discovery watcher.
func (m *Manager) Add(ctx context.Context, cfg ClusterConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.clusters[cfg.Name]; exists {
		return fmt.Errorf("cluster %q already registered", cfg.Name)
	}

	restCfg, err := buildRESTConfig(cfg)
	if err != nil {
		return fmt.Errorf("build rest config for %q: %w", cfg.Name, err)
	}

	k8sClient, err := newRemoteClient(restCfg)
	if err != nil {
		return fmt.Errorf("create client for %q: %w", cfg.Name, err)
	}

	watcher := discovery.NewKubernetesWatcher(k8sClient, m.registry, discovery.KubernetesDiscoveryConfig{
		Cluster: cfg.Name,
	})

	clusterCtx, cancel := context.WithCancel(ctx)
	entry := &clusterEntry{
		Config:  cfg,
		Cancel:  cancel,
		Watcher: watcher,
	}
	m.clusters[cfg.Name] = entry

	go func() {
		logger := log.FromContext(clusterCtx).WithName("multicluster").WithValues("cluster", cfg.Name)
		logger.Info("starting remote cluster watcher")
		watcher.Run(clusterCtx)
		logger.Info("remote cluster watcher stopped")
	}()

	return nil
}

// Remove stops the watcher for a cluster and removes it.
func (m *Manager) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.clusters[name]
	if !exists {
		return fmt.Errorf("cluster %q not found", name)
	}

	entry.Cancel()
	delete(m.clusters, name)
	return nil
}

// List returns the configs of all registered clusters.
func (m *Manager) List() []ClusterConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]ClusterConfig, 0, len(m.clusters))
	for _, entry := range m.clusters {
		result = append(result, entry.Config)
	}
	return result
}

// Get returns a single cluster config by name.
func (m *Manager) Get(name string) (ClusterConfig, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.clusters[name]
	if !ok {
		return ClusterConfig{}, false
	}
	return entry.Config, true
}

// buildRESTConfig creates a *rest.Config from ClusterConfig.
func buildRESTConfig(cfg ClusterConfig) (*rest.Config, error) {
	if cfg.KubeconfigPath != "" {
		rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: cfg.KubeconfigPath}
		overrides := &clientcmd.ConfigOverrides{}
		if cfg.KubeconfigContext != "" {
			overrides.CurrentContext = cfg.KubeconfigContext
		}
		return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	}

	if cfg.APIServer == "" {
		return nil, fmt.Errorf("either kubeconfigPath or apiServer is required")
	}

	rc := &rest.Config{
		Host:        cfg.APIServer,
		BearerToken: cfg.Token,
	}
	if cfg.CABundle != "" {
		rc.TLSClientConfig = rest.TLSClientConfig{
			CAData: []byte(cfg.CABundle),
		}
	}
	return rc, nil
}

// newRemoteClient creates a controller-runtime client from a rest.Config.
func newRemoteClient(cfg *rest.Config) (client.Client, error) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	return client.New(cfg, client.Options{Scheme: s})
}
