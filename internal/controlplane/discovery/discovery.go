// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package discovery implements dual-mode instance discovery for
// the lwauth control plane: automatic Kubernetes label-selector
// watch and manual registration via API.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Instance represents a discovered or registered lwauth instance.
type Instance struct {
	Name      string    `json:"name"`
	Cluster   string    `json:"cluster"`
	Namespace string    `json:"namespace,omitempty"`
	AdminURL  string    `json:"adminUrl"`
	GRPCURL   string    `json:"grpcUrl,omitempty"`
	Status    Status    `json:"status"`
	Source    Source    `json:"source"`
	LastSeen  time.Time `json:"lastSeen"`
}

// Status captures the health state of an instance.
type Status struct {
	Healthy       bool      `json:"healthy"`
	Ready         bool      `json:"ready"`
	ConfigVersion string    `json:"configVersion,omitempty"`
	Replicas      string    `json:"replicas,omitempty"`
	LastCheck     time.Time `json:"lastCheck"`
	Error         string    `json:"error,omitempty"`
}

// Source indicates how an instance was discovered.
type Source string

const (
	SourceAutoDiscovery Source = "auto"
	SourceManual        Source = "manual"
)

// AdminStatusResponse is the expected response from /v1/admin/status.
type AdminStatusResponse struct {
	Ready         bool   `json:"ready"`
	ConfigVersion string `json:"configVersion,omitempty"`
	Replicas      string `json:"replicas,omitempty"`
	Version       string `json:"version,omitempty"`
}

// Registry stores discovered instances and provides lookup.
type Registry struct {
	mu        sync.RWMutex
	instances map[string]*Instance // key: cluster/name
}

// NewRegistry creates an empty instance registry.
func NewRegistry() *Registry {
	return &Registry{
		instances: make(map[string]*Instance),
	}
}

func instanceKey(cluster, name string) string {
	return cluster + "/" + name
}

// Register adds or updates an instance in the registry.
func (r *Registry) Register(inst *Instance) {
	r.mu.Lock()
	defer r.mu.Unlock()
	inst.LastSeen = time.Now()
	r.instances[instanceKey(inst.Cluster, inst.Name)] = inst
}

// Deregister removes an instance from the registry.
func (r *Registry) Deregister(cluster, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.instances, instanceKey(cluster, name))
}

// Get retrieves an instance by cluster and name.
func (r *Registry) Get(cluster, name string) (*Instance, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	inst, ok := r.instances[instanceKey(cluster, name)]
	return inst, ok
}

// List returns all registered instances. Optional filter by cluster.
func (r *Registry) List(cluster string) []*Instance {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*Instance, 0, len(r.instances))
	for _, inst := range r.instances {
		if cluster == "" || inst.Cluster == cluster {
			result = append(result, inst)
		}
	}
	return result
}

// HealthChecker periodically probes all registered instances.
type HealthChecker struct {
	Registry *Registry
	Client   *http.Client
	Interval time.Duration
}

// NewHealthChecker creates a health checker with sensible defaults.
func NewHealthChecker(registry *Registry) *HealthChecker {
	return &HealthChecker{
		Registry: registry,
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
		Interval: 15 * time.Second,
	}
}

// Run starts the periodic health check loop. Blocks until ctx is cancelled.
func (hc *HealthChecker) Run(ctx context.Context) {
	ticker := time.NewTicker(hc.Interval)
	defer ticker.Stop()

	// Initial check.
	hc.checkAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hc.checkAll(ctx)
		}
	}
}

func (hc *HealthChecker) checkAll(ctx context.Context) {
	logger := log.FromContext(ctx).WithName("health-checker")
	instances := hc.Registry.List("")

	for _, inst := range instances {
		if err := hc.probe(ctx, inst); err != nil {
			logger.V(1).Info("instance unhealthy", "instance", inst.Name, "cluster", inst.Cluster, "error", err)
		}
	}
}

func (hc *HealthChecker) probe(ctx context.Context, inst *Instance) error {
	url := inst.AdminURL + "/v1/admin/status"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		inst.Status.Healthy = false
		inst.Status.Error = err.Error()
		inst.Status.LastCheck = time.Now()
		return err
	}

	resp, err := hc.Client.Do(req)
	if err != nil {
		inst.Status.Healthy = false
		inst.Status.Error = err.Error()
		inst.Status.LastCheck = time.Now()
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		inst.Status.Healthy = false
		inst.Status.Error = fmt.Sprintf("unexpected status %d", resp.StatusCode)
		inst.Status.LastCheck = time.Now()
		return fmt.Errorf("status %d from %s", resp.StatusCode, url)
	}

	var status AdminStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		inst.Status.Healthy = false
		inst.Status.Error = "invalid response body"
		inst.Status.LastCheck = time.Now()
		return err
	}

	inst.Status.Healthy = true
	inst.Status.Ready = status.Ready
	inst.Status.ConfigVersion = status.ConfigVersion
	inst.Status.Replicas = status.Replicas
	inst.Status.Error = ""
	inst.Status.LastCheck = time.Now()
	return nil
}

// KubernetesDiscoveryConfig configures the automatic K8s discovery.
type KubernetesDiscoveryConfig struct {
	// LabelSelector is the selector used to find lwauth Services.
	LabelSelector labels.Selector
	// Cluster is the name of the cluster being watched.
	Cluster string
	// Namespaces restricts discovery to specific namespaces.
	// Empty means all namespaces.
	Namespaces []string
}

// ManualRegistration is the request body for POST /instances/register.
type ManualRegistration struct {
	Name     string           `json:"name"`
	Cluster  string           `json:"cluster"`
	AdminURL string           `json:"adminUrl"`
	GRPCURL  string           `json:"grpcUrl,omitempty"`
	TLS      *TLSRegistration `json:"tls,omitempty"`
}

// TLSRegistration holds TLS configuration for manual registration.
type TLSRegistration struct {
	CABundle   string `json:"caBundle,omitempty"`
	ClientCert string `json:"clientCert,omitempty"`
}

// RegisterManual creates an Instance from a manual registration request.
func RegisterManual(reg *ManualRegistration) *Instance {
	return &Instance{
		Name:     reg.Name,
		Cluster:  reg.Cluster,
		AdminURL: reg.AdminURL,
		GRPCURL:  reg.GRPCURL,
		Source:   SourceManual,
		Status: Status{
			LastCheck: time.Now(),
		},
		LastSeen: time.Now(),
	}
}
