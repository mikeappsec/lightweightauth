// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package routes provides a REST-accessible ProxyRoute registry and
// health-probing loop for the control-plane API.
package routes

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/mikeappsec/lightweightauth/internal/controlplane/discovery"
)

// Route is the REST representation of a proxy route.
type Route struct {
	Name        string      `json:"name"`
	Source      RouteEnd    `json:"source"`
	Target      RouteEnd    `json:"target"`
	PathPrefix  string      `json:"pathPrefix"`
	Timeout     string      `json:"timeout,omitempty"`
	FailureMode string      `json:"failureMode,omitempty"`
	Status      RouteStatus `json:"status"`
	CreatedAt   time.Time   `json:"createdAt"`
}

// RouteEnd identifies one side of a proxy route.
type RouteEnd struct {
	Instance string `json:"instance"`
	Cluster  string `json:"cluster"`
}

// RouteStatus captures route health.
type RouteStatus struct {
	Healthy    bool      `json:"healthy"`
	LastProbe  time.Time `json:"lastProbe,omitempty"`
	LatencyP99 string    `json:"latencyP99,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// CreateRequest is the body for POST /routes.
type CreateRequest struct {
	Name        string   `json:"name"`
	Source      RouteEnd `json:"source"`
	Target      RouteEnd `json:"target"`
	PathPrefix  string   `json:"pathPrefix"`
	Timeout     string   `json:"timeout,omitempty"`
	FailureMode string   `json:"failureMode,omitempty"`
}

// Store holds proxy routes and probes their health.
type Store struct {
	mu       sync.RWMutex
	routes   map[string]*Route
	registry *discovery.Registry
}

// NewStore creates a route store.
func NewStore(registry *discovery.Registry) *Store {
	return &Store{
		routes:   make(map[string]*Route),
		registry: registry,
	}
}

// Create adds a new route. Returns error if name already exists.
func (s *Store) Create(req CreateRequest) (*Route, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if _, exists := s.routes[req.Name]; exists {
		return nil, fmt.Errorf("route %q already exists", req.Name)
	}
	if req.Source.Instance == "" || req.Target.Instance == "" {
		return nil, fmt.Errorf("source.instance and target.instance are required")
	}
	if req.PathPrefix == "" {
		return nil, fmt.Errorf("pathPrefix is required")
	}

	if req.Source.Cluster == "" {
		req.Source.Cluster = "local"
	}
	if req.Target.Cluster == "" {
		req.Target.Cluster = "local"
	}
	if req.FailureMode == "" {
		req.FailureMode = "deny"
	}
	if req.Timeout == "" {
		req.Timeout = "2s"
	}

	r := &Route{
		Name:        req.Name,
		Source:      req.Source,
		Target:      req.Target,
		PathPrefix:  req.PathPrefix,
		Timeout:     req.Timeout,
		FailureMode: req.FailureMode,
		CreatedAt:   time.Now(),
	}
	s.routes[req.Name] = r
	return r, nil
}

// Delete removes a route by name.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.routes[name]; !exists {
		return fmt.Errorf("route %q not found", name)
	}
	delete(s.routes, name)
	return nil
}

// Get returns a single route.
func (s *Store) Get(name string) (*Route, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.routes[name]
	return r, ok
}

// List returns all routes.
func (s *Store) List() []*Route {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Route, 0, len(s.routes))
	for _, r := range s.routes {
		result = append(result, r)
	}
	return result
}

// RunHealthProbes periodically probes all routes. Blocks until ctx cancelled.
func (s *Store) RunHealthProbes(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.probeAll(ctx)
		}
	}
}

func (s *Store) probeAll(ctx context.Context) {
	logger := log.FromContext(ctx).WithName("route-health")
	s.mu.Lock()
	defer s.mu.Unlock()

	client := &http.Client{Timeout: 3 * time.Second}

	for _, route := range s.routes {
		target, ok := s.registry.Get(route.Target.Cluster, route.Target.Instance)
		if !ok {
			route.Status.Healthy = false
			route.Status.Error = "target instance not found"
			route.Status.LastProbe = time.Now()
			continue
		}

		start := time.Now()
		healthy := probeInstance(ctx, client, target)
		latency := time.Since(start)

		route.Status.Healthy = healthy
		route.Status.LastProbe = time.Now()
		route.Status.LatencyP99 = latency.String()
		if healthy {
			route.Status.Error = ""
		} else {
			route.Status.Error = "target probe failed"
			logger.V(1).Info("route unhealthy", "route", route.Name, "target", target.Name)
		}
	}
}

func probeInstance(ctx context.Context, client *http.Client, inst *discovery.Instance) bool {
	if inst.AdminURL == "" {
		return false
	}
	url := inst.AdminURL + "/v1/admin/status"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
