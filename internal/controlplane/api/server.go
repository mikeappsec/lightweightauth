// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package api implements the REST API for the lwauth control plane.
// All endpoints live under /v1/controlplane/.
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/mikeappsec/lightweightauth/internal/controlplane/configmgmt"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/discovery"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/multicluster"
)

// Server is the control-plane REST API server.
type Server struct {
	Registry       *discovery.Registry
	ClusterManager *multicluster.Manager
	ConfigStore    *configmgmt.Store
	Mux            *http.ServeMux
}

// NewServer creates a new API server wired to the instance registry.
func NewServer(registry *discovery.Registry, clusterMgr *multicluster.Manager, configStore *configmgmt.Store) *Server {
	s := &Server{
		Registry:       registry,
		ClusterManager: clusterMgr,
		ConfigStore:    configStore,
		Mux:            http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	// Instance endpoints.
	s.Mux.HandleFunc("GET /v1/controlplane/instances", s.handleListInstances)
	s.Mux.HandleFunc("GET /v1/controlplane/instances/{cluster}/{name}", s.handleGetInstance)
	s.Mux.HandleFunc("POST /v1/controlplane/instances/register", s.handleRegisterInstance)
	s.Mux.HandleFunc("DELETE /v1/controlplane/instances/{cluster}/{name}", s.handleDeleteInstance)

	// Cluster endpoints.
	s.Mux.HandleFunc("GET /v1/controlplane/clusters", s.handleListClusters)
	s.Mux.HandleFunc("POST /v1/controlplane/clusters", s.handleAddCluster)
	s.Mux.HandleFunc("DELETE /v1/controlplane/clusters/{name}", s.handleDeleteCluster)

	// Config endpoints (Phase 2).
	s.Mux.HandleFunc("GET /v1/controlplane/instances/{cluster}/{name}/config", s.handleGetConfig)
	s.Mux.HandleFunc("POST /v1/controlplane/instances/{cluster}/{name}/config", s.handlePushConfig)
	s.Mux.HandleFunc("GET /v1/controlplane/instances/{cluster}/{name}/config/history", s.handleConfigHistory)
	s.Mux.HandleFunc("POST /v1/controlplane/instances/{cluster}/{name}/config/rollback", s.handleConfigRollback)

	// Route endpoints (Phase 3 stubs).
	s.Mux.HandleFunc("GET /v1/controlplane/routes", s.handleStub)
	s.Mux.HandleFunc("POST /v1/controlplane/routes", s.handleStub)
	s.Mux.HandleFunc("DELETE /v1/controlplane/routes/{name}", s.handleStub)

	// Health endpoint.
	s.Mux.HandleFunc("GET /v1/controlplane/health", s.handleHealth)
}

// handleListInstances returns all instances, optionally filtered by cluster.
func (s *Server) handleListInstances(w http.ResponseWriter, r *http.Request) {
	cluster := r.URL.Query().Get("cluster")
	instances := s.Registry.List(cluster)
	writeJSON(w, http.StatusOK, instances)
}

// handleGetInstance returns a single instance by cluster and name.
func (s *Server) handleGetInstance(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("cluster")
	name := r.PathValue("name")

	inst, ok := s.Registry.Get(cluster, name)
	if !ok {
		writeError(w, http.StatusNotFound, "instance not found")
		return
	}
	writeJSON(w, http.StatusOK, inst)
}

// handleRegisterInstance manually registers an external instance.
func (s *Server) handleRegisterInstance(w http.ResponseWriter, r *http.Request) {
	var reg discovery.ManualRegistration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	// Validate required fields.
	if reg.Name == "" || reg.Cluster == "" || reg.AdminURL == "" {
		writeError(w, http.StatusUnprocessableEntity, "name, cluster, and adminUrl are required")
		return
	}

	// Basic URL validation.
	if !strings.HasPrefix(reg.AdminURL, "http://") && !strings.HasPrefix(reg.AdminURL, "https://") {
		writeError(w, http.StatusUnprocessableEntity, "adminUrl must start with http:// or https://")
		return
	}

	inst := discovery.RegisterManual(&reg)
	s.Registry.Register(inst)

	logger := log.FromContext(r.Context())
	logger.Info("instance registered manually", "name", reg.Name, "cluster", reg.Cluster)

	writeJSON(w, http.StatusCreated, inst)
}

// handleDeleteInstance removes an instance from the registry.
func (s *Server) handleDeleteInstance(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("cluster")
	name := r.PathValue("name")

	if _, ok := s.Registry.Get(cluster, name); !ok {
		writeError(w, http.StatusNotFound, "instance not found")
		return
	}

	s.Registry.Deregister(cluster, name)
	w.WriteHeader(http.StatusNoContent)
}

// handleListClusters returns all registered clusters with instance counts.
func (s *Server) handleListClusters(w http.ResponseWriter, r *http.Request) {
	clusters := s.ClusterManager.List()

	type clusterInfo struct {
		Name          string `json:"name"`
		APIServer     string `json:"apiServer,omitempty"`
		InstanceCount int    `json:"instanceCount"`
	}

	result := make([]clusterInfo, 0, len(clusters))
	for _, c := range clusters {
		instances := s.Registry.List(c.Name)
		result = append(result, clusterInfo{
			Name:          c.Name,
			APIServer:     c.APIServer,
			InstanceCount: len(instances),
		})
	}

	// Also include the local cluster derived from instances.
	instances := s.Registry.List("")
	localClusters := make(map[string]int)
	for _, inst := range instances {
		localClusters[inst.Cluster]++
	}
	registered := make(map[string]bool)
	for _, c := range clusters {
		registered[c.Name] = true
	}
	for name, count := range localClusters {
		if !registered[name] {
			result = append(result, clusterInfo{
				Name:          name,
				InstanceCount: count,
			})
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// handleAddCluster registers a new remote cluster.
func (s *Server) handleAddCluster(w http.ResponseWriter, r *http.Request) {
	var cfg multicluster.ClusterConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if cfg.Name == "" {
		writeError(w, http.StatusUnprocessableEntity, "name is required")
		return
	}
	if cfg.APIServer == "" && cfg.KubeconfigPath == "" {
		writeError(w, http.StatusUnprocessableEntity, "either apiServer or kubeconfigPath is required")
		return
	}

	if err := s.ClusterManager.Add(r.Context(), cfg); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	logger := log.FromContext(r.Context())
	logger.Info("cluster registered", "name", cfg.Name)
	writeJSON(w, http.StatusCreated, cfg)
}

// handleDeleteCluster removes a remote cluster.
func (s *Server) handleDeleteCluster(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.ClusterManager.Remove(name); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGetConfig returns the current config for an instance.
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("cluster")
	name := r.PathValue("name")

	if _, ok := s.Registry.Get(cluster, name); !ok {
		writeError(w, http.StatusNotFound, "instance not found")
		return
	}

	v, ok := s.ConfigStore.Current(cluster, name)
	if !ok {
		writeError(w, http.StatusNotFound, "no config stored for this instance")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handlePushConfig validates and stores a new config version.
func (s *Server) handlePushConfig(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("cluster")
	name := r.PathValue("name")

	if _, ok := s.Registry.Get(cluster, name); !ok {
		writeError(w, http.StatusNotFound, "instance not found")
		return
	}

	var req struct {
		Content string `json:"content"`
		Author  string `json:"author,omitempty"`
		Comment string `json:"comment,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Content == "" {
		writeError(w, http.StatusUnprocessableEntity, "content is required")
		return
	}

	v, err := s.ConfigStore.PushConfig(r.Context(), cluster, name, req.Content, req.Author, req.Comment)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	logger := log.FromContext(r.Context())
	logger.Info("config pushed", "cluster", cluster, "instance", name, "version", v.Version)
	writeJSON(w, http.StatusCreated, v)
}

// handleConfigHistory returns all config versions for an instance.
func (s *Server) handleConfigHistory(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("cluster")
	name := r.PathValue("name")

	if _, ok := s.Registry.Get(cluster, name); !ok {
		writeError(w, http.StatusNotFound, "instance not found")
		return
	}

	history := s.ConfigStore.History(cluster, name)
	if history == nil {
		history = []configmgmt.ConfigVersion{}
	}
	writeJSON(w, http.StatusOK, history)
}

// handleConfigRollback rolls back to a specific config version.
func (s *Server) handleConfigRollback(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("cluster")
	name := r.PathValue("name")

	if _, ok := s.Registry.Get(cluster, name); !ok {
		writeError(w, http.StatusNotFound, "instance not found")
		return
	}

	var req struct {
		Version int    `json:"version"`
		Author  string `json:"author,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Version <= 0 {
		writeError(w, http.StatusUnprocessableEntity, "version must be a positive integer")
		return
	}

	v, err := s.ConfigStore.Rollback(cluster, name, req.Version, req.Author)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	logger := log.FromContext(r.Context())
	logger.Info("config rolled back", "cluster", cluster, "instance", name, "toVersion", req.Version, "newVersion", v.Version)
	writeJSON(w, http.StatusOK, v)
}

// handleHealth returns aggregated health of all instances.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	instances := s.Registry.List("")
	total := len(instances)
	healthy := 0
	for _, inst := range instances {
		if inst.Status.Healthy {
			healthy++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "ok",
		"totalInstances":   total,
		"healthyInstances": healthy,
	})
}

// handleStub returns 501 for endpoints not yet implemented.
func (s *Server) handleStub(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "endpoint not yet implemented")
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
