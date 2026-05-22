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

	"github.com/mikeappsec/lightweightauth/internal/controlplane/discovery"
)

// Server is the control-plane REST API server.
type Server struct {
	Registry *discovery.Registry
	Mux      *http.ServeMux
}

// NewServer creates a new API server wired to the instance registry.
func NewServer(registry *discovery.Registry) *Server {
	s := &Server{
		Registry: registry,
		Mux:      http.NewServeMux(),
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

	// Cluster endpoints (Phase 2 stubs).
	s.Mux.HandleFunc("GET /v1/controlplane/clusters", s.handleListClusters)
	s.Mux.HandleFunc("POST /v1/controlplane/clusters", s.handleStub)
	s.Mux.HandleFunc("DELETE /v1/controlplane/clusters/{name}", s.handleStub)

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

// handleListClusters returns the list of known clusters.
func (s *Server) handleListClusters(w http.ResponseWriter, r *http.Request) {
	// Derive cluster list from registered instances.
	instances := s.Registry.List("")
	clusterSet := make(map[string]bool)
	for _, inst := range instances {
		clusterSet[inst.Cluster] = true
	}

	clusters := make([]string, 0, len(clusterSet))
	for c := range clusterSet {
		clusters = append(clusters, c)
	}
	writeJSON(w, http.StatusOK, map[string]any{"clusters": clusters})
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
