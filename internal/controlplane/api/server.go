// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package api implements the REST API for the lwauth control plane.
// All endpoints live under /v1/controlplane/.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/mikeappsec/lightweightauth/internal/controlplane/alerting"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/configmgmt"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/discovery"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/metrics"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/multicluster"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/provisioner"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/routes"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/streaming"
)

// Server is the control-plane REST API server.
type Server struct {
	Registry       *discovery.Registry
	ClusterManager *multicluster.Manager
	ConfigStore    *configmgmt.Store
	RouteStore     *routes.Store
	Aggregator     *metrics.Aggregator
	StreamHub      *streaming.Hub
	KubeClient     client.Client
	Mux            *http.ServeMux
	DefaultImage   string

	// AlertEngine + RulesLoader are the Phase 2 alerting primitives.
	// Both may be nil in test or local-dev mode — the endpoints gate
	// on nil checks and return a "not configured" stub rather than
	// crashing.
	AlertEngine  *alerting.Engine
	RulesLoader  *alerting.ConfigMapLoader
}

// NewServer creates a new API server wired to the instance registry.
func NewServer(registry *discovery.Registry, clusterMgr *multicluster.Manager, configStore *configmgmt.Store, routeStore *routes.Store, aggregator *metrics.Aggregator, hub *streaming.Hub, kubeClient client.Client, defaultImage string) *Server {
	s := &Server{
		Registry:       registry,
		ClusterManager: clusterMgr,
		ConfigStore:    configStore,
		RouteStore:     routeStore,
		Aggregator:     aggregator,
		StreamHub:      hub,
		KubeClient:     kubeClient,
		Mux:            http.NewServeMux(),
		DefaultImage:   defaultImage,
	}
	s.registerRoutes()
	return s
}

// WithAlerting wires the alert engine + ConfigMap loader into the
// server. Optional — alerting endpoints degrade gracefully when this
// is not called (local-dev and unit tests run without it). Returned
// Server pointer is the same one for chainability.
func (s *Server) WithAlerting(engine *alerting.Engine, loader *alerting.ConfigMapLoader) *Server {
	s.AlertEngine = engine
	s.RulesLoader = loader
	s.registerAlertRoutes()
	return s
}

func (s *Server) registerRoutes() {
	// Instance endpoints.
	s.Mux.HandleFunc("GET /v1/controlplane/instances", s.handleListInstances)
	s.Mux.HandleFunc("GET /v1/controlplane/instances/{cluster}/{name}", s.handleGetInstance)
	s.Mux.HandleFunc("POST /v1/controlplane/instances/create", s.handleCreateInstance)
	s.Mux.HandleFunc("POST /v1/controlplane/instances/register", s.handleRegisterInstance)
	s.Mux.HandleFunc("DELETE /v1/controlplane/instances/{cluster}/{name}", s.handleDeleteInstance)

	// Module catalogue + presets (Phase A).
	s.Mux.HandleFunc("GET /v1/controlplane/modules", s.handleListModules)
	s.Mux.HandleFunc("GET /v1/controlplane/presets", s.handleListPresets)
	s.Mux.HandleFunc("POST /v1/controlplane/instances/create/preview", s.handlePreviewCreate)
	s.Mux.HandleFunc("POST /v1/controlplane/instances/create/validate", s.handleValidateCreate)

	// Endpoint display + quick test (Phase B).
	s.Mux.HandleFunc("GET /v1/controlplane/instances/{cluster}/{name}/endpoints", s.handleGetEndpoints)
	s.Mux.HandleFunc("POST /v1/controlplane/instances/{cluster}/{name}/test", s.handleQuickTest)

	// Cluster endpoints.
	s.Mux.HandleFunc("GET /v1/controlplane/clusters", s.handleListClusters)
	s.Mux.HandleFunc("POST /v1/controlplane/clusters", s.handleAddCluster)
	s.Mux.HandleFunc("DELETE /v1/controlplane/clusters/{name}", s.handleDeleteCluster)

	// Config endpoints (Phase 2).
	s.Mux.HandleFunc("GET /v1/controlplane/instances/{cluster}/{name}/config", s.handleGetConfig)
	s.Mux.HandleFunc("POST /v1/controlplane/instances/{cluster}/{name}/config", s.handlePushConfig)
	s.Mux.HandleFunc("GET /v1/controlplane/instances/{cluster}/{name}/config/history", s.handleConfigHistory)
	s.Mux.HandleFunc("POST /v1/controlplane/instances/{cluster}/{name}/config/rollback", s.handleConfigRollback)

	// Route endpoints (Phase 3).
	s.Mux.HandleFunc("GET /v1/controlplane/routes", s.handleListRoutes)
	s.Mux.HandleFunc("GET /v1/controlplane/routes/{name}", s.handleGetRoute)
	s.Mux.HandleFunc("POST /v1/controlplane/routes", s.handleCreateRoute)
	s.Mux.HandleFunc("DELETE /v1/controlplane/routes/{name}", s.handleDeleteRoute)

	// Metrics endpoints (Phase 4).
	s.Mux.HandleFunc("GET /v1/controlplane/metrics", s.handleMetrics)
	s.Mux.HandleFunc("GET /v1/controlplane/metrics/{cluster}/{name}", s.handleInstanceMetrics)

	// WebSocket streaming endpoints (Phase 4).
	s.Mux.HandleFunc("/v1/controlplane/stream/decisions", s.StreamHub.HandleDecisionStream)
	s.Mux.HandleFunc("/v1/controlplane/stream/metrics", s.StreamHub.HandleMetricsStream)

	// Health endpoint.
	s.Mux.HandleFunc("GET /v1/controlplane/health", s.handleHealth)

	// URL probe (JWKS reachability check for the create wizard).
	s.Mux.HandleFunc("GET /v1/controlplane/probe/url", s.handleProbeURL)

	// Alerting endpoints (Phase 2). Sub-registration is gated on
	// WithAlerting having been called; the methods themselves also
	// nil-check so direct calls via s.Mux dispatch degrade cleanly
	// in local-dev where alerting is intentionally disabled.
	s.registerAlertRoutes()
}

// registerAlertRoutes wires the alert REST + WS endpoints. Safe to
// call multiple times — the routes are idempotent on the same mux.
// The handlers nil-check s.AlertEngine and s.RulesLoader so endpoints
// respond with a "not configured" stub rather than crashing when
// alerting is disabled in local-dev.
func (s *Server) registerAlertRoutes() {
	s.Mux.HandleFunc("GET /v1/controlplane/alerts", s.handleListAlerts)
	s.Mux.HandleFunc("POST /v1/controlplane/alerts/{id}/ack", s.handleAckAlert)
	s.Mux.HandleFunc("GET /v1/controlplane/alerts/rules", s.handleListRules)
	s.Mux.HandleFunc("PUT /v1/controlplane/alerts/rules", s.handlePutRules)
	s.Mux.HandleFunc("POST /v1/controlplane/alerts/rules", s.handlePutRules)
	s.Mux.HandleFunc("/v1/controlplane/stream/alerts", s.handleAlertStream)
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

// CreateInstanceRequest is the request body for POST /instances/create.
// It deploys a new lwauth instance by directly creating a Deployment + Service.
// Supports both the legacy flat format (Config string) and the new structured
// format (Identifiers/Authorizers/Mutators arrays from the module-aware form).
type CreateInstanceRequest struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Cluster   string `json:"cluster,omitempty"`
	Replicas  *int32 `json:"replicas,omitempty"`
	Version   string `json:"version,omitempty"`
	Image     string `json:"image,omitempty"`
	Config    string `json:"config,omitempty"` // Inline auth config YAML/JSON (legacy).

	// Structured fields from the module-aware wizard (Phase A).
	ImageTag       string                         `json:"imageTag,omitempty"`
	Preset         string                         `json:"preset,omitempty"`
	Identifiers    []provisioner.ModuleEntry      `json:"identifiers,omitempty"`
	Authorizers    []provisioner.ModuleEntry      `json:"authorizers,omitempty"`
	Mutators       []provisioner.ModuleEntry      `json:"mutators,omitempty"`
	Infrastructure *provisioner.InfrastructureReq `json:"infrastructure,omitempty"`
}

// handleCreateInstance directly creates a Deployment + Service in the target
// namespace. Accepts both legacy (raw config string) and structured (module
// arrays) request formats. The lwauth nodes handle their own leader election
// and coordination. Kubernetes handles scheduling, restarts, and scaling.
func (s *Server) handleCreateInstance(w http.ResponseWriter, r *http.Request) {
	var req CreateInstanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusUnprocessableEntity, "name is required")
		return
	}
	if req.Namespace == "" {
		req.Namespace = "lwauth-system"
	}
	if req.Cluster == "" {
		req.Cluster = "local"
	}

	// If structured fields are present, use the provisioner to generate config.
	if len(req.Identifiers) > 0 || req.Preset != "" {
		nodeReq := &provisioner.CreateNodeRequest{
			Name:        req.Name,
			Namespace:   req.Namespace,
			Cluster:     req.Cluster,
			Replicas:    req.Replicas,
			ImageTag:    req.ImageTag,
			Preset:      req.Preset,
			Identifiers: req.Identifiers,
			Authorizers: req.Authorizers,
			Mutators:    req.Mutators,
		}
		if req.Infrastructure != nil {
			nodeReq.Infrastructure = *req.Infrastructure
		}

		// Apply preset if specified.
		if req.Preset != "" && len(req.Identifiers) == 0 {
			if !provisioner.ApplyPreset(nodeReq, req.Preset) {
				writeError(w, http.StatusUnprocessableEntity, "unknown preset: "+req.Preset)
				return
			}
		}

		// Validate.
		result := nodeReq.Validate()
		if !result.Valid {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":            "validation failed",
				"validationErrors": result.Errors,
			})
			return
		}

		// Generate auth config.
		generatedConfig, err := nodeReq.GenerateAuthConfig()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to generate config: "+err.Error())
			return
		}
		req.Config = generatedConfig

		if req.Version == "" && req.ImageTag != "" {
			req.Version = req.ImageTag
		}
	}

	// Default to a single replica (see provisioner.GenerateValues for rationale):
	// a second replica doubles per-node memory, which matters on small clusters
	// such as the 12 GB OCI Always Free tier. Callers set Replicas for HA.
	replicas := int32(1)
	if req.Replicas != nil {
		replicas = *req.Replicas
	}

	image := s.resolveImage(req.Image, req.Version)

	labels := map[string]string{
		"app.kubernetes.io/name":       "lwauth",
		"app.kubernetes.io/instance":   req.Name,
		"app.kubernetes.io/managed-by": "lwauth-controlplane",
		"lightweightauth.io/cluster":   req.Cluster,
	}

	// Annotations on every provisioner-created resource.
	// "managed-by: lwauth-controlplane" signals to ArgoCD that these resources
	// are imperatively provisioned by the CP API, not owned by any ArgoCD
	// Application. ArgoCD tracks its own resources via the same annotation
	// with its app name; a different value prevents pruning by ArgoCD.
	provisionerAnnotations := map[string]string{
		"argocd.argoproj.io/managed-by": "lwauth-controlplane",
	}

	// If a config was generated, create a ConfigMap to hold it and mount it.
	if req.Config != "" {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:        req.Name + "-config",
				Namespace:   req.Namespace,
				Labels:      labels,
				Annotations: provisionerAnnotations,
			},
			Data: map[string]string{"config.yaml": req.Config},
		}
		if err := s.KubeClient.Create(r.Context(), cm); err != nil && !strings.Contains(err.Error(), "already exists") {
			writeError(w, http.StatusInternalServerError, "failed to create config: "+err.Error())
			return
		}
	}

	// Build container spec, mounting the generated config when present.
	container := corev1.Container{
		Name:  "lwauth",
		Image: image,
		Ports: []corev1.ContainerPort{
			{Name: "http", ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
			{Name: "grpc", ContainerPort: 9001, Protocol: corev1.ProtocolTCP},
			{Name: "admin", ContainerPort: 8081, Protocol: corev1.ProtocolTCP},
		},
		Resources: defaultResources(),
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/healthz",
					Port: intstr.FromString("http"),
				},
			},
			InitialDelaySeconds: 5,
			PeriodSeconds:       10,
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/readyz",
					Port: intstr.FromString("http"),
				},
			},
			InitialDelaySeconds: 3,
			PeriodSeconds:       5,
		},
	}

	// Resolve TLS config from the infrastructure request.
	tlsSecretName := ""
	if req.Infrastructure != nil && req.Infrastructure.TLS != nil && req.Infrastructure.TLS.Enabled {
		tlsSecretName = req.Infrastructure.TLS.SecretName
		// When TLS is enabled the binary serves HTTPS, so kubelet probes must
		// use HTTPS too — otherwise they get a TLS handshake error and the pod
		// is killed in a CrashLoopBackOff.
		container.LivenessProbe.HTTPGet.Scheme = corev1.URISchemeHTTPS
		container.ReadinessProbe.HTTPGet.Scheme = corev1.URISchemeHTTPS
	}
	if req.Config != "" {
		container.Args = []string{"--config=/etc/lwauth/config.yaml"}
		container.VolumeMounts = []corev1.VolumeMount{
			{Name: "config", MountPath: "/etc/lwauth"},
		}
	}
	if tlsSecretName != "" {
		container.Args = append(container.Args,
			"--tls-cert=/etc/lwauth/tls/tls.crt",
			"--tls-key=/etc/lwauth/tls/tls.key",
		)
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
			Name:      "tls",
			MountPath: "/etc/lwauth/tls",
			ReadOnly:  true,
		})
	}

	podVolumes := []corev1.Volume{}
	if req.Config != "" {
		podVolumes = append(podVolumes, corev1.Volume{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: req.Name + "-config"},
				},
			},
		})
	}
	if tlsSecretName != "" {
		podVolumes = append(podVolumes, corev1.Volume{
			Name: "tls",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: tlsSecretName},
			},
		})
	}

	// Create the Deployment.
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:        req.Name,
			Namespace:   req.Namespace,
			Labels:      labels,
			Annotations: provisionerAnnotations,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{container},
					Volumes:    podVolumes,
					TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
						{
							MaxSkew:           1,
							TopologyKey:       "topology.kubernetes.io/zone",
							WhenUnsatisfiable: corev1.ScheduleAnyway,
							LabelSelector:     &metav1.LabelSelector{MatchLabels: labels},
						},
					},
				},
			},
		},
	}

	if err := s.KubeClient.Create(r.Context(), deploy); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeError(w, http.StatusConflict, "instance already exists: "+req.Name)
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create deployment: "+err.Error())
		return
	}

	// Create the Service.
	svcAnnotations := map[string]string{
		"argocd.argoproj.io/managed-by": "lwauth-controlplane",
	}
	if tlsSecretName != "" {
		// Signal to the Kubernetes watcher that this node speaks HTTPS,
		// so it builds an https:// admin URL for health checks.
		svcAnnotations["lwauth.io/tls"] = "true"
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        req.Name,
			Namespace:   req.Namespace,
			Labels:      labels,
			Annotations: svcAnnotations,
		},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 8080, TargetPort: intstr.FromString("http"), Protocol: corev1.ProtocolTCP},
				{Name: "grpc", Port: 9001, TargetPort: intstr.FromString("grpc"), Protocol: corev1.ProtocolTCP},
			},
		},
	}

	if err := s.KubeClient.Create(r.Context(), svc); err != nil {
		// If service creation fails, log but don't fail the whole request — deployment exists.
		logger := log.FromContext(r.Context())
		logger.Error(err, "failed to create service (deployment was created)", "name", req.Name)
	}

	logger := log.FromContext(r.Context())
	logger.Info("instance deployed", "name", req.Name, "namespace", req.Namespace, "replicas", replicas)

	writeJSON(w, http.StatusCreated, map[string]any{
		"name":      req.Name,
		"namespace": req.Namespace,
		"cluster":   req.Cluster,
		"replicas":  replicas,
		"image":     image,
		"status":    "deploying",
	})
}

func (s *Server) resolveImage(image, version string) string {
	if image != "" {
		return image
	}
	if version != "" {
		return fmt.Sprintf("ghcr.io/mikeappsec/lightweightauth:%s", version)
	}
	if s.DefaultImage != "" {
		return s.DefaultImage
	}
	return "ghcr.io/mikeappsec/lightweightauth:latest"
}

func defaultResources() corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}
}

// handleDeleteInstance tears down a provisioned instance. It deletes all
// Kubernetes resources the control plane created for the node — Deployment,
// Service, ConfigMap, and any CP-owned Secret — and then removes it from the
// registry. Resources are selected by the labels the CP stamps at create time
// (app.kubernetes.io/instance + managed-by=lwauth-controlplane), so
// externally-provided objects such as shared or cert-manager-managed TLS
// secrets (which do not carry these labels) are intentionally preserved.
func (s *Server) handleDeleteInstance(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("cluster")
	name := r.PathValue("name")

	inst, ok := s.Registry.Get(cluster, name)
	if !ok {
		writeError(w, http.StatusNotFound, "instance not found")
		return
	}

	namespace := inst.Namespace
	if namespace == "" {
		namespace = "lwauth-system"
	}

	logger := log.FromContext(r.Context())

	// Only tear down cluster resources for CP-provisioned (auto-discovered)
	// nodes. Manually registered external instances have no CP-owned resources;
	// for those we just drop the registry entry.
	if s.KubeClient != nil && inst.Source != discovery.SourceManual {
		selector := client.MatchingLabels{
			"app.kubernetes.io/instance":   name,
			"app.kubernetes.io/managed-by": "lwauth-controlplane",
		}
		inNS := client.InNamespace(namespace)

		// Delete each kind; ignore not-found so delete is idempotent.
		deletions := []struct {
			kind string
			obj  client.Object
		}{
			{"deployment", &appsv1.Deployment{}},
			{"service", &corev1.Service{}},
			{"configmap", &corev1.ConfigMap{}},
			{"secret", &corev1.Secret{}},
		}
		for _, d := range deletions {
			if err := s.KubeClient.DeleteAllOf(r.Context(), d.obj, inNS, selector); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				logger.Error(err, "failed to delete resource during teardown",
					"kind", d.kind, "name", name, "namespace", namespace)
				writeError(w, http.StatusInternalServerError,
					fmt.Sprintf("failed to delete %s: %s", d.kind, err.Error()))
				return
			}
		}
	}

	s.Registry.Deregister(cluster, name)
	logger.Info("instance torn down", "name", name, "namespace", namespace, "cluster", cluster)
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

// --- Route handlers (Phase 3) ---

// handleListRoutes returns all proxy routes.
func (s *Server) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.RouteStore.List())
}

// handleGetRoute returns a single route by name.
func (s *Server) handleGetRoute(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	route, ok := s.RouteStore.Get(name)
	if !ok {
		writeError(w, http.StatusNotFound, "route not found")
		return
	}
	writeJSON(w, http.StatusOK, route)
}

// handleCreateRoute creates a new proxy route.
func (s *Server) handleCreateRoute(w http.ResponseWriter, r *http.Request) {
	var req routes.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	// Validate source instance exists.
	srcCluster := req.Source.Cluster
	if srcCluster == "" {
		srcCluster = "local"
	}
	if _, ok := s.Registry.Get(srcCluster, req.Source.Instance); !ok {
		writeError(w, http.StatusUnprocessableEntity, "source instance not found: "+req.Source.Instance)
		return
	}

	// Validate target instance exists.
	tgtCluster := req.Target.Cluster
	if tgtCluster == "" {
		tgtCluster = "local"
	}
	if _, ok := s.Registry.Get(tgtCluster, req.Target.Instance); !ok {
		writeError(w, http.StatusUnprocessableEntity, "target instance not found: "+req.Target.Instance)
		return
	}

	route, err := s.RouteStore.Create(req)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	logger := log.FromContext(r.Context())
	logger.Info("route created", "name", req.Name, "source", req.Source.Instance, "target", req.Target.Instance)
	writeJSON(w, http.StatusCreated, route)
}

// handleDeleteRoute removes a proxy route.
func (s *Server) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.RouteStore.Delete(name); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

// --- Metrics handlers (Phase 4) ---

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	rollup := s.Aggregator.GetGlobalRollup()
	writeJSON(w, http.StatusOK, rollup)
}

func (s *Server) handleInstanceMetrics(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("cluster")
	name := r.PathValue("name")

	m, ok := s.Aggregator.GetInstanceMetrics(cluster, name)
	if !ok {
		writeError(w, http.StatusNotFound, "no metrics for instance")
		return
	}
	writeJSON(w, http.StatusOK, m)
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
