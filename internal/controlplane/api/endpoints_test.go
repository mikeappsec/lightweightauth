// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/mikeappsec/lightweightauth/internal/controlplane/api"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/configmgmt"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/discovery"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/metrics"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/multicluster"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/routes"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/streaming"
)

func newTestServer(t *testing.T) *api.Server {
	t.Helper()
	registry := discovery.NewRegistry()
	aggregator := metrics.NewAggregator(registry)
	clusterMgr := multicluster.NewManager(registry)
	configStore := configmgmt.NewStore()
	routeStore := routes.NewStore(registry)
	hub := streaming.NewHub(registry, aggregator)
	kubeClient := fake.NewClientBuilder().Build()
	return api.NewServer(registry, clusterMgr, configStore, routeStore, aggregator, hub, kubeClient, "")
}

func registerInstance(s *api.Server, name, cluster, namespace, adminURL string) {
	s.Registry.Register(&discovery.Instance{
		Name:      name,
		Cluster:   cluster,
		Namespace: namespace,
		AdminURL:  adminURL,
		Source:    discovery.SourceManual,
		Status: discovery.Status{
			Healthy:  true,
			Ready:    true,
			Replicas: "2/2",
		},
	})
}

// ── GET /instances/{cluster}/{name}/endpoints ──────────────────────────────

func TestHandleGetEndpoints_NotFound(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/controlplane/instances/local/missing/endpoints", nil)
	req.SetPathValue("cluster", "local")
	req.SetPathValue("name", "missing")
	rr := httptest.NewRecorder()

	s.Mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleGetEndpoints_ReturnsHTTPAndGRPC(t *testing.T) {
	s := newTestServer(t)
	registerInstance(s, "payments-auth", "local", "payments", "http://payments-auth.payments.svc:8080")

	req := httptest.NewRequest(http.MethodGet, "/v1/controlplane/instances/local/payments-auth/endpoints", nil)
	req.SetPathValue("cluster", "local")
	req.SetPathValue("name", "payments-auth")
	rr := httptest.NewRecorder()

	s.Mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var endpoints api.NodeEndpoints
	if err := json.NewDecoder(rr.Body).Decode(&endpoints); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	// Internal HTTP should include port 8080.
	if !strings.Contains(endpoints.HTTP.Internal, ":8080") {
		t.Errorf("expected :8080 in HTTP internal, got %q", endpoints.HTTP.Internal)
	}

	// Internal gRPC should include port 9001.
	if !strings.Contains(endpoints.GRPC.Internal, ":9001") {
		t.Errorf("expected :9001 in gRPC internal, got %q", endpoints.GRPC.Internal)
	}

	// Envoy config should reference the service name.
	if !strings.Contains(endpoints.ExtAuthz.EnvoyClusterYAML, "payments-auth") {
		t.Errorf("expected Envoy config to contain service name, got %q", endpoints.ExtAuthz.EnvoyClusterYAML)
	}

	// ExtAuthz port should be 9001.
	if endpoints.ExtAuthz.Port != 9001 {
		t.Errorf("expected ext_authz port 9001, got %d", endpoints.ExtAuthz.Port)
	}

	// Load balancing strategy set.
	if endpoints.LoadBalancing.Strategy == "" {
		t.Error("expected non-empty load balancing strategy")
	}
}

func TestHandleGetEndpoints_ReplicasParsed(t *testing.T) {
	s := newTestServer(t)
	inst := &discovery.Instance{
		Name:      "svc",
		Cluster:   "local",
		Namespace: "default",
		AdminURL:  "http://svc.default.svc:8080",
		Source:    discovery.SourceManual,
		Status:    discovery.Status{Healthy: true, Ready: true, Replicas: "3/5"},
	}
	s.Registry.Register(inst)

	req := httptest.NewRequest(http.MethodGet, "/v1/controlplane/instances/local/svc/endpoints", nil)
	req.SetPathValue("cluster", "local")
	req.SetPathValue("name", "svc")
	rr := httptest.NewRecorder()
	s.Mux.ServeHTTP(rr, req)

	var endpoints api.NodeEndpoints
	_ = json.NewDecoder(rr.Body).Decode(&endpoints)

	if endpoints.LoadBalancing.ReadyReplicas != 3 {
		t.Errorf("expected ready=3, got %d", endpoints.LoadBalancing.ReadyReplicas)
	}
	if endpoints.LoadBalancing.TotalReplicas != 5 {
		t.Errorf("expected total=5, got %d", endpoints.LoadBalancing.TotalReplicas)
	}
}

func TestHandleGetEndpoints_ExternalURLDerived(t *testing.T) {
	s := newTestServer(t)
	// Register with an external-looking admin URL.
	registerInstance(s, "ext-node", "local", "lwauth", "https://ext-node.lwauth.example.com/admin")

	req := httptest.NewRequest(http.MethodGet, "/v1/controlplane/instances/local/ext-node/endpoints", nil)
	req.SetPathValue("cluster", "local")
	req.SetPathValue("name", "ext-node")
	rr := httptest.NewRecorder()
	s.Mux.ServeHTTP(rr, req)

	var endpoints api.NodeEndpoints
	_ = json.NewDecoder(rr.Body).Decode(&endpoints)

	// External URL should be derived from the admin URL hostname.
	if endpoints.HTTP.External == "" {
		t.Error("expected non-empty external HTTP URL for externally-registered instance")
	}
	if !strings.HasPrefix(endpoints.HTTP.External, "https://") {
		t.Errorf("expected https:// prefix on external URL, got %q", endpoints.HTTP.External)
	}
}

// ── POST /instances/{cluster}/{name}/test ──────────────────────────────────

func TestHandleQuickTest_NotFound(t *testing.T) {
	s := newTestServer(t)

	body := `{"protocol":"http","method":"GET","path":"/"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/controlplane/instances/local/missing/test",
		strings.NewReader(body))
	req.SetPathValue("cluster", "local")
	req.SetPathValue("name", "missing")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.Mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleQuickTest_NoAdminURL(t *testing.T) {
	s := newTestServer(t)
	s.Registry.Register(&discovery.Instance{
		Name:    "no-admin",
		Cluster: "local",
		Source:  discovery.SourceManual,
		Status:  discovery.Status{Healthy: true},
	})

	body := `{"protocol":"http","method":"GET","path":"/"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/controlplane/instances/local/no-admin/test",
		strings.NewReader(body))
	req.SetPathValue("cluster", "local")
	req.SetPathValue("name", "no-admin")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.Mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", rr.Code)
	}
}

func TestHandleQuickTest_ProxiesToExplain(t *testing.T) {
	// Spin up a fake explain server.
	explainCalled := false
	fakeLwauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/admin/explain" {
			explainCalled = true
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"allow":      true,
				"statusCode": 200,
				"latency":    "5ms",
				"identity": map[string]any{
					"sub":   "alice",
					"roles": []string{"admin"},
				},
				"headers": map[string]any{
					"X-Auth-Subject": "alice",
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer fakeLwauth.Close()

	s := newTestServer(t)
	registerInstance(s, "test-svc", "local", "default", fakeLwauth.URL)

	body := `{"protocol":"http","method":"GET","path":"/api/v1/data","headers":{"Authorization":"Bearer tok"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/controlplane/instances/local/test-svc/test",
		strings.NewReader(body))
	req.SetPathValue("cluster", "local")
	req.SetPathValue("name", "test-svc")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.Mux.ServeHTTP(rr, req)

	if !explainCalled {
		t.Fatal("expected /v1/admin/explain to be called on the fake lwauth server")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp api.QuickTestResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if resp.Status != "allow" {
		t.Errorf("expected status 'allow', got %q", resp.Status)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected statusCode 200, got %d", resp.StatusCode)
	}
	if resp.Latency != "5ms" {
		t.Errorf("expected latency '5ms', got %q", resp.Latency)
	}
	if resp.Identity == nil {
		t.Error("expected non-nil identity")
	}
	if resp.Headers["X-Auth-Subject"] != "alice" {
		t.Errorf("expected X-Auth-Subject=alice, got %q", resp.Headers["X-Auth-Subject"])
	}
}

func TestHandleQuickTest_DenyResponse(t *testing.T) {
	fakeLwauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"allow":      false,
			"statusCode": 403,
			"denyReason": "missing required role: admin",
		})
	}))
	defer fakeLwauth.Close()

	s := newTestServer(t)
	registerInstance(s, "deny-svc", "local", "default", fakeLwauth.URL)

	body := `{"protocol":"http","method":"POST","path":"/admin"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/controlplane/instances/local/deny-svc/test",
		strings.NewReader(body))
	req.SetPathValue("cluster", "local")
	req.SetPathValue("name", "deny-svc")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Mux.ServeHTTP(rr, req)

	var resp api.QuickTestResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Status != "deny" {
		t.Errorf("expected 'deny', got %q", resp.Status)
	}
	if resp.StatusCode != 403 {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
	if !strings.Contains(resp.DenyReason, "admin") {
		t.Errorf("expected deny reason to mention 'admin', got %q", resp.DenyReason)
	}
}

func TestHandleQuickTest_UnreachableInstance(t *testing.T) {
	s := newTestServer(t)
	// Register with a port that is definitely not listening.
	registerInstance(s, "unreachable", "local", "default", "http://127.0.0.1:19999")

	body := `{"protocol":"http","method":"GET","path":"/"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/controlplane/instances/local/unreachable/test",
		strings.NewReader(body))
	req.SetPathValue("cluster", "local")
	req.SetPathValue("name", "unreachable")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Mux.ServeHTTP(rr, req)

	// Should return 200 with an error field (not a hard 500).
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error payload, got %d", rr.Code)
	}

	var resp api.QuickTestResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Error == "" {
		t.Error("expected non-empty error field for unreachable instance")
	}
}
