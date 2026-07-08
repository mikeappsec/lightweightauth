// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package streaming implements WebSocket streams for real-time decisions
// and metrics from the lwauth control plane.
package streaming

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/mikeappsec/lightweightauth/internal/controlplane/discovery"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/metrics"
	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"
)

// Decision represents a single authorization decision from an instance.
type Decision struct {
	Timestamp  time.Time `json:"timestamp"`
	Instance   string    `json:"instance"`
	Cluster    string    `json:"cluster"`
	Subject    string    `json:"subject"`
	Path       string    `json:"path"`
	Method     string    `json:"method"`
	Verdict    string    `json:"verdict"` // "allow" or "deny"
	Reason     string    `json:"reason,omitempty"`
	Tenant     string    `json:"tenant,omitempty"`
	DurationMs float64   `json:"durationMs"`
}

// MetricsSnapshot is a periodic metrics push to connected clients.
type MetricsSnapshot struct {
	Timestamp time.Time                  `json:"timestamp"`
	Global    metrics.GlobalRollup       `json:"global"`
	Instances []*metrics.InstanceMetrics `json:"instances"`
}

// Hub manages WebSocket connections and broadcasts.
type Hub struct {
	Registry   *discovery.Registry
	Aggregator *metrics.Aggregator

	mu              sync.RWMutex
	decisionClients map[*wsClient]bool
	metricsClients  map[*wsClient]bool

	// Decision fan-in channel: instances push decisions here.
	Decisions chan Decision
}

type wsClient struct {
	conn   *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc
	filter DecisionFilter
}

// DecisionFilter allows clients to filter the decision stream.
type DecisionFilter struct {
	Cluster string `json:"cluster,omitempty"`
	Tenant  string `json:"tenant,omitempty"`
	Verdict string `json:"verdict,omitempty"`
}

// NewHub creates a streaming hub.
func NewHub(registry *discovery.Registry, aggregator *metrics.Aggregator) *Hub {
	return &Hub{
		Registry:        registry,
		Aggregator:      aggregator,
		decisionClients: make(map[*wsClient]bool),
		metricsClients:  make(map[*wsClient]bool),
		Decisions:       make(chan Decision, 1000),
	}
}

// Run starts the hub's broadcast loops. Blocks until ctx is cancelled.
func (h *Hub) Run(ctx context.Context) {
	logger := log.FromContext(ctx).WithName("streaming-hub")
	logger.Info("starting streaming hub")

	go h.broadcastDecisions(ctx)
	go h.broadcastMetrics(ctx)
	<-ctx.Done()
}

// HandleDecisionStream is the HTTP handler for WS /v1/controlplane/stream/decisions.
func (h *Hub) HandleDecisionStream(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // Allow any origin for dev.
	})
	if err != nil {
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	client := &wsClient{conn: conn, ctx: ctx, cancel: cancel}

	// Parse filter from query params.
	client.filter = DecisionFilter{
		Cluster: r.URL.Query().Get("cluster"),
		Tenant:  r.URL.Query().Get("tenant"),
		Verdict: r.URL.Query().Get("verdict"),
	}

	h.mu.Lock()
	h.decisionClients[client] = true
	h.mu.Unlock()

	// Block: read until client disconnects.
	defer func() {
		h.mu.Lock()
		delete(h.decisionClients, client)
		h.mu.Unlock()
		cancel()
		conn.Close(websocket.StatusNormalClosure, "")
	}()
	for {
		_, _, err := conn.Read(ctx)
		if err != nil {
			return
		}
	}
}

// HandleMetricsStream is the HTTP handler for WS /v1/controlplane/stream/metrics.
func (h *Hub) HandleMetricsStream(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	client := &wsClient{conn: conn, ctx: ctx, cancel: cancel}

	h.mu.Lock()
	h.metricsClients[client] = true
	h.mu.Unlock()

	// Block: read until client disconnects.
	defer func() {
		h.mu.Lock()
		delete(h.metricsClients, client)
		h.mu.Unlock()
		cancel()
		conn.Close(websocket.StatusNormalClosure, "")
	}()
	for {
		_, _, err := conn.Read(ctx)
		if err != nil {
			return
		}
	}
}

func (h *Hub) broadcastDecisions(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case d := <-h.Decisions:
			h.mu.RLock()
			clients := make([]*wsClient, 0, len(h.decisionClients))
			for c := range h.decisionClients {
				clients = append(clients, c)
			}
			h.mu.RUnlock()

			for _, c := range clients {
				if !matchesFilter(d, c.filter) {
					continue
				}
				// Non-blocking write with timeout.
				writeCtx, writeCancel := context.WithTimeout(c.ctx, 5*time.Second)
				_ = wsjson.Write(writeCtx, c.conn, d)
				writeCancel()
			}
		}
	}
}

func (h *Hub) broadcastMetrics(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snapshot := MetricsSnapshot{
				Timestamp: time.Now(),
				Global:    h.Aggregator.GetGlobalRollup(),
				Instances: h.Aggregator.ListInstanceMetrics(),
			}

			h.mu.RLock()
			clients := make([]*wsClient, 0, len(h.metricsClients))
			for c := range h.metricsClients {
				clients = append(clients, c)
			}
			h.mu.RUnlock()

			for _, c := range clients {
				writeCtx, writeCancel := context.WithTimeout(c.ctx, 5*time.Second)
				_ = wsjson.Write(writeCtx, c.conn, snapshot)
				writeCancel()
			}
		}
	}
}

func matchesFilter(d Decision, f DecisionFilter) bool {
	if f.Cluster != "" && d.Cluster != f.Cluster {
		return false
	}
	if f.Tenant != "" && d.Tenant != f.Tenant {
		return false
	}
	if f.Verdict != "" && d.Verdict != f.Verdict {
		return false
	}
	return true
}

// DecisionCollector scrapes audit/decision streams from instances and fans them into the hub.
type DecisionCollector struct {
	Registry *discovery.Registry
	Hub      *Hub
	Client   *http.Client
	Interval time.Duration
}

// NewDecisionCollector creates a collector that polls instance audit endpoints.
func NewDecisionCollector(registry *discovery.Registry, hub *Hub) *DecisionCollector {
	return &DecisionCollector{
		Registry: registry,
		Hub:      hub,
		Client:   &http.Client{Timeout: 10 * time.Second},
		Interval: 2 * time.Second,
	}
}

// Run starts polling instances for audit decisions. Blocks until ctx is cancelled.
func (dc *DecisionCollector) Run(ctx context.Context) {
	logger := log.FromContext(ctx).WithName("decision-collector")
	logger.Info("starting decision collector")
	ticker := time.NewTicker(dc.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dc.collectAll(ctx)
		}
	}
}

func (dc *DecisionCollector) collectAll(ctx context.Context) {
	instances := dc.Registry.List("")
	for _, inst := range instances {
		dc.collectFromInstance(ctx, inst)
	}
}

func (dc *DecisionCollector) collectFromInstance(ctx context.Context, inst *discovery.Instance) {
	url := inst.AdminURL + "/v1/admin/audit/recent"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}

	resp, err := dc.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	// The data plane returns its canonical audit.Event schema (json
	// tags: ts, decision, latency_ms, …). The control-plane Decision
	// struct uses different json tags (timestamp, verdict, …) so the
	// events are decoded as audit.Event and mapped locally — keeping
	// the WS stream's on-wire Decision shape unchanged for clients.
	var events []audit.Event
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return
	}

	for _, e := range events {
		dec := Decision{
			Timestamp:  e.Timestamp,
			Instance:   inst.Name,
			Cluster:    inst.Cluster,
			Subject:    e.Subject,
			Path:       e.Path,
			Method:     e.Method,
			Verdict:    e.Decision,
			Reason:     e.DenyReason,
			Tenant:     e.Tenant,
			DurationMs: e.LatencyMs,
		}
		select {
		case dc.Hub.Decisions <- dec:
		default:
			// Drop if buffer full.
		}
	}
}
