// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/mikeappsec/lightweightauth/internal/controlplane/alerting"
)

// registerAnalyticsRoutes wires the Phase 4 analytics endpoints.
// Safe to call multiple times — routes are idempotent on the mux.
// The handlers nil-check s.AnalyticsService so endpoints respond
// with a 503 "not configured" stub in local-dev.
func (s *Server) registerAnalyticsRoutes() {
	s.Mux.HandleFunc("GET /v1/controlplane/analytics/decisions", s.handleAnalyticsDecisions)
	s.Mux.HandleFunc("GET /v1/controlplane/analytics/latency", s.handleAnalyticsLatency)
	s.Mux.HandleFunc("GET /v1/controlplane/analytics/latency/quantiles", s.handleAnalyticsLatencyQuantiles)
	s.Mux.HandleFunc("GET /v1/controlplane/analytics/policy", s.handleAnalyticsPolicy)
	s.Mux.HandleFunc("GET /v1/controlplane/analytics/top/{dimension}", s.handleAnalyticsTop)
}

// parseWindowParam extracts the ?window= query parameter (default 1h,
// max 24h) and the ?step= parameter (default 1m, min 15s) from the
// request. Returns normalised durations.
func parseWindowStep(r *http.Request) (time.Duration, time.Duration) {
	window := 1 * time.Hour
	if v := r.URL.Query().Get("window"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 && d <= 24*time.Hour {
			window = d
		}
	}
	step := 1 * time.Minute
	if v := r.URL.Query().Get("step"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 15*time.Second {
			step = d
		}
	}
	return window, step
}

// handleAnalyticsDecisions returns a time-series of decision counts
// broken down by outcome (allow/deny/error) over the given window.
//
// GET /v1/controlplane/analytics/decisions?window=1h&step=1m&groupBy=outcome
func (s *Server) handleAnalyticsDecisions(w http.ResponseWriter, r *http.Request) {
	if s.AnalyticsService == nil {
		writeError(w, http.StatusServiceUnavailable, "analytics service not configured")
		return
	}
	window, step := parseWindowStep(r)
	groupBy := r.URL.Query().Get("groupBy")
	if groupBy == "" {
		groupBy = "outcome"
	}
	switch groupBy {
	case "outcome", "tenant", "authorizer", "identifier":
	default:
		writeError(w, http.StatusBadRequest, "unsupported groupBy")
		return
	}
	resp, err := s.AnalyticsService.DecisionTimeSeries(r.Context(), window, step, groupBy)
	if err != nil {
		if errors.Is(err, alerting.ErrDegraded) {
			writeError(w, http.StatusServiceUnavailable, "prometheus backend not configured")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAnalyticsLatency returns the latency-distribution histogram
// (cumulative bucket counts) for the given window.
//
// GET /v1/controlplane/analytics/latency?window=1h
func (s *Server) handleAnalyticsLatency(w http.ResponseWriter, r *http.Request) {
	if s.AnalyticsService == nil {
		writeError(w, http.StatusServiceUnavailable, "analytics service not configured")
		return
	}
	window, _ := parseWindowStep(r)
	resp, err := s.AnalyticsService.LatencyHistogram(r.Context(), window)
	if err != nil {
		if errors.Is(err, alerting.ErrDegraded) {
			writeError(w, http.StatusServiceUnavailable, "prometheus backend not configured")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAnalyticsLatencyQuantiles returns P50/P90/P99 as time-series
// for the latency-trend chart.
//
// GET /v1/controlplane/analytics/latency/quantiles?window=1h&step=1m
func (s *Server) handleAnalyticsLatencyQuantiles(w http.ResponseWriter, r *http.Request) {
	if s.AnalyticsService == nil {
		writeError(w, http.StatusServiceUnavailable, "analytics service not configured")
		return
	}
	window, step := parseWindowStep(r)
	resp, err := s.AnalyticsService.LatencyQuantiles(r.Context(), window, step)
	if err != nil {
		if errors.Is(err, alerting.ErrDegraded) {
			writeError(w, http.StatusServiceUnavailable, "prometheus backend not configured")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAnalyticsPolicy returns the per-policy-version breakdown
// (allow/deny/error counts, shadow/canary disagreement rates).
//
// GET /v1/controlplane/analytics/policy?window=1h
func (s *Server) handleAnalyticsPolicy(w http.ResponseWriter, r *http.Request) {
	if s.AnalyticsService == nil {
		writeError(w, http.StatusServiceUnavailable, "analytics service not configured")
		return
	}
	window, _ := parseWindowStep(r)
	resp, err := s.AnalyticsService.PolicyBreakdown(r.Context(), window)
	if err != nil {
		if errors.Is(err, alerting.ErrDegraded) {
			writeError(w, http.StatusServiceUnavailable, "prometheus backend not configured")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAnalyticsTop returns the top-N entries for a given dimension
// (tenant, authorizer, identifier).
//
// GET /v1/controlplane/analytics/top/{dimension}?window=1h&limit=10
func (s *Server) handleAnalyticsTop(w http.ResponseWriter, r *http.Request) {
	if s.AnalyticsService == nil {
		writeError(w, http.StatusServiceUnavailable, "analytics service not configured")
		return
	}
	dimension := r.PathValue("dimension")
	if dimension == "" {
		writeError(w, http.StatusBadRequest, "missing dimension")
		return
	}
	window, _ := parseWindowStep(r)
	limit := 10
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 50 {
			limit = n
		}
	}
	resp, err := s.AnalyticsService.TopDimension(r.Context(), dimension, window, limit)
	if err != nil {
		if errors.Is(err, alerting.ErrDegraded) {
			writeError(w, http.StatusServiceUnavailable, "prometheus backend not configured")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}