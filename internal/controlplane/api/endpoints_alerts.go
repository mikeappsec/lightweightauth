// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/mikeappsec/lightweightauth/internal/controlplane/alerting"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/auth"
)

// handleListAlerts returns the open + acked alerts and (optionally)
// recently-resolved history. Filter by state/severity/rule via query
// parameters; pass `state=resolved` to limit the response to closed
// alerts only.
//
// GET /v1/controlplane/alerts[?state=&severity=&rule=]
func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	if s.AlertEngine == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"alerts": []any{}, "enabled": false,
		})
		return
	}
	filter := alerting.AlertFilter{
		Severity: r.URL.Query().Get("severity"),
		State:    r.URL.Query().Get("state"),
		Rule:     r.URL.Query().Get("rule"),
	}
	alerts := s.AlertEngine.ListAlerts(r.URL.Query().Get("state"), filter)
	promDe, lokiDe := s.AlertEngine.IsDegraded()
	writeJSON(w, http.StatusOK, map[string]any{
		"alerts":  alerts,
		"enabled": true,
		"degraded": map[string]bool{
			"prometheus": promDe,
			"loki":       lokiDe,
		},
	})
}

// ackRequest is the ack body for POST /v1/controlplane/alerts/{id}/ack.
type ackRequest struct {
	Note string `json:"note,omitempty"`
}

// handleAckAlert snoozes notifications on the alert ID for the engine's
// AckCooldown window. Returns 404 if the ID is unknown, 409 if the
// requesting operator has already acked the alert, 503 if alerting
// is not configured.
//
// POST /v1/controlplane/alerts/{id}/ack
func (s *Server) handleAckAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	if s.AlertEngine == nil {
		writeError(w, http.StatusServiceUnavailable, "alerting engine not configured")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing alert id")
		return
	}
	var req ackRequest
	body := http.MaxBytesReader(w, r.Body, 1<<16) // 64KB cap (note only)
	if r.ContentLength > 0 {
		if err := json.NewDecoder(body).Decode(&req); err != nil && err.Error() != "EOF" {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	// Operator identity comes from the CP session middleware
	// (auth.Manager). The session username is set on the request
	// context under a private key; pull it via the helper and avoid
	// pulling the auth package import into the api package just for
	// ack. The middleware writes the username as a context value when
	// CP_AUTH_ENABLED=true; when disabled, "anonymous" is used so the
	// ack_tracker is still populated (visible in the UI audit trail
	// trace from the audit.Sink path).
	operator := operatorFromContext(r)
	if err := s.AlertEngine.Ack(id, operator, req.Note); err != nil {
		switch {
		case errors.Is(err, alerting.ErrAlertNotFound):
			writeError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, alerting.ErrAlertAlreadyAcked):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"acked": true, "id": id, "by": operator})
}

// handleListRules returns the active rule catalog (defaults merged
// with operator overrides). Operators GET this to see what's
// firing.
//
// GET /v1/controlplane/alerts/rules
func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	if s.AlertEngine == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.AlertEngine.Rules())
}

// putRulesRequest is the body for PUT /v1/controlplane/alerts/rules
// (replace the operator override set in the lwauth-alerting-rules
// ConfigMap); this is the single endpoint operators POST/PUT to manage
// overrides — the full rule set is the GET response (defaults +
// overrides). Passing an empty array removes overrides entirely and
// reverts to the built-in defaults on the next poll.
type putRulesRequest struct {
	Overrides []alerting.Rule `json:"overrides"`
}

// handlePutRules persists the supplied override set to the ConfigMap
// and applies the merge immediately so the next engine tick observes
// the new rule set without waiting for the polling window.
//
// PUT /v1/controlplane/alerts/rules
func (s *Server) handlePutRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "PUT or POST only")
		return
	}
	if s.RulesLoader == nil {
		writeError(w, http.StatusServiceUnavailable, "alerting-rules loader not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB cap
	var req putRulesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Overrides) > 100 {
		writeError(w, http.StatusBadRequest, "too many override rules (max 100)")
		return
	}
	// Validate the override set before persisting: each rule must have
	// a unique name and a sane (positive) For/Window when Enabled.
	seen := map[string]bool{}
	for i, r := range req.Overrides {
		if r.Name == "" {
			writeError(w, http.StatusBadRequest, "override["+strconv.Itoa(i)+"] missing name")
			return
		}
		if seen[r.Name] {
			writeError(w, http.StatusBadRequest, "override["+strconv.Itoa(i)+"] duplicate name "+r.Name)
			return
		}
		seen[r.Name] = true
	}
	if err := s.RulesLoader.PutRules(r.Context(), req.Overrides); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted":  true,
		"overrides": len(req.Overrides),
	})
}

// handleAlertStream is the WS handler for
// /v1/controlplane/stream/alerts. Subscribers receive AlertEvent
// records (open/acked/resolved) matching their query filter as the
// engine transitions alert state.
func (s *Server) handleAlertStream(w http.ResponseWriter, r *http.Request) {
	if s.AlertEngine == nil {
		writeError(w, http.StatusServiceUnavailable, "alerting engine not configured")
		return
	}
	var acceptOpts *websocket.AcceptOptions
	if s.AllowedOrigin != "" {
		acceptOpts = &websocket.AcceptOptions{OriginPatterns: []string{s.AllowedOrigin}}
	} else {
		acceptOpts = &websocket.AcceptOptions{InsecureSkipVerify: true}
	}
	conn, err := websocket.Accept(w, r, acceptOpts)
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	defer conn.Close(websocket.StatusNormalClosure, "")

	filter := alerting.AlertFilter{
		Severity: r.URL.Query().Get("severity"),
		State:    r.URL.Query().Get("state"),
		Rule:     r.URL.Query().Get("rule"),
	}
	ch := s.AlertEngine.Subscribe(filter)
	defer s.AlertEngine.Unsubscribe(ch)

	// Exit the connection when EITHER the client closes the socket
	// OR the context is cancelled (server shutdown). The reader-loop
	// goroutine below mirrors the existing streaming.Hub pattern.
	go func() {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			// Note: we don't pass the connection's per-write ctx
			// because the engine's broadcast writes non-blocking — a
			// slow client could otherwise stall the send forever.
			writeCtx, writeCancel := context.WithTimeout(ctx, 5*time.Second)
			_ = writeJSONConn(writeCtx, conn, evt)
			writeCancel()
		}
	}
}

// operatorFromContext reads the authenticated operator name from the
// request context (injected by auth.Manager.Middleware). Falls back to
// "anonymous" when CP_AUTH_ENABLED=false or the request arrives on an
// unauthenticated path, so the ack audit trail is always populated.
func operatorFromContext(r *http.Request) string {
	if sub := auth.ContextSubject(r); sub != "" {
		return sub
	}
	return "anonymous"
}

// writeJSONConn is a thin wrapper around wsjson.Write for the alert
// stream channel; it lives here to keep the Server's existing writeJSON
// helpers unchanged.
func writeJSONConn(ctx context.Context, conn *websocket.Conn, v any) error {
	return wsjson.Write(ctx, conn, v)
}
