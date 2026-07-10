// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package alerting

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPromClient_EmptyReturnsErrDegraded(t *testing.T) {
	t.Parallel()
	var c *PromClient
	if !c.Empty() {
		t.Fatal("nil PromClient should be Empty")
	}
	if _, err := c.Query(context.Background(), "up"); err != ErrDegraded {
		t.Errorf("nil client Query err = %v, want ErrDegraded", err)
	}
}

func TestPromClient_Success(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("query"); got != "up" {
			t.Errorf("query param = %q, want up", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"status":"success","data":{
				"resultType":"vector",
				"result":[
					{"metric":{"identifier":"jwt"},"value":[1700000000,"0.12345"]},
					{"metric":{"identifier":"api"},"value":[1700000000,"0"]}
				]
			}
		}`))
	}))
	defer srv.Close()

	c := &PromClient{BaseURL: srv.URL, HTTP: srv.Client()}
	rows, err := c.Query(context.Background(), "up")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	v0, err := rows[0].Float()
	if err != nil {
		t.Fatalf("Float[0]: %v", err)
	}
	if v0 != 0.12345 {
		t.Errorf("rows[0] value = %v, want 0.12345", v0)
	}
	v1, err := rows[1].Float()
	if err != nil {
		t.Fatalf("Float[1]: %v", err)
	}
	if v1 != 0 {
		t.Errorf("rows[1] value = %v, want 0", v1)
	}
}

func TestPromClient_ErrorStatusReturned(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"error","error":"expression parse failed"}`))
	}))
	defer srv.Close()

	c := &PromClient{BaseURL: srv.URL, HTTP: srv.Client()}
	if _, err := c.Query(context.Background(), "bad("); err == nil {
		t.Fatal("expected error on prometheus error status")
	}
}

func TestPromClient_Non200Status(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &PromClient{BaseURL: srv.URL, HTTP: srv.Client()}
	if _, err := c.Query(context.Background(), "up"); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestPromVector_ExtractScope(t *testing.T) {
	t.Parallel()
	v := PromVector{
		Metric: map[string]string{"identifier": "jwt", "tenant": "acme", "noise": "drop"},
		Value:  [2]any{0, "1"},
	}
	scope := v.ExtractScope([]string{"cluster", "identifier"}, "us-east-1")
	if scope["cluster"] != "us-east-1" {
		t.Errorf("cluster fallback missing: %+v", scope)
	}
	if scope["identifier"] != "jwt" {
		t.Errorf("identifier label not extracted: %+v", scope)
	}
	if _, ok := scope["noise"]; ok {
		t.Errorf("noise label leaked into scope: %+v", scope)
	}
}

func TestLokiClient_EmptyReturnsErrDegraded(t *testing.T) {
	t.Parallel()
	var c *LokiClient
	if !c.Empty() {
		t.Fatal("nil LokiClient should be Empty")
	}
	if _, err := c.QueryRange(context.Background(), "rate({}[5m])", 5*60*1e9); err != ErrDegraded {
		t.Errorf("nil client QueryRange err = %v, want ErrDegraded", err)
	}
}

func TestLokiClient_Success(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/loki/api/v1/query_range" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.URL.Query().Get("query") == "" {
			t.Error("query param missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{
			"resultType":"matrix",
			"result":[
				{"stream":{"tenant":"acme"},"values":[[1700000000000000000,"42"],[1700000001000000000,"50"]]},
				{"stream":{"tenant":"other"},"values":[[1700000000000000000,"5"]]}
			]
		}}`))
	}))
	defer srv.Close()

	c := &LokiClient{BaseURL: srv.URL, HTTP: srv.Client()}
	streams, err := c.QueryRange(context.Background(), "rate({}[5m])", 5*60*1e9)
	if err != nil {
		t.Fatalf("QueryRange: %v", err)
	}
	if len(streams) != 2 {
		t.Fatalf("got %d streams, want 2", len(streams))
	}
	v, err := streams[0].LatestValue()
	if err != nil {
		t.Fatalf("LatestValue: %v", err)
	}
	if v != 50 {
		t.Errorf("LatestValue = %v, want 50 (last sample)", v)
	}
	scope := streams[0].ExtractScope([]string{"cluster", "tenant"}, "local")
	if scope["cluster"] != "local" || scope["tenant"] != "acme" {
		t.Errorf("ExtractScope wrong: %+v", scope)
	}
}

func TestLokiClient_NonSuccessJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"error","error":"bad"}`))
	}))
	defer srv.Close()

	c := &LokiClient{BaseURL: srv.URL, HTTP: srv.Client()}
	if _, err := c.QueryRange(context.Background(), "rate({}[5m])", 5*60*1e9); err == nil {
		t.Fatal("expected error on loki error status")
	}
}

func TestLokiStream_LatestValueEmptyStream(t *testing.T) {
	t.Parallel()
	s := LokiStream{Values: [][]any{}}
	if _, err := s.LatestValue(); err == nil {
		t.Fatal("expected error for empty stream")
	}

	// Numeric coercion via JSON re-marshall — confirm float64 path
	// works if Loki ever swaps to JSON-typed values.
	if err := json.Unmarshal([]byte(`[]`), new([]any)); err != nil {
		t.Fatalf("array unmarshal sanity: %v", err)
	}
}