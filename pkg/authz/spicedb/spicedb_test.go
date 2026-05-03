// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package spicedb

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// fakeSpiceDB implements the v1.PermissionsServiceServer interface minimally.
type fakeSpiceDB struct {
	v1.UnimplementedPermissionsServiceServer
	calls  atomic.Int32
	allow  bool
	err    error
}

func (f *fakeSpiceDB) CheckPermission(_ context.Context, req *v1.CheckPermissionRequest) (*v1.CheckPermissionResponse, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	perm := v1.CheckPermissionResponse_PERMISSIONSHIP_NO_PERMISSION
	if f.allow {
		perm = v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION
	}
	return &v1.CheckPermissionResponse{Permissionship: perm}, nil
}

// startFakeSpiceDB starts a gRPC server implementing PermissionsService.
func startFakeSpiceDB(t *testing.T) (*fakeSpiceDB, string) {
	t.Helper()
	fake := &fakeSpiceDB{allow: true}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	v1.RegisterPermissionsServiceServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.GracefulStop)

	return fake, lis.Addr().String()
}

func newTestAuthorizer(t *testing.T, endpoint string) *authorizer {
	t.Helper()
	cfg := map[string]any{
		"endpoint": endpoint,
		"token":    "test-token",
		"insecure": true,
		"check": map[string]any{
			"resourceType": "document",
			"resourceId":   "{{ index .Request.PathParts 1 }}",
			"permission":   "{{ .Request.Method | lower }}",
			"subjectType":  "user",
			"subjectId":    "{{ .Identity.Subject }}",
		},
	}
	a, err := factory("spicedb-test", cfg)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return a.(*authorizer)
}

func TestSpiceDB_AllowAndDeny(t *testing.T) {
	fake, addr := startFakeSpiceDB(t)
	a := newTestAuthorizer(t, addr)

	r := &module.Request{Method: "GET", Path: "/docs/42"}
	id := &module.Identity{Subject: "alice"}

	// Allow path.
	fake.allow = true
	d, err := a.Authorize(context.Background(), r, id)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !d.Allow {
		t.Fatalf("expected allow, got deny: %s", d.Reason)
	}

	// Deny path.
	fake.allow = false
	d, err = a.Authorize(context.Background(), r, id)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if d.Allow || d.Status != 403 {
		t.Fatalf("expected 403 deny, got %+v", d)
	}
}

func TestSpiceDB_UpstreamErrorWrapsErrUpstream(t *testing.T) {
	fake, addr := startFakeSpiceDB(t)
	fake.err = status.Error(codes.Internal, "boom")
	a := newTestAuthorizer(t, addr)

	_, err := a.Authorize(context.Background(), &module.Request{Method: "GET", Path: "/docs/1"}, &module.Identity{Subject: "bob"})
	if err == nil {
		t.Fatal("expected error on upstream failure")
	}
	if !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("expected ErrUpstream, got %v", err)
	}
}

func TestSpiceDB_EmptyRenderedFieldsDenies(t *testing.T) {
	_, addr := startFakeSpiceDB(t)
	cfg := map[string]any{
		"endpoint": addr,
		"token":    "t",
		"insecure": true,
		"check": map[string]any{
			"resourceType": "document",
			"resourceId":   "  ",
			"permission":   "view",
			"subjectType":  "user",
			"subjectId":    "{{ .Identity.Subject }}",
		},
	}
	a, err := factory("empty-test", cfg)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	d, err := a.Authorize(context.Background(), &module.Request{Method: "GET", Path: "/x"}, &module.Identity{Subject: "u"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if d.Allow {
		t.Fatal("expected deny on empty field")
	}
}

func TestSpiceDB_ConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]any
	}{
		{"missing endpoint", map[string]any{"token": "x", "check": map[string]any{"resourceType": "a", "resourceId": "b", "permission": "c", "subjectType": "d", "subjectId": "e"}}},
		{"missing token", map[string]any{"endpoint": "localhost:50051", "check": map[string]any{"resourceType": "a", "resourceId": "b", "permission": "c", "subjectType": "d", "subjectId": "e"}}},
		{"missing check", map[string]any{"endpoint": "localhost:50051", "token": "x"}},
		{"missing permission", map[string]any{"endpoint": "localhost:50051", "token": "x", "insecure": true, "check": map[string]any{"resourceType": "a", "resourceId": "b", "subjectType": "d", "subjectId": "e"}}},
		{"bad template", map[string]any{"endpoint": "localhost:50051", "token": "x", "insecure": true, "check": map[string]any{"resourceType": "{{ .Bad", "resourceId": "b", "permission": "c", "subjectType": "d", "subjectId": "e"}}},
		{"bad timeout", map[string]any{"endpoint": "localhost:50051", "token": "x", "insecure": true, "timeout": "nope", "check": map[string]any{"resourceType": "a", "resourceId": "b", "permission": "c", "subjectType": "d", "subjectId": "e"}}},
		{"zero timeout", map[string]any{"endpoint": "localhost:50051", "token": "x", "insecure": true, "timeout": "0s", "check": map[string]any{"resourceType": "a", "resourceId": "b", "permission": "c", "subjectType": "d", "subjectId": "e"}}},
		{"negative timeout", map[string]any{"endpoint": "localhost:50051", "token": "x", "insecure": true, "timeout": "-1s", "check": map[string]any{"resourceType": "a", "resourceId": "b", "permission": "c", "subjectType": "d", "subjectId": "e"}}},
		{"bad consistency", map[string]any{"endpoint": "localhost:50051", "token": "x", "insecure": true, "consistency": "invalid", "check": map[string]any{"resourceType": "a", "resourceId": "b", "permission": "c", "subjectType": "d", "subjectId": "e"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := factory("cfg-test", tc.cfg)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if !errors.Is(err, module.ErrConfig) {
				t.Fatalf("expected ErrConfig, got %v", err)
			}
		})
	}
}

func TestSpiceDB_BreakerTripsAfterRepeatedFailures(t *testing.T) {
	fake, addr := startFakeSpiceDB(t)
	fake.err = status.Error(codes.Internal, "overload")

	cfg := map[string]any{
		"endpoint": addr,
		"token":    "t",
		"insecure": true,
		"check": map[string]any{
			"resourceType": "doc",
			"resourceId":   "1",
			"permission":   "view",
			"subjectType":  "user",
			"subjectId":    "{{ .Identity.Subject }}",
		},
		"resilience": map[string]any{
			"breaker": map[string]any{
				"failureThreshold": 3,
				"coolDown":         "1h",
			},
		},
	}
	a, err := factory("breaker-test", cfg)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	r := &module.Request{Method: "GET", Path: "/docs/1"}
	id := &module.Identity{Subject: "alice"}

	for i := 0; i < 3; i++ {
		_, err := a.Authorize(context.Background(), r, id)
		if !errors.Is(err, module.ErrUpstream) {
			t.Fatalf("call #%d: expected ErrUpstream, got %v", i, err)
		}
	}
	callsBefore := fake.calls.Load()

	_, err = a.Authorize(context.Background(), r, id)
	if !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("post-trip: expected ErrUpstream, got %v", err)
	}
	if got := fake.calls.Load(); got != callsBefore {
		t.Fatalf("breaker did not short-circuit: calls before=%d after=%d", callsBefore, got)
	}
}

func TestSpiceDB_DenyReasonIsGeneric(t *testing.T) {
	fake, addr := startFakeSpiceDB(t)
	fake.allow = false
	a := newTestAuthorizer(t, addr)

	d, err := a.Authorize(context.Background(), &module.Request{Method: "GET", Path: "/docs/42"}, &module.Identity{Subject: "alice"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	// Deny reason must NOT leak resource/subject details.
	if strings.Contains(d.Reason, "alice") || strings.Contains(d.Reason, "42") || strings.Contains(d.Reason, "document") {
		t.Fatalf("deny reason leaks internal details: %q", d.Reason)
	}
	if d.Reason != "spicedb: permission denied" {
		t.Fatalf("unexpected deny reason: %q", d.Reason)
	}
}

func TestSpiceDB_RenderedLengthCap(t *testing.T) {
	_, addr := startFakeSpiceDB(t)
	// Use a template that produces >1024 chars from a long path.
	longPath := "/" + strings.Repeat("a", 1100) + "/resource"
	cfg := map[string]any{
		"endpoint": addr,
		"token":    "t",
		"insecure": true,
		"check": map[string]any{
			"resourceType": "doc",
			"resourceId":   "{{ index .Request.PathParts 0 }}",
			"permission":   "view",
			"subjectType":  "user",
			"subjectId":    "{{ .Identity.Subject }}",
		},
	}
	a, err := factory("len-test", cfg)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	_, err = a.Authorize(context.Background(), &module.Request{Method: "GET", Path: longPath}, &module.Identity{Subject: "u"})
	if err == nil {
		t.Fatal("expected error for oversized rendered output")
	}
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
}

func TestSpiceDB_ConditionalPermissionReturnsError(t *testing.T) {
	// Fake returns CONDITIONAL permissionship.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	cond := &conditionalFakeSpiceDB{}
	v1.RegisterPermissionsServiceServer(srv, cond)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.GracefulStop)

	cfg := map[string]any{
		"endpoint": lis.Addr().String(),
		"token":    "t",
		"insecure": true,
		"check": map[string]any{
			"resourceType": "doc",
			"resourceId":   "1",
			"permission":   "view",
			"subjectType":  "user",
			"subjectId":    "{{ .Identity.Subject }}",
		},
	}
	a, err := factory("cond-test", cfg)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	_, err = a.Authorize(context.Background(), &module.Request{Method: "GET", Path: "/docs/1"}, &module.Identity{Subject: "bob"})
	if err == nil {
		t.Fatal("expected error for conditional permission")
	}
	if !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("expected ErrUpstream, got %v", err)
	}
}

type conditionalFakeSpiceDB struct {
	v1.UnimplementedPermissionsServiceServer
}

func (c *conditionalFakeSpiceDB) CheckPermission(_ context.Context, _ *v1.CheckPermissionRequest) (*v1.CheckPermissionResponse, error) {
	return &v1.CheckPermissionResponse{
		Permissionship: v1.CheckPermissionResponse_PERMISSIONSHIP_CONDITIONAL_PERMISSION,
	}, nil
}

func TestSpiceDB_FullyConsistentConfig(t *testing.T) {
	_, addr := startFakeSpiceDB(t)
	cfg := map[string]any{
		"endpoint":    addr,
		"token":       "t",
		"insecure":    true,
		"consistency": "fully_consistent",
		"check": map[string]any{
			"resourceType": "doc",
			"resourceId":   "1",
			"permission":   "view",
			"subjectType":  "user",
			"subjectId":    "{{ .Identity.Subject }}",
		},
	}
	a, err := factory("consistency-test", cfg)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	d, err := a.Authorize(context.Background(), &module.Request{Method: "GET", Path: "/docs/1"}, &module.Identity{Subject: "alice"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !d.Allow {
		t.Fatalf("expected allow, got deny: %s", d.Reason)
	}
}
