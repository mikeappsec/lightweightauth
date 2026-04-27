package headers

import (
	"context"
	"testing"

	"github.com/yourorg/lightweightauth/pkg/module"
)

func TestHeaderAdd_LiteralAndExpansion(t *testing.T) {
	t.Parallel()
	m, err := module.BuildMutator("header-add", "h", map[string]any{
		"subjectHeader": "X-Auth-Subject",
		"upstream": map[string]any{
			"X-User-Email": "${claim:email}",
			"X-Static":     "literal",
		},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	d := &module.Decision{}
	id := &module.Identity{Subject: "alice", Claims: map[string]any{"email": "a@b.com"}}
	if err := m.Mutate(context.Background(), &module.Request{}, id, d); err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if d.UpstreamHeaders["X-Auth-Subject"] != "alice" {
		t.Errorf("subject hdr = %q", d.UpstreamHeaders["X-Auth-Subject"])
	}
	if d.UpstreamHeaders["X-User-Email"] != "a@b.com" {
		t.Errorf("email hdr = %q", d.UpstreamHeaders["X-User-Email"])
	}
	if d.UpstreamHeaders["X-Static"] != "literal" {
		t.Errorf("static hdr = %q", d.UpstreamHeaders["X-Static"])
	}
}

func TestHeaderRemove(t *testing.T) {
	t.Parallel()
	m, err := module.BuildMutator("header-remove", "r",
		map[string]any{"upstream": []any{"Authorization", "Cookie"}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	d := &module.Decision{}
	if err := m.Mutate(context.Background(), &module.Request{}, nil, d); err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if v, ok := d.UpstreamHeaders["Authorization"]; !ok || v != "" {
		t.Errorf("Authorization not deleted: %v", d.UpstreamHeaders)
	}
}

func TestHeaderPassthrough(t *testing.T) {
	t.Parallel()
	m, err := module.BuildMutator("header-passthrough", "p",
		map[string]any{"headers": []any{"X-Request-ID", "X-Trace-Id"}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	d := &module.Decision{}
	r := &module.Request{Headers: map[string][]string{
		"X-Request-Id": {"abc-123"},
		"X-Trace-Id":   {"trace-1"},
	}}
	if err := m.Mutate(context.Background(), r, nil, d); err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if d.UpstreamHeaders["X-Request-ID"] != "abc-123" {
		t.Errorf("X-Request-ID = %q", d.UpstreamHeaders["X-Request-ID"])
	}
	if d.UpstreamHeaders["X-Trace-Id"] != "trace-1" {
		t.Errorf("X-Trace-Id = %q", d.UpstreamHeaders["X-Trace-Id"])
	}
}
