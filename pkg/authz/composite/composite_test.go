package composite

import (
	"context"
	"errors"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

type stub struct {
	name string
	dec  *module.Decision
	err  error
}

func (s *stub) Name() string { return s.name }
func (s *stub) Authorize(_ context.Context, _ *module.Request, _ *module.Identity) (*module.Decision, error) {
	return s.dec, s.err
}

func mkComposite(t *testing.T, k kind, children ...module.Authorizer) *authorizer {
	t.Helper()
	return &authorizer{name: "c", kind: k, children: children}
}

func TestAnyOf_AllowsOnFirstAllow(t *testing.T) {
	t.Parallel()
	c := mkComposite(t, kindAny,
		&stub{name: "a", dec: &module.Decision{Allow: false, Status: 403, Reason: "no"}},
		&stub{name: "b", dec: &module.Decision{Allow: true}},
	)
	dec, err := c.Authorize(context.Background(), &module.Request{}, &module.Identity{})
	if err != nil || !dec.Allow {
		t.Fatalf("got (%+v, %v), want allow", dec, err)
	}
}

func TestAnyOf_AllDenyAggregatesReasons(t *testing.T) {
	t.Parallel()
	c := mkComposite(t, kindAny,
		&stub{name: "a", dec: &module.Decision{Allow: false, Status: 403, Reason: "no-a"}},
		&stub{name: "b", dec: &module.Decision{Allow: false, Status: 403, Reason: "no-b"}},
	)
	dec, err := c.Authorize(context.Background(), &module.Request{}, &module.Identity{})
	if err != nil || dec.Allow {
		t.Fatalf("expected deny, got (%+v, %v)", dec, err)
	}
	if dec.Reason == "" {
		t.Error("expected aggregated reason")
	}
}

func TestAnyOf_UpstreamErrorShortCircuits(t *testing.T) {
	t.Parallel()
	c := mkComposite(t, kindAny,
		&stub{name: "a", err: module.ErrUpstream},
		&stub{name: "b", dec: &module.Decision{Allow: true}}, // never reached
	)
	_, err := c.Authorize(context.Background(), &module.Request{}, &module.Identity{})
	if !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("err = %v, want ErrUpstream", err)
	}
}

func TestAllOf_DeniesOnFirstDeny(t *testing.T) {
	t.Parallel()
	c := mkComposite(t, kindAll,
		&stub{name: "a", dec: &module.Decision{Allow: true}},
		&stub{name: "b", dec: &module.Decision{Allow: false, Status: 403, Reason: "nope"}},
		&stub{name: "c", dec: &module.Decision{Allow: true}}, // never reached
	)
	dec, err := c.Authorize(context.Background(), &module.Request{}, &module.Identity{})
	if err != nil || dec.Allow {
		t.Fatalf("expected deny, got (%+v, %v)", dec, err)
	}
}

func TestAllOf_MergesAllowedHeaders(t *testing.T) {
	t.Parallel()
	c := mkComposite(t, kindAll,
		&stub{name: "a", dec: &module.Decision{Allow: true, ResponseHeaders: map[string]string{"X-A": "1"}}},
		&stub{name: "b", dec: &module.Decision{Allow: true, ResponseHeaders: map[string]string{"X-B": "2"}}},
	)
	dec, err := c.Authorize(context.Background(), &module.Request{}, &module.Identity{})
	if err != nil || !dec.Allow {
		t.Fatalf("expected allow, got (%+v, %v)", dec, err)
	}
	if dec.ResponseHeaders["X-A"] != "1" || dec.ResponseHeaders["X-B"] != "2" {
		t.Errorf("headers = %v, want both", dec.ResponseHeaders)
	}
}

func TestFactory_RequiresExactlyOneOfAnyOfAllOf(t *testing.T) {
	t.Parallel()
	if _, err := factory("c", map[string]any{}); !errors.Is(err, module.ErrConfig) {
		t.Errorf("missing both: err = %v, want ErrConfig", err)
	}
	if _, err := factory("c", map[string]any{
		"anyOf": []any{},
		"allOf": []any{},
	}); !errors.Is(err, module.ErrConfig) {
		t.Errorf("both set: err = %v, want ErrConfig", err)
	}
}
