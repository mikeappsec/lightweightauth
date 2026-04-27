package apikey

import (
	"context"
	"errors"
	"testing"

	"github.com/yourorg/lightweightauth/pkg/module"
)

func build(t *testing.T) module.Identifier {
	t.Helper()
	id, err := factory("apikey-test", map[string]any{
		"headerName": "X-Api-Key",
		"static":     map[string]any{"k1": "alice", "k2": "bob"},
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return id
}

func TestAPIKey_Match(t *testing.T) {
	id := build(t)
	r := &module.Request{Headers: map[string][]string{"X-Api-Key": {"k1"}}}
	got, err := id.Identify(context.Background(), r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", got.Subject)
	}
}

func TestAPIKey_NoHeader(t *testing.T) {
	id := build(t)
	_, err := id.Identify(context.Background(), &module.Request{Headers: map[string][]string{}})
	if !errors.Is(err, module.ErrNoMatch) {
		t.Fatalf("err = %v, want ErrNoMatch", err)
	}
}

func TestAPIKey_UnknownKey(t *testing.T) {
	id := build(t)
	r := &module.Request{Headers: map[string][]string{"X-Api-Key": {"nope"}}}
	_, err := id.Identify(context.Background(), r)
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}
