package conformance_test

import (
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/module/conformance"

	// Register the built-ins we exercise.
	_ "github.com/mikeappsec/lightweightauth/pkg/authz/rbac"
	_ "github.com/mikeappsec/lightweightauth/pkg/identity/apikey"
	_ "github.com/mikeappsec/lightweightauth/pkg/mutator/headers"
)

// These self-tests exercise the conformance harness against representative
// built-ins (apikey, rbac, header-add). They serve two purposes:
//  1. Catch breakage in the harness itself.
//  2. Document, by example, how third-party plugin authors should call the
//     Contract functions from their own test suites.

func TestApikeyConformsToIdentifierContract(t *testing.T) {
	id, err := module.BuildIdentifier("apikey", "test", map[string]any{
		"headerName": "X-Api-Key",
		"static": map[string]any{
			"good-key": map[string]any{
				"subject": "alice",
				"roles":   []any{"admin"},
			},
		},
	})
	if err != nil {
		t.Fatalf("build apikey: %v", err)
	}

	conformance.IdentifierContract(t, id, conformance.IdentifierOpts{
		ValidRequest: &module.Request{
			Method:  "GET",
			Path:    "/v1/things",
			Headers: map[string][]string{"X-Api-Key": {"good-key"}},
		},
		NoMatchRequest: &module.Request{
			Method:  "GET",
			Path:    "/v1/things",
			Headers: map[string][]string{},
		},
		InvalidRequest: &module.Request{
			Method:  "GET",
			Path:    "/v1/things",
			Headers: map[string][]string{"X-Api-Key": {"wrong-key"}},
		},
	})
}

func TestRBACConformsToAuthorizerContract(t *testing.T) {
	az, err := module.BuildAuthorizer("rbac", "test", map[string]any{
		"rolesFrom": "claim:roles",
		"allow":     []any{"admin"},
	})
	if err != nil {
		t.Fatalf("build rbac: %v", err)
	}

	req := &module.Request{Method: "GET", Path: "/v1/things"}
	conformance.AuthorizerContract(t, az, conformance.AuthorizerOpts{
		AllowRequest: req,
		AllowIdentity: &module.Identity{
			Subject: "alice",
			Claims:  map[string]any{"roles": []any{"admin"}},
		},
		DenyRequest: req,
		DenyIdentity: &module.Identity{
			Subject: "bob",
			Claims:  map[string]any{"roles": []any{"viewer"}},
		},
	})
}

func TestHeaderAddConformsToMutatorContract(t *testing.T) {
	m, err := module.BuildMutator("header-add", "test", map[string]any{
		"subjectHeader": "X-Auth-Subject",
		"upstream": map[string]any{
			"X-Auth-Email": "${claim:email}",
		},
	})
	if err != nil {
		t.Fatalf("build header-add: %v", err)
	}

	conformance.MutatorContract(t, m, conformance.MutatorOpts{
		Request: &module.Request{Method: "GET", Path: "/v1/things"},
		Identity: &module.Identity{
			Subject: "alice",
			Claims:  map[string]any{"email": "alice@example.com"},
		},
		Decision: &module.Decision{Allow: true},
	})
}
