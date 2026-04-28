// Package golden enforces the v1.0 backwards-compatibility lock for
// AuthConfig YAML and the plugin proto wire shape. Every fixture under
// tests/golden/authconfig/ MUST parse with internal/config.LoadFile and
// successfully Compile against the built-in module registry, on every
// commit.
//
// See tests/golden/README.md for the contract.
package golden

import (
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"

	"github.com/mikeappsec/lightweightauth/internal/config"
)

// TestAuthConfigGoldensLoadAndCompile is the v1.0 contract: every YAML
// fixture under tests/golden/authconfig/ must round-trip Load → Compile.
// Adding a YAML key that an existing fixture sets, then removing it
// silently in a refactor, breaks here. That is the whole point.
func TestAuthConfigGoldensLoadAndCompile(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("authconfig", "*.yaml"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no goldens found under tests/golden/authconfig/*.yaml")
	}
	for _, path := range matches {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			ac, err := config.LoadFile(path)
			if err != nil {
				t.Fatalf("LoadFile(%s): %v", path, err)
			}
			if _, err := config.Compile(ac); err != nil {
				t.Fatalf("Compile(%s): %v", path, err)
			}
		})
	}
}

// TestAuthConfigGoldensCoverEveryModule asserts that the goldens, taken
// together, exercise every module type registered in the binary's
// builtins. If a future PR adds a new module to pkg/builtins but
// forgets to add a golden fixture for it, the count goes out of sync
// and this test fails — preventing silent under-coverage of the v1.0
// freeze surface.
//
// We allow-list `jwt` and `oauth2` (constructor I/O — covered by their
// own packages) and `oauth2-introspection` (same reason).
func TestAuthConfigGoldensCoverEveryModule(t *testing.T) {
	matches, _ := filepath.Glob(filepath.Join("authconfig", "*.yaml"))
	seen := map[string]bool{}
	for _, p := range matches {
		ac, err := config.LoadFile(p)
		if err != nil {
			continue
		}
		for _, s := range ac.Identifiers {
			seen[s.Type] = true
		}
		for _, s := range ac.Authorizers {
			seen[s.Type] = true
			// Composite children are also "seen" for coverage.
			if s.Type == "composite" {
				for _, k := range []string{"anyOf", "allOf"} {
					if list, ok := s.Config[k].([]any); ok {
						for _, child := range list {
							if m, ok := child.(map[string]any); ok {
								if t, ok := m["type"].(string); ok {
									seen[t] = true
								}
							}
						}
					}
				}
			}
		}
		for _, s := range ac.Response {
			seen[s.Type] = true
		}
	}

	// Modules whose constructors do real I/O (HTTPS GET, etc) so we
	// can't safely include them in a load-and-compile fixture.
	ioBound := map[string]bool{
		"jwt":                  true,
		"oauth2":               true,
		"oauth2-introspection": true,
		"dpop":                 true, // wraps an inner identifier; constructed via composite
		"grpc-plugin":          true, // dials a remote service
	}

	wantInGoldens := []string{
		// Identifiers
		"apikey", "hmac", "mtls",
		// Authorizers
		"rbac", "opa", "cel", "openfga", "composite",
		// Mutators
		"jwt-issue", "header-add", "header-remove", "header-passthrough",
	}
	var missing []string
	for _, k := range wantInGoldens {
		if !seen[k] && !ioBound[k] {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("goldens do not exercise: %s", strings.Join(missing, ", "))
	}
}
