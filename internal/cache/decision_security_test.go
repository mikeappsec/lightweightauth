package cache

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// TestNewDecision_RejectsUnknownKeyField is the fail-closed fence on
// cache.key validation. The previous implementation silently dropped any
// value resolveField did not recognise, which meant a typo like
// "pathTemplate" would degrade [sub, method, pathTemplate] to [sub,
// method] and let a single allow decision replay across every path the
// same subject hit with the same method.
func TestNewDecision_RejectsUnknownKeyField(t *testing.T) {
	t.Parallel()
	cases := []string{
		"pathTemplate", // the documented-but-unimplemented typo
		"PATH",         // case-sensitive: only lower-case "path" is valid
		"resource",
		"header:", // empty selector
		"claim:",  // empty selector
		"",
	}
	for _, f := range cases {
		f := f
		t.Run(f, func(t *testing.T) {
			t.Parallel()
			_, err := NewDecision(DecisionOptions{
				Size:        16,
				PositiveTTL: time.Minute,
				KeyFields:   []string{"sub", f},
			})
			if err == nil {
				t.Fatalf("expected error for key field %q, got nil", f)
			}
			if !errors.Is(err, module.ErrConfig) {
				t.Errorf("error not in ErrConfig taxonomy: %v", err)
			}
			if !strings.Contains(err.Error(), "cache.key") {
				t.Errorf("error message should mention cache.key: %v", err)
			}
		})
	}
}

func TestNewDecision_AcceptsAllRecognisedFields(t *testing.T) {
	t.Parallel()
	good := []string{
		"sub", "tenant", "method", "host", "path",
		"header:X-Forwarded-For",
		"claim:roles",
	}
	for _, f := range good {
		f := f
		t.Run(f, func(t *testing.T) {
			t.Parallel()
			d, err := NewDecision(DecisionOptions{
				Size:        16,
				PositiveTTL: time.Minute,
				KeyFields:   []string{f},
			})
			if err != nil {
				t.Fatalf("recognised field %q rejected: %v", f, err)
			}
			if d == nil {
				t.Fatalf("recognised field %q produced nil cache", f)
			}
		})
	}
}
