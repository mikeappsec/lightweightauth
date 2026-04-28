package conformance

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// IdentifierOpts configures IdentifierContract.
//
// At minimum, ValidRequest must be supplied: a request the identifier
// should accept and produce a non-nil *Identity for. NoMatchRequest and
// InvalidRequest are optional but strongly recommended; without them the
// suite can't verify your sentinel-error wiring.
type IdentifierOpts struct {
	// ValidRequest is a request your identifier should successfully
	// produce an Identity for. The harness will clone it per sub-test.
	ValidRequest *module.Request

	// NoMatchRequest, if non-nil, is a request your identifier should
	// reject with errors.Is(err, module.ErrNoMatch). For example, a JWT
	// identifier given a request without an Authorization header.
	NoMatchRequest *module.Request

	// InvalidRequest, if non-nil, is a request that has the right
	// "shape" but a tampered credential — the harness expects
	// errors.Is(err, module.ErrInvalidCredential).
	InvalidRequest *module.Request

	// Concurrency controls how many parallel goroutines hit Identify in
	// the race-detection sub-test. Default 32.
	Concurrency int

	// MaxLatency is the upper bound on a single Identify call against
	// ValidRequest. Default 2s. Bump it if your module talks to real
	// dependencies; otherwise a regression that introduces a hot-path
	// network call will be caught.
	MaxLatency time.Duration
}

// IdentifierContract asserts that ident honours the module.Identifier
// contract documented in pkg/module/module.go.
func IdentifierContract(t *testing.T, ident module.Identifier, opts IdentifierOpts) {
	t.Helper()
	if ident == nil {
		t.Fatal("conformance: nil Identifier")
	}
	if opts.ValidRequest == nil {
		t.Fatal("conformance: IdentifierOpts.ValidRequest is required")
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 32
	}
	if opts.MaxLatency <= 0 {
		opts.MaxLatency = 2 * time.Second
	}

	t.Run("Name_NonEmpty_Stable", func(t *testing.T) {
		n1 := ident.Name()
		if n1 == "" {
			t.Fatal("Name() returned empty string")
		}
		if n2 := ident.Name(); n1 != n2 {
			t.Fatalf("Name() not stable: %q then %q", n1, n2)
		}
	})

	t.Run("NilRequest_NoPanic", func(t *testing.T) {
		defer mustNotPanic(t, "Identify(nil)")
		_, err := ident.Identify(context.Background(), nil)
		if err == nil {
			t.Fatal("Identify(nil) returned nil error; expected an error")
		}
	})

	t.Run("ValidRequest_ReturnsIdentity", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), opts.MaxLatency)
		defer cancel()
		start := time.Now()
		id, err := ident.Identify(ctx, cloneRequest(opts.ValidRequest))
		if err != nil {
			t.Fatalf("Identify(valid): %v", err)
		}
		if id == nil {
			t.Fatal("Identify(valid) returned nil Identity with nil error")
		}
		if id.Subject == "" {
			t.Error("Identity.Subject is empty (must identify the principal)")
		}
		if d := time.Since(start); d > opts.MaxLatency {
			t.Errorf("Identify took %s, exceeds MaxLatency %s", d, opts.MaxLatency)
		}
	})

	if opts.NoMatchRequest != nil {
		t.Run("NoMatch_ReturnsErrNoMatch", func(t *testing.T) {
			_, err := ident.Identify(context.Background(), cloneRequest(opts.NoMatchRequest))
			if !errors.Is(err, module.ErrNoMatch) {
				t.Fatalf("expected errors.Is(err, ErrNoMatch); got %v", err)
			}
		})
	}

	if opts.InvalidRequest != nil {
		t.Run("Invalid_ReturnsErrInvalidCredential", func(t *testing.T) {
			_, err := ident.Identify(context.Background(), cloneRequest(opts.InvalidRequest))
			if !errors.Is(err, module.ErrInvalidCredential) {
				t.Fatalf("expected errors.Is(err, ErrInvalidCredential); got %v", err)
			}
		})
	}

	t.Run("CancelledContext_NoPanic", func(t *testing.T) {
		defer mustNotPanic(t, "Identify(cancelled ctx)")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _ = ident.Identify(ctx, cloneRequest(opts.ValidRequest))
		// We don't assert err == ctx.Err() because some modules legitimately
		// finish before checking ctx (synchronous parsers). We only require
		// no panic and prompt return.
	})

	t.Run("NoRequestRetention", func(t *testing.T) {
		defer mustNotPanic(t, "post-call Request.Context mutation")
		req := cloneRequest(opts.ValidRequest)
		if req.Context == nil {
			req.Context = map[string]any{}
		}
		_, _ = ident.Identify(context.Background(), req)
		// Mutating the map after the call must not affect the module on
		// the next call. This mostly catches modules that stash *Request
		// in a struct field.
		req.Context["conformance.poison"] = make(chan struct{})
		_, err := ident.Identify(context.Background(), cloneRequest(opts.ValidRequest))
		if err != nil && !errors.Is(err, module.ErrNoMatch) &&
			!errors.Is(err, module.ErrInvalidCredential) &&
			!errors.Is(err, module.ErrForbidden) {
			// A legitimate sentinel is fine; an arbitrary error here is
			// suspicious and likely indicates retention.
			t.Logf("second call returned non-sentinel error %v "+
				"(may indicate request-retention bug)", err)
		}
	})

	t.Run("Concurrent_NoRace", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, opts.Concurrency)
		for i := 0; i < opts.Concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						errs <- panicErr(r)
					}
				}()
				if _, err := ident.Identify(context.Background(),
					cloneRequest(opts.ValidRequest)); err != nil {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("concurrent Identify: %v", err)
		}
	})
}
