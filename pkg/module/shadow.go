// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package module

import (
	"context"
	"log/slog"
)

// ShadowAuthorizer is an Authorizer decorator that evaluates a shadow
// policy alongside the production authorizer and reports disagreements.
// The production verdict is always returned; the shadow result is
// discarded after comparison.
//
// This extracts the inline shadow logic from the pipeline engine into a
// composable decorator that can be applied to any authorizer.
type ShadowAuthorizer struct {
	prod   Authorizer
	shadow Authorizer
	// onDisagreement is called when the shadow verdict differs from prod.
	// Parameters: prod decision, shadow decision, whether shadow errored.
	onDisagreement func(prod, shadow *Decision, shadowErr error)
}

func (s *ShadowAuthorizer) Name() string { return s.prod.Name() }

func (s *ShadowAuthorizer) Authorize(ctx context.Context, r *Request, id *Identity) (*Decision, error) {
	// Always run prod first.
	prodDec, prodErr := s.prod.Authorize(ctx, r, id)

	// Run shadow — never propagate its error or result.
	shadowDec, shadowErr := s.shadow.Authorize(ctx, r, id)

	// Compare verdicts.
	if s.onDisagreement != nil && disagrees(prodDec, prodErr, shadowDec, shadowErr) {
		s.onDisagreement(prodDec, shadowDec, shadowErr)
	}

	return prodDec, prodErr
}

// disagrees returns true when the shadow and prod arrive at different
// allow/deny verdicts.
func disagrees(prod *Decision, prodErr error, shadow *Decision, shadowErr error) bool {
	if prodErr != nil || shadowErr != nil {
		// Any error in either is considered a disagreement unless both error.
		return (prodErr == nil) != (shadowErr == nil)
	}
	if prod == nil || shadow == nil {
		return prod != shadow
	}
	return prod.Allow != shadow.Allow
}

// WithShadowAuthorizer returns an AuthorizerDecorator that runs a shadow
// authorizer alongside the decorated authorizer and calls onDisagreement
// when their verdicts differ. The shadow's result is never used for the
// actual decision.
func WithShadowAuthorizer(shadow Authorizer, onDisagreement func(prod, shadow *Decision, shadowErr error)) AuthorizerDecorator {
	return func(prod Authorizer) Authorizer {
		if shadow == nil {
			return prod
		}
		if onDisagreement == nil {
			onDisagreement = func(p, s *Decision, err error) {
				slog.Warn("shadow authorizer disagreement",
					"prod_allow", p != nil && p.Allow,
					"shadow_allow", s != nil && s.Allow,
					"shadow_err", err,
				)
			}
		}
		return &ShadowAuthorizer{
			prod:           prod,
			shadow:         shadow,
			onDisagreement: onDisagreement,
		}
	}
}
