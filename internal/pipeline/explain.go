// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"errors"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/revocation"
)

// ExplainResult is the structured output of a pipeline dry-run explaining
// what would happen for a given request. Used by the admin /v1/admin/explain
// endpoint (G6 — EXPLAIN-API-1).
type ExplainResult struct {
	// Timestamp when the explain was evaluated.
	Timestamp time.Time `json:"timestamp"`

	// PolicyVersion is the operator-assigned spec.version tag.
	PolicyVersion string `json:"policy_version,omitempty"`

	// TotalLatency is wall-clock time for the full explain evaluation.
	TotalLatency time.Duration `json:"total_latency_ns"`

	// Stages contains per-stage trace information in execution order.
	Stages []ExplainStage `json:"stages"`

	// FinalDecision summarises the terminal outcome.
	FinalDecision ExplainDecision `json:"final_decision"`

	// Identity is the resolved identity (nil if identification failed).
	Identity *ExplainIdentity `json:"identity,omitempty"`
}

// ExplainStage is one pipeline stage's contribution to the trace.
type ExplainStage struct {
	// Name is the stage type: "identifier", "revocation", "authorizer", "mutator".
	Name string `json:"name"`

	// Module is the registered module name that executed.
	Module string `json:"module"`

	// Latency is wall-clock time for this stage.
	Latency time.Duration `json:"latency_ns"`

	// Result is stage-specific: "match", "no_match", "allow", "deny",
	// "revoked", "not_revoked", "applied", "skipped", "error".
	Result string `json:"result"`

	// Detail carries human-readable context (deny reason, error msg, etc).
	Detail string `json:"detail,omitempty"`

	// CacheHit indicates the authorizer result came from cache.
	CacheHit bool `json:"cache_hit,omitempty"`
}

// ExplainDecision summarises the terminal outcome.
type ExplainDecision struct {
	Allow  bool   `json:"allow"`
	Status int    `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// ExplainIdentity is the identity produced during explain (minimal view).
type ExplainIdentity struct {
	Subject string `json:"subject"`
	Source  string `json:"source"`
	ACR     string `json:"acr,omitempty"`
	AMR     string `json:"amr,omitempty"`
}

// Explain runs the pipeline stages in order against the given request,
// collecting per-stage timing and results without emitting metrics or
// audit events. It is a read-only operation suitable for admin tooling.
func (e *Engine) Explain(ctx context.Context, r *module.Request) *ExplainResult {
	start := time.Now()
	if r.Context == nil {
		r.Context = make(map[string]any)
	}

	result := &ExplainResult{
		Timestamp:     start.UTC(),
		PolicyVersion: e.policyVersion,
	}

	// Stage 1: Identification
	id, idStages := e.explainIdentify(ctx, r)
	result.Stages = append(result.Stages, idStages...)

	if id != nil {
		result.Identity = &ExplainIdentity{
			Subject: id.Subject,
			Source:  id.Source,
			ACR:     id.ACR,
		}
		if len(id.AMR) > 0 {
			amr := ""
			for i, m := range id.AMR {
				if i > 0 {
					amr += " "
				}
				amr += m
			}
			result.Identity.AMR = amr
		}
		r.Context["identity"] = id
	}

	// Stage 2: Revocation check
	if e.revocationStore != nil && id != nil {
		revStage := e.explainRevocation(ctx, r, id)
		result.Stages = append(result.Stages, revStage)
		if revStage.Result == "revoked" {
			result.FinalDecision = ExplainDecision{
				Allow:  false,
				Status: 401,
				Reason: "credential revoked",
			}
			result.TotalLatency = time.Since(start)
			return result
		}
	}

	// Stage 3: Authorization
	azStage := e.explainAuthorize(ctx, r, id)
	result.Stages = append(result.Stages, azStage)

	if azStage.Result == "error" || azStage.Result == "deny" {
		status := 403
		if azStage.Result == "error" {
			status = 500
		}
		result.FinalDecision = ExplainDecision{
			Allow:  false,
			Status: status,
			Reason: azStage.Detail,
		}
		result.TotalLatency = time.Since(start)
		return result
	}

	// Stage 4: Mutators
	for _, m := range e.mutators {
		mStage := e.explainMutate(ctx, m, r, id)
		result.Stages = append(result.Stages, mStage)
		if mStage.Result == "error" {
			result.FinalDecision = ExplainDecision{
				Allow:  false,
				Status: 500,
				Reason: mStage.Detail,
			}
			result.TotalLatency = time.Since(start)
			return result
		}
	}

	result.FinalDecision = ExplainDecision{
		Allow:  true,
		Status: 200,
	}
	result.TotalLatency = time.Since(start)
	return result
}

// explainIdentify runs identifiers and returns per-identifier stages.
func (e *Engine) explainIdentify(ctx context.Context, r *module.Request) (*module.Identity, []ExplainStage) {
	var stages []ExplainStage

	switch e.identifierMode {
	case AllMust:
		// AllMust: every identifier must succeed.
		for _, idr := range e.identifiers {
			s := time.Now()
			id, err := idr.Identify(ctx, r)
			lat := time.Since(s)
			if err != nil {
				stages = append(stages, ExplainStage{
					Name:    "identifier",
					Module:  idr.Name(),
					Latency: lat,
					Result:  "error",
					Detail:  err.Error(),
				})
				return nil, stages
			}
			if id == nil {
				stages = append(stages, ExplainStage{
					Name:    "identifier",
					Module:  idr.Name(),
					Latency: lat,
					Result:  "no_match",
				})
				return nil, stages
			}
			stages = append(stages, ExplainStage{
				Name:    "identifier",
				Module:  idr.Name(),
				Latency: lat,
				Result:  "match",
			})
		}
		// Merge: use last identifier's result (simplified — real AllMust merges claims).
		if len(e.identifiers) > 0 {
			s := time.Now()
			id, _ := e.identifiers[len(e.identifiers)-1].Identify(ctx, r)
			_ = time.Since(s)
			if id != nil && id.Source == "" {
				id.Source = e.identifiers[len(e.identifiers)-1].Name()
			}
			return id, stages
		}
		return nil, stages

	default: // FirstMatch
		for _, idr := range e.identifiers {
			s := time.Now()
			id, err := idr.Identify(ctx, r)
			lat := time.Since(s)
			if err != nil {
				if errors.Is(err, module.ErrNoMatch) {
					stages = append(stages, ExplainStage{
						Name:    "identifier",
						Module:  idr.Name(),
						Latency: lat,
						Result:  "no_match",
					})
					continue
				}
				stages = append(stages, ExplainStage{
					Name:    "identifier",
					Module:  idr.Name(),
					Latency: lat,
					Result:  "error",
					Detail:  err.Error(),
				})
				return nil, stages
			}
			if id == nil {
				stages = append(stages, ExplainStage{
					Name:    "identifier",
					Module:  idr.Name(),
					Latency: lat,
					Result:  "no_match",
				})
				continue
			}
			if id.Source == "" {
				id.Source = idr.Name()
			}
			stages = append(stages, ExplainStage{
				Name:    "identifier",
				Module:  idr.Name(),
				Latency: lat,
				Result:  "match",
			})
			return id, stages
		}
	}
	return nil, stages
}

// explainRevocation checks revocation status for explain.
func (e *Engine) explainRevocation(ctx context.Context, r *module.Request, id *module.Identity) ExplainStage {
	s := time.Now()

	var checker module.RevocationChecker
	for _, ident := range e.identifiers {
		if ident.Name() == id.Source {
			if rc, ok := ident.(module.RevocationChecker); ok {
				checker = rc
			}
			break
		}
	}
	if checker == nil {
		return ExplainStage{
			Name:    "revocation",
			Module:  "revocation-store",
			Latency: time.Since(s),
			Result:  "skipped",
			Detail:  "identifier does not implement RevocationChecker",
		}
	}

	keys := checker.RevocationKeys(id, r.TenantID)
	if len(keys) == 0 {
		return ExplainStage{
			Name:    "revocation",
			Module:  "revocation-store",
			Latency: time.Since(s),
			Result:  "skipped",
			Detail:  "no revocation keys for identity",
		}
	}

	pc := revocation.NewParallelChecker(e.revocationStore)
	revoked, err := pc.ExistsAny(ctx, keys)
	lat := time.Since(s)
	if err != nil {
		if e.revocationFailOpen {
			return ExplainStage{
				Name:    "revocation",
				Module:  "revocation-store",
				Latency: lat,
				Result:  "skipped",
				Detail:  "store error (fail-open): " + err.Error(),
			}
		}
		return ExplainStage{
			Name:    "revocation",
			Module:  "revocation-store",
			Latency: lat,
			Result:  "revoked",
			Detail:  "store error (fail-closed): " + err.Error(),
		}
	}
	if revoked {
		return ExplainStage{
			Name:    "revocation",
			Module:  "revocation-store",
			Latency: lat,
			Result:  "revoked",
		}
	}
	return ExplainStage{
		Name:    "revocation",
		Module:  "revocation-store",
		Latency: lat,
		Result:  "not_revoked",
	}
}

// explainAuthorize runs the authorizer and captures the result.
func (e *Engine) explainAuthorize(ctx context.Context, r *module.Request, id *module.Identity) ExplainStage {
	s := time.Now()
	dec, err := e.authorizer.Authorize(ctx, r, id)
	lat := time.Since(s)
	if err != nil {
		return ExplainStage{
			Name:    "authorizer",
			Module:  e.authorizer.Name(),
			Latency: lat,
			Result:  "error",
			Detail:  err.Error(),
		}
	}
	if dec == nil || !dec.Allow {
		reason := ""
		status := 403
		if dec != nil {
			reason = dec.Reason
			if dec.Status != 0 {
				status = dec.Status
			}
		}
		_ = status
		return ExplainStage{
			Name:    "authorizer",
			Module:  e.authorizer.Name(),
			Latency: lat,
			Result:  "deny",
			Detail:  reason,
		}
	}
	return ExplainStage{
		Name:    "authorizer",
		Module:  e.authorizer.Name(),
		Latency: lat,
		Result:  "allow",
	}
}

// explainMutate runs a single mutator for explain.
func (e *Engine) explainMutate(ctx context.Context, m module.ResponseMutator, r *module.Request, id *module.Identity) ExplainStage {
	s := time.Now()
	dec := &module.Decision{Allow: true, Status: 200}
	err := m.Mutate(ctx, r, id, dec)
	lat := time.Since(s)
	if err != nil {
		return ExplainStage{
			Name:    "mutator",
			Module:  m.Name(),
			Latency: lat,
			Result:  "error",
			Detail:  err.Error(),
		}
	}
	return ExplainStage{
		Name:    "mutator",
		Module:  m.Name(),
		Latency: lat,
		Result:  "applied",
	}
}

// SimEvaluate runs the pipeline in a lightweight mode for bulk replay
// (G7 — POL-SIM-1). It returns the allow/deny verdict and a reason string
// without emitting metrics, audit, or traces. Used by `lwauthctl simulate`.
func (e *Engine) SimEvaluate(ctx context.Context, r *module.Request) (allow bool, reason string) {
	if r.Context == nil {
		r.Context = make(map[string]any)
	}

	id, err := e.identify(ctx, r)
	if err != nil {
		return false, "identify: " + err.Error()
	}
	if id != nil {
		r.Context["identity"] = id
	}

	dec, err := e.authorizer.Authorize(ctx, r, id)
	if err != nil {
		return false, "authorize: " + err.Error()
	}
	if dec == nil || !dec.Allow {
		reason := "denied"
		if dec != nil && dec.Reason != "" {
			reason = dec.Reason
		}
		return false, reason
	}
	return true, ""
}
