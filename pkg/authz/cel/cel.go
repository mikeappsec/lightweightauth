// Package cel is the lighter ABAC authorizer based on Google's Common
// Expression Language (DESIGN.md §5). Use it when full Rego is overkill.
//
// Config shape:
//
//	authorizers:
//	  - name: only-admins
//	    type: cel
//	    config:
//	      expression: |
//	        identity.claims.role == "admin" &&
//	        request.method == "GET"
//
// Variables exposed to the expression:
//
//	identity        map<string, dyn>   subject/claims/source
//	request         map<string, dyn>   method/host/path/headers/tenantId
//	context         map<string, dyn>   pipeline scratch
package cel

import (
	"context"
	"fmt"

	"github.com/google/cel-go/cel"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

type authorizer struct {
	name string
	prog cel.Program
}

func (a *authorizer) Name() string { return a.name }

func (a *authorizer) Authorize(ctx context.Context, r *module.Request, id *module.Identity) (*module.Decision, error) {
	out, _, err := a.prog.ContextEval(ctx, map[string]any{
		"identity": identityVars(id),
		"request":  requestVars(r),
		"context":  contextVars(r),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: cel eval: %v", module.ErrUpstream, err)
	}
	allow, ok := out.Value().(bool)
	if !ok {
		return nil, fmt.Errorf("%w: cel %q: expression must yield bool, got %T", module.ErrConfig, a.name, out.Value())
	}
	if !allow {
		return &module.Decision{Allow: false, Status: 403, Reason: "cel: denied"}, nil
	}
	return &module.Decision{Allow: true}, nil
}

func identityVars(id *module.Identity) map[string]any {
	if id == nil {
		return map[string]any{"subject": "", "claims": map[string]any{}, "source": ""}
	}
	claims := id.Claims
	if claims == nil {
		claims = map[string]any{}
	}
	return map[string]any{"subject": id.Subject, "claims": claims, "source": id.Source}
}

func requestVars(r *module.Request) map[string]any {
	hdrs := map[string]string{}
	for k, vs := range r.Headers {
		if len(vs) > 0 {
			hdrs[k] = vs[0]
		}
	}
	return map[string]any{
		"method":   r.Method,
		"host":     r.Host,
		"path":     r.Path,
		"headers":  hdrs,
		"tenantId": r.TenantID,
	}
}

func contextVars(r *module.Request) map[string]any {
	if r.Context == nil {
		return map[string]any{}
	}
	return r.Context
}

func factory(name string, raw map[string]any) (module.Authorizer, error) {
	expr, _ := raw["expression"].(string)
	if expr == "" {
		return nil, fmt.Errorf("%w: cel %q: expression is required", module.ErrConfig, name)
	}
	env, err := cel.NewEnv(
		cel.Variable("identity", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("context", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: cel %q: env: %v", module.ErrConfig, name, err)
	}
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("%w: cel %q: compile: %v", module.ErrConfig, name, iss.Err())
	}
	if !ast.OutputType().IsAssignableType(cel.BoolType) {
		return nil, fmt.Errorf("%w: cel %q: expression must yield bool, got %s", module.ErrConfig, name, ast.OutputType())
	}
	prog, err := env.Program(ast,
		cel.EvalOptions(cel.OptOptimize),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: cel %q: program: %v", module.ErrConfig, name, err)
	}
	return &authorizer{name: name, prog: prog}, nil
}

// suppress unused import "context" lint when cel-go variants change.
var _ = context.Background

func init() { module.RegisterAuthorizer("cel", factory) }
