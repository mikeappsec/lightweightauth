// Package openfga is the OpenFGA / Zanzibar-style ReBAC authorizer
// (DESIGN.md §5, §7).
//
// This authorizer does NOT embed a relationship store; it adapts an
// external OpenFGA Pod (run alongside lwauth by the operator) and maps
// each AuthZ request to an OpenFGA Check call:
//
//	POST {apiUrl}/stores/{storeId}/check
//	{
//	  "tuple_key": {"user":"user:alice","relation":"editor","object":"doc:42"},
//	  "authorization_model_id": "01H..."
//	}
//
// The user / relation / object strings are produced by Go text/template
// snippets so AuthConfigs can derive them from request metadata.
//
// Config shape:
//
//	authorizers:
//	  - name: docs-rebac
//	    type: openfga
//	    config:
//	      apiUrl: http://openfga.openfga.svc:8080
//	      storeId: 01HX...
//	      authorizationModelId: 01H...    # optional, latest if empty
//	      timeout: 500ms                  # optional, default 2s
//	      check:
//	        user: "user:{{ .Identity.Subject }}"
//	        relation: "{{ .Request.Method | lower }}"   # "get" → "viewer" etc. via OpenFGA model
//	        object: "doc:{{ index .Request.PathParts 1 }}"
//	      # Optional API token forwarded as Authorization: Bearer <token>
//	      apiToken: ${OPENFGA_TOKEN}
//
// Composition: pair this with RBAC under composite/anyOf so cheap role
// checks short-circuit before issuing a network call to OpenFGA.
package openfga

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"text/template"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/upstream"
)

const defaultTimeout = 2 * time.Second

// HTTPDoer is satisfied by *http.Client. It exists so tests can swap in
// httptest.NewServer-based clients without wiring through a transport.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type authorizer struct {
	name     string
	apiURL   string // trimmed of trailing slash
	storeID  string
	modelID  string
	apiToken string
	timeout  time.Duration

	userTpl     *template.Template
	relationTpl *template.Template
	objectTpl   *template.Template

	client HTTPDoer
	guard  *upstream.Guard
}

// templateInput is the value passed into the user/relation/object
// templates. Kept narrow on purpose: the template author should not be
// able to reach into pipeline internals.
type templateInput struct {
	Identity *module.Identity
	Request  *templateRequest
}

type templateRequest struct {
	Method    string
	Host      string
	Path      string
	PathParts []string
	TenantID  string
	Headers   map[string]string
}

func (a *authorizer) Name() string { return a.name }

func (a *authorizer) Authorize(ctx context.Context, r *module.Request, id *module.Identity) (*module.Decision, error) {
	in := templateInput{
		Identity: id,
		Request:  buildTemplateRequest(r),
	}

	user, err := render(a.userTpl, in)
	if err != nil {
		return nil, fmt.Errorf("%w: openfga %q: render user: %v", module.ErrConfig, a.name, err)
	}
	relation, err := render(a.relationTpl, in)
	if err != nil {
		return nil, fmt.Errorf("%w: openfga %q: render relation: %v", module.ErrConfig, a.name, err)
	}
	object, err := render(a.objectTpl, in)
	if err != nil {
		return nil, fmt.Errorf("%w: openfga %q: render object: %v", module.ErrConfig, a.name, err)
	}
	if user == "" || relation == "" || object == "" {
		return &module.Decision{
			Allow:  false,
			Status: 403,
			Reason: fmt.Sprintf("openfga: empty tuple (%q,%q,%q)", user, relation, object),
		}, nil
	}

	allowed, err := a.check(ctx, user, relation, object)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return &module.Decision{
			Allow:  false,
			Status: 403,
			Reason: fmt.Sprintf("openfga: %s is not %s of %s", user, relation, object),
		}, nil
	}
	return &module.Decision{
		Allow:  true,
		Reason: fmt.Sprintf("openfga: %s is %s of %s", user, relation, object),
	}, nil
}

type checkRequest struct {
	TupleKey             checkTuple `json:"tuple_key"`
	AuthorizationModelID string     `json:"authorization_model_id,omitempty"`
}

type checkTuple struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

type checkResponse struct {
	Allowed    bool   `json:"allowed"`
	Resolution string `json:"resolution,omitempty"`
}

func (a *authorizer) check(ctx context.Context, user, relation, object string) (bool, error) {
	body, err := json.Marshal(checkRequest{
		TupleKey:             checkTuple{User: user, Relation: relation, Object: object},
		AuthorizationModelID: a.modelID,
	})
	if err != nil {
		return false, fmt.Errorf("%w: openfga marshal: %v", module.ErrUpstream, err)
	}
	url := fmt.Sprintf("%s/stores/%s/check", a.apiURL, a.storeID)

	if a.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("%w: openfga request: %v", module.ErrUpstream, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if a.apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiToken)
	}

	var out checkResponse
	err = a.guard.Do(ctx, func(ctx context.Context) error {
		// Re-build the request per attempt so the body reader is fresh
		// and ctx (which may be the per-attempt timeout we cloned
		// earlier) propagates correctly.
		attemptReq := req.Clone(ctx)
		attemptReq.Body = io.NopCloser(bytes.NewReader(body))
		resp, err := a.client.Do(attemptReq)
		if err != nil {
			return fmt.Errorf("%w: openfga check: %v", module.ErrUpstream, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			preview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return fmt.Errorf("%w: openfga check: status %d: %s", module.ErrUpstream, resp.StatusCode, bytes.TrimSpace(preview))
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return fmt.Errorf("%w: openfga decode: %v", module.ErrUpstream, err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, upstream.ErrCircuitOpen) {
			return false, fmt.Errorf("%w: openfga: circuit open", module.ErrUpstream)
		}
		return false, err
	}
	return out.Allowed, nil
}

func buildTemplateRequest(r *module.Request) *templateRequest {
	if r == nil {
		return &templateRequest{}
	}
	hdrs := map[string]string{}
	for k, vs := range r.Headers {
		if len(vs) > 0 {
			hdrs[strings.ToLower(k)] = vs[0]
		}
	}
	parts := splitPath(r.Path)
	return &templateRequest{
		Method:    r.Method,
		Host:      r.Host,
		Path:      r.Path,
		PathParts: parts,
		TenantID:  r.TenantID,
		Headers:   hdrs,
	}
}

func splitPath(p string) []string {
	p = path.Clean("/" + strings.TrimPrefix(p, "/"))
	if p == "/" {
		return nil
	}
	return strings.Split(strings.TrimPrefix(p, "/"), "/")
}

func render(t *template.Template, in templateInput) (string, error) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, in); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}

// templateFuncs are the helpers available inside user/relation/object
// templates. Kept tiny on purpose; users wanting full Sprig should reach
// for OPA instead.
var templateFuncs = template.FuncMap{
	"lower": strings.ToLower,
	"upper": strings.ToUpper,
}

func factory(name string, raw map[string]any) (module.Authorizer, error) {
	apiURL, _ := raw["apiUrl"].(string)
	if apiURL == "" {
		return nil, fmt.Errorf("%w: openfga %q: apiUrl is required", module.ErrConfig, name)
	}
	storeID, _ := raw["storeId"].(string)
	if storeID == "" {
		return nil, fmt.Errorf("%w: openfga %q: storeId is required", module.ErrConfig, name)
	}
	modelID, _ := raw["authorizationModelId"].(string)
	apiToken, _ := raw["apiToken"].(string)

	timeout := defaultTimeout
	if v, ok := raw["timeout"].(string); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("%w: openfga %q: timeout: %v", module.ErrConfig, name, err)
		}
		timeout = d
	}

	check, _ := raw["check"].(map[string]any)
	if check == nil {
		return nil, fmt.Errorf("%w: openfga %q: check block is required", module.ErrConfig, name)
	}
	userSrc, _ := check["user"].(string)
	relSrc, _ := check["relation"].(string)
	objSrc, _ := check["object"].(string)
	if userSrc == "" || relSrc == "" || objSrc == "" {
		return nil, fmt.Errorf("%w: openfga %q: check.user/relation/object are required", module.ErrConfig, name)
	}

	parse := func(field, src string) (*template.Template, error) {
		t, err := template.New(name + "." + field).Funcs(templateFuncs).Parse(src)
		if err != nil {
			return nil, fmt.Errorf("%w: openfga %q: parse %s: %v", module.ErrConfig, name, field, err)
		}
		return t, nil
	}
	userTpl, err := parse("user", userSrc)
	if err != nil {
		return nil, err
	}
	relTpl, err := parse("relation", relSrc)
	if err != nil {
		return nil, err
	}
	objTpl, err := parse("object", objSrc)
	if err != nil {
		return nil, err
	}

	guardCfg, err := upstream.FromMap(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: openfga %q: %v", module.ErrConfig, name, err)
	}

	return &authorizer{
		name:        name,
		apiURL:      strings.TrimRight(apiURL, "/"),
		storeID:     storeID,
		modelID:     modelID,
		apiToken:    apiToken,
		timeout:     timeout,
		userTpl:     userTpl,
		relationTpl: relTpl,
		objectTpl:   objTpl,
		client:      &http.Client{Timeout: timeout + time.Second},
		guard:       upstream.NewGuard(guardCfg),
	}, nil
}

func init() { module.RegisterAuthorizer("openfga", factory) }

// Compile-time check that errors.Is works with the wrapped sentinels.
var _ = errors.Is
