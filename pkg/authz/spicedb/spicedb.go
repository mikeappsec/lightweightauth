// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package spicedb is the SpiceDB / Zanzibar-style ReBAC authorizer
// (DESIGN.md §F6).
//
// This authorizer adapts an external SpiceDB instance via its gRPC
// CheckPermission API, mapping each AuthZ request to a permission check:
//
//	CheckPermission {
//	  resource:   { object_type: "document", object_id: "42" }
//	  permission: "view"
//	  subject:    { object: { object_type: "user", object_id: "alice" } }
//	}
//
// The resource type/id, permission, and subject type/id are produced by
// Go text/template snippets so AuthConfigs can derive them from request
// metadata.
//
// Config shape:
//
//	authorizers:
//	  - name: docs-spicedb
//	    type: spicedb
//	    config:
//	      endpoint: spicedb.spicedb.svc:50051
//	      token: ${SPICEDB_TOKEN}           # pre-shared key
//	      insecure: false                   # use TLS (default)
//	      timeout: 500ms                    # optional, default 2s
//	      check:
//	        resourceType: "document"
//	        resourceId: "{{ index .Request.PathParts 1 }}"
//	        permission: "{{ .Request.Method | lower }}"
//	        subjectType: "user"
//	        subjectId: "{{ .Identity.Subject }}"
//
// Composition: pair this with RBAC under composite/anyOf so cheap role
// checks short-circuit before issuing a network call to SpiceDB.
package spicedb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"text/template"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/upstream"
)

const defaultTimeout = 2 * time.Second

type authorizer struct {
	name    string
	timeout time.Duration

	resourceTypeTpl *template.Template
	resourceIDTpl   *template.Template
	permissionTpl   *template.Template
	subjectTypeTpl  *template.Template
	subjectIDTpl    *template.Template

	client *authzed.Client
	guard  *upstream.Guard
}

// templateInput is the value passed into the check templates.
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

	resourceType, err := render(a.resourceTypeTpl, in)
	if err != nil {
		return nil, fmt.Errorf("%w: spicedb %q: render resourceType: %v", module.ErrConfig, a.name, err)
	}
	resourceID, err := render(a.resourceIDTpl, in)
	if err != nil {
		return nil, fmt.Errorf("%w: spicedb %q: render resourceId: %v", module.ErrConfig, a.name, err)
	}
	permission, err := render(a.permissionTpl, in)
	if err != nil {
		return nil, fmt.Errorf("%w: spicedb %q: render permission: %v", module.ErrConfig, a.name, err)
	}
	subjectType, err := render(a.subjectTypeTpl, in)
	if err != nil {
		return nil, fmt.Errorf("%w: spicedb %q: render subjectType: %v", module.ErrConfig, a.name, err)
	}
	subjectID, err := render(a.subjectIDTpl, in)
	if err != nil {
		return nil, fmt.Errorf("%w: spicedb %q: render subjectId: %v", module.ErrConfig, a.name, err)
	}

	if resourceType == "" || resourceID == "" || permission == "" || subjectType == "" || subjectID == "" {
		return &module.Decision{
			Allow:  false,
			Status: 403,
			Reason: fmt.Sprintf("spicedb: empty check fields (resource=%s:%s, permission=%s, subject=%s:%s)",
				resourceType, resourceID, permission, subjectType, subjectID),
		}, nil
	}

	allowed, err := a.checkPermission(ctx, resourceType, resourceID, permission, subjectType, subjectID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return &module.Decision{
			Allow:  false,
			Status: 403,
			Reason: fmt.Sprintf("spicedb: %s:%s does not have %s on %s:%s",
				subjectType, subjectID, permission, resourceType, resourceID),
		}, nil
	}
	return &module.Decision{
		Allow: true,
		Reason: fmt.Sprintf("spicedb: %s:%s has %s on %s:%s",
			subjectType, subjectID, permission, resourceType, resourceID),
	}, nil
}

func (a *authorizer) checkPermission(ctx context.Context, resourceType, resourceID, permission, subjectType, subjectID string) (bool, error) {
	if a.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.timeout)
		defer cancel()
	}

	req := &v1.CheckPermissionRequest{
		Resource: &v1.ObjectReference{
			ObjectType: resourceType,
			ObjectId:   resourceID,
		},
		Permission: permission,
		Subject: &v1.SubjectReference{
			Object: &v1.ObjectReference{
				ObjectType: subjectType,
				ObjectId:   subjectID,
			},
		},
		Consistency: &v1.Consistency{
			Requirement: &v1.Consistency_MinimizeLatency{MinimizeLatency: true},
		},
	}

	var allowed bool
	err := a.guard.Do(ctx, func(ctx context.Context) error {
		resp, err := a.client.CheckPermission(ctx, req)
		if err != nil {
			return fmt.Errorf("%w: spicedb check: %v", module.ErrUpstream, err)
		}
		allowed = resp.Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION
		return nil
	})
	if err != nil {
		if errors.Is(err, upstream.ErrCircuitOpen) {
			return false, fmt.Errorf("%w: spicedb: circuit open", module.ErrUpstream)
		}
		return false, err
	}
	return allowed, nil
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

var templateFuncs = template.FuncMap{
	"lower": strings.ToLower,
	"upper": strings.ToUpper,
}

func factory(name string, raw map[string]any) (module.Authorizer, error) {
	endpoint, _ := raw["endpoint"].(string)
	if endpoint == "" {
		return nil, fmt.Errorf("%w: spicedb %q: endpoint is required", module.ErrConfig, name)
	}
	token, _ := raw["token"].(string)
	if token == "" {
		return nil, fmt.Errorf("%w: spicedb %q: token is required", module.ErrConfig, name)
	}
	useInsecure, _ := raw["insecure"].(bool)

	timeout := defaultTimeout
	if v, ok := raw["timeout"].(string); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("%w: spicedb %q: timeout: %v", module.ErrConfig, name, err)
		}
		timeout = d
	}

	check, _ := raw["check"].(map[string]any)
	if check == nil {
		return nil, fmt.Errorf("%w: spicedb %q: check block is required", module.ErrConfig, name)
	}
	resourceTypeSrc, _ := check["resourceType"].(string)
	resourceIDSrc, _ := check["resourceId"].(string)
	permissionSrc, _ := check["permission"].(string)
	subjectTypeSrc, _ := check["subjectType"].(string)
	subjectIDSrc, _ := check["subjectId"].(string)
	if resourceTypeSrc == "" || resourceIDSrc == "" || permissionSrc == "" || subjectTypeSrc == "" || subjectIDSrc == "" {
		return nil, fmt.Errorf("%w: spicedb %q: check.resourceType/resourceId/permission/subjectType/subjectId are all required", module.ErrConfig, name)
	}

	parse := func(field, src string) (*template.Template, error) {
		t, err := template.New(name + "." + field).Funcs(templateFuncs).Parse(src)
		if err != nil {
			return nil, fmt.Errorf("%w: spicedb %q: parse %s: %v", module.ErrConfig, name, field, err)
		}
		return t, nil
	}
	resourceTypeTpl, err := parse("resourceType", resourceTypeSrc)
	if err != nil {
		return nil, err
	}
	resourceIDTpl, err := parse("resourceId", resourceIDSrc)
	if err != nil {
		return nil, err
	}
	permissionTpl, err := parse("permission", permissionSrc)
	if err != nil {
		return nil, err
	}
	subjectTypeTpl, err := parse("subjectType", subjectTypeSrc)
	if err != nil {
		return nil, err
	}
	subjectIDTpl, err := parse("subjectId", subjectIDSrc)
	if err != nil {
		return nil, err
	}

	guardCfg, err := upstream.FromMap(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: spicedb %q: %v", module.ErrConfig, name, err)
	}

	// Build gRPC dial options.
	var dialOpts []grpc.DialOption
	if useInsecure {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		dialOpts = append(dialOpts, grpcutil.WithInsecureBearerToken(token))
	} else {
		systemCerts, err := grpcutil.WithSystemCerts(grpcutil.VerifyCA)
		if err != nil {
			return nil, fmt.Errorf("%w: spicedb %q: system certs: %v", module.ErrConfig, name, err)
		}
		dialOpts = append(dialOpts, systemCerts)
		dialOpts = append(dialOpts, grpcutil.WithBearerToken(token))
	}

	client, err := authzed.NewClient(endpoint, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: spicedb %q: dial: %v", module.ErrConfig, name, err)
	}

	return &authorizer{
		name:            name,
		timeout:         timeout,
		resourceTypeTpl: resourceTypeTpl,
		resourceIDTpl:   resourceIDTpl,
		permissionTpl:   permissionTpl,
		subjectTypeTpl:  subjectTypeTpl,
		subjectIDTpl:    subjectIDTpl,
		client:          client,
		guard:           upstream.NewGuard(guardCfg),
	}, nil
}

func init() {
	module.RegisterAuthorizer("spicedb", factory)
}
