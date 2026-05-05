// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package scim implements a SCIM 2.0 provisioning callback identifier
// (G9 — ID-SAML-1).
//
// SCIM (System for Cross-domain Identity Management, RFC 7643/7644) is used
// by IdPs to push user/group provisioning events to a Service Provider. This
// module validates incoming SCIM bearer tokens (used by the IdP to
// authenticate provisioning requests) and extracts the SCIM user identity.
//
// Configuration:
//
//	type: scim
//	name: scim-provisioning
//	config:
//	  bearerToken: "secret-provisioning-token"
//	  header: Authorization
//	  scheme: Bearer
//	  subjectClaim: userName
//	  groupsClaim: groups
package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func init() { module.RegisterIdentifier("scim", factory) }

// Compile-time guard.
var _ module.Identifier = (*identifier)(nil)

type identifier struct {
	name         string
	bearerToken  string
	header       string
	scheme       string
	subjectClaim string
	groupsClaim  string
}

func (i *identifier) Name() string { return i.name }

// Identify validates the SCIM provisioning bearer token and extracts
// the user identity from the SCIM request body (Users endpoint) or
// falls back to token-based identity for provisioning operations.
func (i *identifier) Identify(_ context.Context, r *module.Request) (*module.Identity, error) {
	// Check for bearer token in the configured header.
	raw := r.Header(i.header)
	if raw == "" {
		return nil, module.ErrNoMatch
	}

	prefix := i.scheme + " "
	if len(raw) < len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) {
		return nil, module.ErrNoMatch
	}
	token := strings.TrimSpace(raw[len(prefix):])
	if token == "" {
		return nil, module.ErrNoMatch
	}

	// Validate the provisioning bearer token.
	if token != i.bearerToken {
		return nil, fmt.Errorf("%w: scim: invalid provisioning token", module.ErrInvalidCredential)
	}

	// Try to extract user identity from request body (SCIM User payload).
	claims := map[string]any{
		"provisioning": true,
	}
	subject := "scim-provisioner"

	if len(r.Body) > 0 {
		var payload map[string]any
		if err := json.Unmarshal(r.Body, &payload); err == nil {
			// Extract subject from the configured claim field.
			if v, ok := payload[i.subjectClaim].(string); ok && v != "" {
				subject = v
				claims[i.subjectClaim] = v
			}
			// Extract groups if present.
			if i.groupsClaim != "" {
				if g, ok := payload[i.groupsClaim]; ok {
					claims[i.groupsClaim] = g
				}
			}
			// Extract SCIM schemas.
			if schemas, ok := payload["schemas"]; ok {
				claims["schemas"] = schemas
			}
			// Extract SCIM id if present.
			if id, ok := payload["id"].(string); ok {
				claims["scimId"] = id
			}
			// Extract displayName.
			if dn, ok := payload["displayName"].(string); ok {
				claims["displayName"] = dn
			}
			// Extract active status.
			if active, ok := payload["active"].(bool); ok {
				claims["active"] = active
			}
		}
	}

	return &module.Identity{
		Subject: subject,
		Claims:  claims,
		Source:  i.name,
	}, nil
}

// --- Factory ---------------------------------------------------------------

var knownKeys = map[string]struct{}{
	"bearerToken":  {},
	"header":       {},
	"scheme":       {},
	"subjectClaim": {},
	"groupsClaim":  {},
}

func factory(name string, raw map[string]any) (module.Identifier, error) {
	if err := module.CheckUnknownKeys("scim", name, raw, knownKeys); err != nil {
		return nil, err
	}

	id := &identifier{
		name:         name,
		header:       "Authorization",
		scheme:       "Bearer",
		subjectClaim: "userName",
		groupsClaim:  "groups",
	}

	if v, ok := raw["bearerToken"].(string); ok && v != "" {
		id.bearerToken = v
	} else {
		return nil, fmt.Errorf("%w: scim: bearerToken is required", module.ErrConfig)
	}

	if v, ok := raw["header"].(string); ok && v != "" {
		id.header = v
	}
	if v, ok := raw["scheme"].(string); ok && v != "" {
		id.scheme = v
	}
	if v, ok := raw["subjectClaim"].(string); ok && v != "" {
		id.subjectClaim = v
	}
	if v, ok := raw["groupsClaim"].(string); ok && v != "" {
		id.groupsClaim = v
	}

	return id, nil
}
