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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func init() { module.RegisterIdentifier("scim", factory) }

// maxSCIMBodySize is the maximum allowed SCIM request body size (1 MiB).
// This prevents memory exhaustion from oversized payloads.
const maxSCIMBodySize = 1 << 20 // 1 MiB

// minTokenLen is the minimum acceptable bearer token length (20 bytes).
// Short tokens are trivially brute-forceable at the provisioning endpoint.
// SCIM-VULN-01: enforced at configuration time.
const minTokenLen = 20

// maxSubjectLen is the maximum length of a body-derived subject (1024 chars).
// SCIM-VULN-04: prevents memory exhaustion from oversized subjects in
// identity caches and log storage.
const maxSubjectLen = 1024

// maxGroupsCount is the maximum number of group entries extracted from the body.
// SCIM-VULN-05: prevents resource exhaustion from extremely large group arrays.
const maxGroupsCount = 100

// Compile-time guard.
var _ module.Identifier = (*identifier)(nil)

type identifier struct {
	name          string
	tokenHash     [32]byte // G9-VULN-10: SHA-256 of bearer token (not plaintext)
	header        string
	scheme        string
	subjectClaim  string
	groupsClaim   string
	subjectPrefix string // SCIM-VULN-02: namespace prefix for body-derived subjects
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

	// G9-VULN-10: Compare SHA-256 hash of presented token against stored hash.
	// This avoids holding the plaintext token in memory (heap dump exposure)
	// while maintaining constant-time comparison.
	presentedHash := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(presentedHash[:], i.tokenHash[:]) != 1 {
		return nil, fmt.Errorf("%w: scim: invalid provisioning token", module.ErrInvalidCredential)
	}

	// Try to extract user identity from request body (SCIM User payload).
	// G9-VULN-05: Enforce maximum body size to prevent memory exhaustion.
	claims := map[string]any{
		"provisioning": true,
	}
	subject := "scim-provisioner"

	if len(r.Body) > maxSCIMBodySize {
		return nil, fmt.Errorf("%w: scim: request body exceeds maximum size (%d bytes)",
			module.ErrInvalidCredential, maxSCIMBodySize)
	}

	if len(r.Body) > 0 {
		var payload map[string]any
		if err := json.Unmarshal(r.Body, &payload); err == nil {
			// Extract subject from the configured claim field.
			if v, ok := payload[i.subjectClaim].(string); ok && v != "" {
				// SCIM-VULN-04: Reject subjects exceeding maximum length.
				if len(v) > maxSubjectLen {
					return nil, fmt.Errorf("%w: scim: %s exceeds maximum length (%d chars)",
						module.ErrInvalidCredential, i.subjectClaim, maxSubjectLen)
				}
				// SCIM-VULN-03: Reject subjects containing control characters
				// to prevent log injection and audit evasion.
				if containsControlChar(v) {
					return nil, fmt.Errorf("%w: scim: %s contains invalid control characters",
						module.ErrInvalidCredential, i.subjectClaim)
				}
				// SCIM-VULN-02: Prefix prevents body-derived subjects from
				// colliding with subjects produced by other identifiers
				// (JWT, HMAC, etc.) in shared authorization pipelines.
				subject = i.subjectPrefix + v
				claims[i.subjectClaim] = v
			}
			// Extract groups if present.
			if i.groupsClaim != "" {
				if g, ok := payload[i.groupsClaim]; ok {
					// SCIM-VULN-05: Validate groups is an array of strings
					// and enforce maximum count to prevent type confusion
					// and resource exhaustion in downstream authorization.
					validated, err := validateGroups(g, i.groupsClaim)
					if err != nil {
						return nil, fmt.Errorf("%w: scim: %v", module.ErrInvalidCredential, err)
					}
					claims[i.groupsClaim] = validated
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
	"bearerToken":   {},
	"header":        {},
	"scheme":        {},
	"subjectClaim":  {},
	"groupsClaim":   {},
	"subjectPrefix": {},
}

func factory(name string, raw map[string]any) (module.Identifier, error) {
	if err := module.CheckUnknownKeys("scim", name, raw, knownKeys); err != nil {
		return nil, err
	}

	id := &identifier{
		name:          name,
		header:        "Authorization",
		scheme:        "Bearer",
		subjectClaim:  "userName",
		groupsClaim:   "groups",
		subjectPrefix: "scim:",
	}

	if v, ok := raw["bearerToken"].(string); ok && v != "" {
		// SCIM-VULN-01: Reject short tokens that are trivially brute-forceable.
		if len(v) < minTokenLen {
			return nil, fmt.Errorf("%w: scim: bearerToken must be at least %d characters", module.ErrConfig, minTokenLen)
		}
		// G9-VULN-10: Store only the hash; the plaintext is discarded.
		id.tokenHash = sha256.Sum256([]byte(v))
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
	if v, ok := raw["subjectPrefix"].(string); ok {
		id.subjectPrefix = v // allow empty to opt out (not recommended)
	}

	return id, nil
}

// containsControlChar reports whether s contains any ASCII control character
// (bytes 0x00–0x1F or 0x7F) or Unicode control category characters.
// SCIM-VULN-03: prevents log injection / audit evasion via crafted subjects.
func containsControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7F || unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// validateGroups checks that the groups value is a JSON array of strings
// and enforces the maximum groups count.
// SCIM-VULN-05: prevents type confusion and resource exhaustion.
func validateGroups(v any, claimName string) ([]string, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a JSON array", claimName)
	}
	if len(arr) > maxGroupsCount {
		return nil, fmt.Errorf("%s exceeds maximum count (%d)", claimName, maxGroupsCount)
	}
	result := make([]string, 0, len(arr))
	for _, elem := range arr {
		s, ok := elem.(string)
		if !ok {
			return nil, fmt.Errorf("%s must contain only strings", claimName)
		}
		result = append(result, s)
	}
	return result, nil
}
