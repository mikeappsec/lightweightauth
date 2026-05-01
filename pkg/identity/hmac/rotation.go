// Package hmac rotation support (D1 — ENT-KEYROT-1).
//
// Adds the `secrets` array format alongside the legacy `keys` map:
//
//	secrets:
//	  - kid: "v2"
//	    secret: "<base64>"
//	    subject: "service-a"
//	    roles: [machine]
//	    notBefore: "2026-05-01T00:00:00Z"
//	  - kid: "v1"
//	    secret: "<base64>"
//	    subject: "service-a"
//	    roles: [machine]
//	    notAfter: "2026-05-02T00:00:00Z"
//	    gracePeriod: "10m"
//
// When `secrets` is present it takes precedence over `keys`. The module
// uses pkg/keyrotation.KeySet to manage the lifecycle and emits
// lwauth_key_verify_total metrics per kid.
package hmac

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/keyrotation"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// RotatableKeyEntry extends KeyEntry with rotation metadata.
type RotatableKeyEntry struct {
	KeyEntry
	Meta keyrotation.KeyMeta
}

// parseSecrets parses the `secrets` array from config. Returns nil if
// the key is absent, allowing fallback to legacy `keys` map.
func parseSecrets(raw map[string]any) ([]RotatableKeyEntry, error) {
	arr, ok := raw["secrets"].([]any)
	if !ok || len(arr) == 0 {
		return nil, nil
	}

	entries := make([]RotatableKeyEntry, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: hmac: secrets entry must be an object", module.ErrConfig)
		}
		kid, _ := m["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("%w: hmac: secrets entry missing kid", module.ErrConfig)
		}
		secretStr, _ := m["secret"].(string)
		if secretStr == "" {
			return nil, fmt.Errorf("%w: hmac: secrets entry %q missing secret", module.ErrConfig, kid)
		}

		e := RotatableKeyEntry{}
		e.Meta.KID = kid
		e.Secret = decodeSecretBytes(secretStr)
		e.Subject, _ = m["subject"].(string)
		if e.Subject == "" {
			e.Subject = kid
		}
		if rs, ok := m["roles"].([]any); ok {
			for _, r := range rs {
				if s, ok := r.(string); ok {
					e.Roles = append(e.Roles, s)
				}
			}
		}
		if v, _ := m["notBefore"].(string); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return nil, fmt.Errorf("%w: hmac: secrets %q notBefore: %v", module.ErrConfig, kid, err)
			}
			e.Meta.NotBefore = t
		}
		if v, _ := m["notAfter"].(string); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return nil, fmt.Errorf("%w: hmac: secrets %q notAfter: %v", module.ErrConfig, kid, err)
			}
			e.Meta.NotAfter = t
		}
		if v, _ := m["gracePeriod"].(string); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return nil, fmt.Errorf("%w: hmac: secrets %q gracePeriod: %v", module.ErrConfig, kid, err)
			}
			e.Meta.GracePeriod = d
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// decodeSecretBytes attempts base64 decode; falls back to raw UTF-8.
func decodeSecretBytes(s string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return decoded
	}
	return []byte(s)
}
