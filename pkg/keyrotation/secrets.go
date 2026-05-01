package keyrotation

import (
	"encoding/base64"
	"fmt"
	"time"
)

// SecretEntry is the parsed form of one entry in a rotatable `secrets`
// config array. This is credential-type-agnostic — the raw secret bytes
// are stored opaquely; the calling module interprets them (HMAC key,
// API key hash, OAuth2 client secret, etc.).
type SecretEntry struct {
	Meta    KeyMeta
	Secret  []byte
	Subject string
	Roles   []string
	Extra   map[string]any // module-specific fields passed through
}

// ParseSecretsConfig parses the common `secrets:` array format from a
// module config map. Returns nil (no error) if the key is absent,
// allowing fallback to legacy formats.
//
// Expected YAML shape (embedded in any identifier config):
//
//	secrets:
//	  - kid: "v2"
//	    secret: "<base64-or-utf8>"
//	    subject: "service-a"       # optional
//	    roles: [machine]           # optional
//	    notBefore: "2026-05-01T00:00:00Z"  # optional
//	    notAfter:  "2026-05-02T00:00:00Z"  # optional
//	    gracePeriod: "10m"                  # optional
func ParseSecretsConfig(raw map[string]any) ([]SecretEntry, error) {
	arr, ok := raw["secrets"].([]any)
	if !ok || len(arr) == 0 {
		return nil, nil
	}

	entries := make([]SecretEntry, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("secrets entry must be an object")
		}
		kid, _ := m["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("secrets entry missing kid")
		}
		secretStr, _ := m["secret"].(string)
		if secretStr == "" {
			return nil, fmt.Errorf("secrets entry %q missing secret", kid)
		}

		e := SecretEntry{}
		e.Meta.KID = kid
		e.Secret = DecodeSecret(secretStr)
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
				return nil, fmt.Errorf("secrets %q notBefore: %w", kid, err)
			}
			e.Meta.NotBefore = t
		}
		if v, _ := m["notAfter"].(string); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return nil, fmt.Errorf("secrets %q notAfter: %w", kid, err)
			}
			e.Meta.NotAfter = t
		}
		if v, _ := m["gracePeriod"].(string); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return nil, fmt.Errorf("secrets %q gracePeriod: %w", kid, err)
			}
			e.Meta.GracePeriod = d
		}
		// Pass through any extra fields the module might need.
		e.Extra = make(map[string]any)
		for k, v := range m {
			switch k {
			case "kid", "secret", "subject", "roles", "notBefore", "notAfter", "gracePeriod":
			default:
				e.Extra[k] = v
			}
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// DecodeSecret attempts base64 standard decode; falls back to raw UTF-8.
func DecodeSecret(s string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return decoded
	}
	return []byte(s)
}
