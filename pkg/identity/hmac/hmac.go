// Package hmac is the HMAC identifier. The default canonicalizer signs
//
//	method + "\n" + path + "\n" + dateHeader + "\n" + sha256(body)
//
// which is enough for most internal RPC fences and machine-to-machine
// auth (DESIGN.md §4). A SigV4-style canonicalizer is on the roadmap;
// the canonicalizer is a function value so we can plug a richer one in
// without changing the wire format.
//
// Authorization header format (default):
//
//	Authorization: HMAC-SHA256 keyId="abc", signature="<base64>"
//
// Replay protection: callers MUST send a Date header, and the module
// rejects any request whose Date is more than `clockSkew` from now.
package hmac

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/lightweightauth/pkg/module"
)

// Config is the YAML/CRD shape.
//
//	type: hmac
//	header:      Authorization                # default
//	scheme:      HMAC-SHA256                  # default
//	dateHeader:  Date                         # default
//	clockSkew:   5m                           # default
//	keys:
//	  abc: { secret: "<base64>", subject: "service-a", roles: [machine] }
type Config struct {
	Header     string                 `yaml:"header" json:"header"`
	Scheme     string                 `yaml:"scheme" json:"scheme"`
	DateHeader string                 `yaml:"dateHeader" json:"dateHeader"`
	ClockSkew  time.Duration          `yaml:"clockSkew" json:"clockSkew"`
	Keys       map[string]KeyEntry    `yaml:"keys" json:"keys"`
}

// KeyEntry is one HMAC key + its associated identity.
type KeyEntry struct {
	Secret  []byte
	Subject string
	Roles   []string
}

type identifier struct {
	name       string
	header     string
	scheme     string
	dateHeader string
	clockSkew  time.Duration
	keys       map[string]KeyEntry
	canon      Canonicalizer
}

// Canonicalizer turns a request into the byte string that gets HMAC'd.
// Replace via SetCanonicalizer to plug a SigV4-style scheme later.
type Canonicalizer func(r *module.Request, dateHeader string) []byte

// Default canonicalizer: method | path | date | sha256(body).
func defaultCanon(r *module.Request, dateHeader string) []byte {
	bodyHash := sha256.Sum256(r.Body)
	parts := []string{
		strings.ToUpper(r.Method),
		r.Path,
		r.Header(dateHeader),
		base64.StdEncoding.EncodeToString(bodyHash[:]),
	}
	return []byte(strings.Join(parts, "\n"))
}

func (i *identifier) Name() string { return i.name }

func (i *identifier) Identify(_ context.Context, r *module.Request) (*module.Identity, error) {
	auth := r.Header(i.header)
	if auth == "" {
		return nil, module.ErrNoMatch
	}
	prefix := i.scheme + " "
	if !strings.HasPrefix(auth, prefix) {
		return nil, module.ErrNoMatch
	}
	keyID, sigB64, err := parseAuth(auth[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("%w: hmac: %v", module.ErrInvalidCredential, err)
	}
	entry, ok := i.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: hmac: unknown keyId", module.ErrInvalidCredential)
	}
	if err := i.checkClockSkew(r); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, entry.Secret)
	mac.Write(i.canon(r, i.dateHeader))
	expected := mac.Sum(nil)
	got, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("%w: hmac: signature b64: %v", module.ErrInvalidCredential, err)
	}
	if subtle.ConstantTimeCompare(got, expected) != 1 {
		return nil, fmt.Errorf("%w: hmac: signature mismatch", module.ErrInvalidCredential)
	}

	claims := map[string]any{"sub": entry.Subject, "keyId": keyID}
	if len(entry.Roles) > 0 {
		rs := make([]any, len(entry.Roles))
		for i, r := range entry.Roles {
			rs[i] = r
		}
		claims["roles"] = rs
	}
	return &module.Identity{Subject: entry.Subject, Claims: claims, Source: i.name}, nil
}

func (i *identifier) checkClockSkew(r *module.Request) error {
	if i.clockSkew <= 0 {
		return nil
	}
	dv := r.Header(i.dateHeader)
	if dv == "" {
		return fmt.Errorf("%w: hmac: missing %s", module.ErrInvalidCredential, i.dateHeader)
	}
	t, err := http.ParseTime(dv)
	if err != nil {
		// fall back to RFC3339 for non-HTTP transports
		t, err = time.Parse(time.RFC3339, dv)
		if err != nil {
			return fmt.Errorf("%w: hmac: %s parse: %v", module.ErrInvalidCredential, i.dateHeader, err)
		}
	}
	if d := time.Since(t); d > i.clockSkew || -d > i.clockSkew {
		return fmt.Errorf("%w: hmac: clock skew %s > %s", module.ErrInvalidCredential, d, i.clockSkew)
	}
	return nil
}

// parseAuth tolerates both
//
//	keyId="abc", signature="<b64>"          (RFC-style)
//	abc:<b64>                                (compact)
func parseAuth(s string) (keyID, sig string, err error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ':'); i > 0 && !strings.ContainsAny(s, "=,") {
		return s[:i], s[i+1:], nil
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(part[:eq]))
		v := strings.Trim(strings.TrimSpace(part[eq+1:]), `"`)
		switch k {
		case "keyid":
			keyID = v
		case "signature":
			sig = v
		}
	}
	if keyID == "" || sig == "" {
		return "", "", fmt.Errorf("missing keyId/signature")
	}
	return keyID, sig, nil
}

func factory(name string, raw map[string]any) (module.Identifier, error) {
	hdr := "Authorization"
	if v, ok := raw["header"].(string); ok && v != "" {
		hdr = v
	}
	scheme := "HMAC-SHA256"
	if v, ok := raw["scheme"].(string); ok && v != "" {
		scheme = v
	}
	dateHdr := "Date"
	if v, ok := raw["dateHeader"].(string); ok && v != "" {
		dateHdr = v
	}
	skew := 5 * time.Minute
	if v, ok := raw["clockSkew"].(string); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("%w: hmac.clockSkew: %v", module.ErrConfig, err)
		}
		skew = d
	}

	rawKeys, _ := raw["keys"].(map[string]any)
	if len(rawKeys) == 0 {
		return nil, fmt.Errorf("%w: hmac %q: keys map is required", module.ErrConfig, name)
	}
	keys := make(map[string]KeyEntry, len(rawKeys))
	for kid, v := range rawKeys {
		spec, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: hmac %q: key %q must be an object", module.ErrConfig, name, kid)
		}
		secret, _ := spec["secret"].(string)
		if secret == "" {
			return nil, fmt.Errorf("%w: hmac %q: key %q missing secret", module.ErrConfig, name, kid)
		}
		raw, err := base64.StdEncoding.DecodeString(secret)
		if err != nil {
			// Allow plain UTF-8 secrets too — easier for human-managed config.
			raw = []byte(secret)
		}
		entry := KeyEntry{Secret: raw}
		entry.Subject, _ = spec["subject"].(string)
		if entry.Subject == "" {
			entry.Subject = kid
		}
		if rs, ok := spec["roles"].([]any); ok {
			for _, r := range rs {
				if s, ok := r.(string); ok {
					entry.Roles = append(entry.Roles, s)
				}
			}
		}
		keys[kid] = entry
	}

	return &identifier{
		name:       name,
		header:     hdr,
		scheme:     scheme,
		dateHeader: dateHdr,
		clockSkew:  skew,
		keys:       keys,
		canon:      defaultCanon,
	}, nil
}

func init() { module.RegisterIdentifier("hmac", factory) }
