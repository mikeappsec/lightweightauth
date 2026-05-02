// Package hmac is the HMAC identifier.
//
// # Canonical request shape
//
// The signed bytes are a newline-separated canonical string:
//
//	HMAC-SHA256-V1
//	upper(method)
//	lower(host)
//	pathWithoutQuery
//	canonicalQuery
//	lower(name1) ":" joinedValues1
//	lower(name2) ":" joinedValues2
//	...
//	signedHeadersList                       (e.g. "date,host")
//	hex(sha256(body))
//
//   - `canonicalQuery` is the request's raw query string split on `&`,
//     each kv preserved verbatim, then sorted lexicographically and
//     re-joined with `&`. Empty when no query is present.
//   - The header lines reproduce, in the SAME order they appear in the
//     `signedHeaders` list of the Authorization header, every header
//     the signer wanted bound. Multi-value headers are joined with
//     `,` (single comma, no spaces).
//   - `signedHeadersList` itself MUST include `host` and the configured
//     `dateHeader` (case-insensitive); the verifier rejects the
//     signature otherwise. Operators can extend the required set via
//     `requiredSignedHeaders` to bind extra inputs (e.g. `content-type`).
//
// **Authorization header:**
//
//	Authorization: HMAC-SHA256 keyId="abc", signedHeaders="date;host;content-type", signature="<b64>"
//
// The `signedHeaders` list is `;`-separated by default so the comma
// that separates top-level Authorization parameters keeps working;
// a quoted comma form (`"date,host"`) is also accepted.
//
// Replay protection: callers MUST send a Date header (configurable),
// and the module rejects any request whose Date is more than
// `clockSkew` from now.
package hmac

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// Config is the YAML/CRD shape.
//
//	type: hmac
//	header:        Authorization                # default
//	scheme:        HMAC-SHA256                  # default
//	dateHeader:    Date                         # default
//	clockSkew:     5m                           # default
//	requiredSignedHeaders: [host, date]         # default
//	keys:
//	  abc: { secret: "<base64>", subject: "service-a", roles: [machine] }
type Config struct {
	Header                string              `yaml:"header" json:"header"`
	Scheme                string              `yaml:"scheme" json:"scheme"`
	DateHeader            string              `yaml:"dateHeader" json:"dateHeader"`
	ClockSkew             time.Duration       `yaml:"clockSkew" json:"clockSkew"`
	RequiredSignedHeaders []string            `yaml:"requiredSignedHeaders" json:"requiredSignedHeaders"`
	Keys                  map[string]KeyEntry `yaml:"keys" json:"keys"`
}

// KeyEntry is one HMAC key + its associated identity.
type KeyEntry struct {
	Secret  []byte
	Subject string
	Roles   []string
}

type identifier struct {
	name            string
	header          string
	scheme          string
	dateHeader      string
	clockSkew       time.Duration
	requiredHeaders []string // already lower-cased
	keys            map[string]KeyEntry
}

// canonical builds the canonical string. signedHeaders is the
// already-validated list from the Authorization header, in the order
// the signer chose; we reproduce the same order so signer/verifier
// agree.
func canonical(r *module.Request, signedHeaders []string) []byte {
	path, query := splitPathQuery(r.Path)
	bodyHash := sha256.Sum256(r.Body)

	var b strings.Builder
	b.WriteString("HMAC-SHA256-V1\n")
	b.WriteString(strings.ToUpper(r.Method))
	b.WriteByte('\n')
	b.WriteString(strings.ToLower(r.Host))
	b.WriteByte('\n')
	b.WriteString(path)
	b.WriteByte('\n')
	b.WriteString(canonicalQuery(query))
	b.WriteByte('\n')
	for _, h := range signedHeaders {
		b.WriteString(strings.ToLower(h))
		b.WriteByte(':')
		b.WriteString(joinHeaderValues(r, h))
		b.WriteByte('\n')
	}
	b.WriteString(strings.Join(lowerAll(signedHeaders), ","))
	b.WriteByte('\n')
	b.WriteString(hex.EncodeToString(bodyHash[:]))
	return []byte(b.String())
}

func splitPathQuery(p string) (path, query string) {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return p, ""
}

// canonicalQuery sorts the raw kv pairs of a query string
// lexicographically and rejoins them with `&`. This is intentionally a
// byte-level sort: signer and verifier just need to apply the same
// transformation; we never URL-decode (so % escapes survive verbatim).
func canonicalQuery(q string) string {
	if q == "" {
		return ""
	}
	parts := strings.Split(q, "&")
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

// joinHeaderValues returns all values of `name` joined with a single
// comma, in the order the request carried them. Trims surrounding
// whitespace per value (RFC 7230 §3.2.4).
func joinHeaderValues(r *module.Request, name string) string {
	if r == nil || r.Headers == nil {
		return ""
	}
	for k, vs := range r.Headers {
		if !strings.EqualFold(k, name) {
			continue
		}
		out := make([]string, 0, len(vs))
		for _, v := range vs {
			out = append(out, strings.TrimSpace(v))
		}
		return strings.Join(out, ",")
	}
	return ""
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
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
	parsed, err := parseAuth(auth[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("%w: hmac: %v", module.ErrInvalidCredential, err)
	}
	entry, ok := i.keys[parsed.keyID]
	if !ok {
		return nil, fmt.Errorf("%w: hmac: unknown keyId", module.ErrInvalidCredential)
	}
	if err := i.checkClockSkew(r); err != nil {
		return nil, err
	}
	signed, err := i.validateSignedHeaders(parsed.signedHeaders)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, entry.Secret)
	mac.Write(canonical(r, signed))
	expected := mac.Sum(nil)
	got, err := base64.StdEncoding.DecodeString(parsed.signature)
	if err != nil {
		return nil, fmt.Errorf("%w: hmac: signature b64: %v", module.ErrInvalidCredential, err)
	}
	if subtle.ConstantTimeCompare(got, expected) != 1 {
		return nil, fmt.Errorf("%w: hmac: signature mismatch", module.ErrInvalidCredential)
	}

	claims := map[string]any{"sub": entry.Subject, "keyId": parsed.keyID}
	if len(entry.Roles) > 0 {
		rs := make([]any, len(entry.Roles))
		for i, r := range entry.Roles {
			rs[i] = r
		}
		claims["roles"] = rs
	}
	return &module.Identity{Subject: entry.Subject, Claims: claims, Source: i.name}, nil
}

// validateSignedHeaders enforces that the signer's signedHeaders list
// contains every header the operator declared as required (always
// including host + dateHeader by default). This is the protection that
// stops a signer from omitting host or query-affecting headers.
func (i *identifier) validateSignedHeaders(have []string) ([]string, error) {
	if len(have) == 0 {
		return nil, fmt.Errorf("%w: hmac: signedHeaders missing in Authorization", module.ErrInvalidCredential)
	}
	present := make(map[string]struct{}, len(have))
	for _, h := range have {
		present[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	for _, req := range i.requiredHeaders {
		if _, ok := present[req]; !ok {
			return nil, fmt.Errorf("%w: hmac: signedHeaders missing required %q", module.ErrInvalidCredential, req)
		}
	}
	return have, nil
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

type parsedAuth struct {
	keyID         string
	signature     string
	signedHeaders []string // ordered, raw (case preserved)
}

// parseAuth understands the canonical form
//
//	keyId="abc", signedHeaders="date;host", signature="<b64>"
//
// The signedHeaders value tolerates both ';' (default) and ',' as
// separators. The compact `keyId:signature` form is no longer
// accepted: it cannot carry a signedHeaders list.
func parseAuth(s string) (parsedAuth, error) {
	s = strings.TrimSpace(s)
	out := parsedAuth{}
	for _, part := range splitTopLevelCommas(s) {
		part = strings.TrimSpace(part)
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(part[:eq]))
		v := strings.Trim(strings.TrimSpace(part[eq+1:]), `"`)
		switch k {
		case "keyid":
			out.keyID = v
		case "signature":
			out.signature = v
		case "signedheaders":
			out.signedHeaders = parseSignedHeaders(v)
		}
	}
	if out.keyID == "" || out.signature == "" {
		return parsedAuth{}, fmt.Errorf("missing keyId/signature")
	}
	return out, nil
}

// splitTopLevelCommas splits an Authorization parameter string on
// commas that are NOT inside double quotes. This lets a quoted
// signedHeaders value contain commas (e.g. "host,date") while a comma
// between the keyId / signature / signedHeaders pairs still acts as
// the separator.
func splitTopLevelCommas(s string) []string {
	var parts []string
	depth := 0
	last := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			depth ^= 1
		case ',':
			if depth == 0 {
				parts = append(parts, s[last:i])
				last = i + 1
			}
		}
	}
	parts = append(parts, s[last:])
	return parts
}

// parseSignedHeaders accepts both ';' and ',' separators inside the
// already-unquoted value.
func parseSignedHeaders(v string) []string {
	v = strings.ReplaceAll(v, ";", ",")
	out := make([]string, 0, 4)
	for _, h := range strings.Split(v, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			out = append(out, h)
		}
	}
	return out
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

	// Required signed headers: default to host + dateHeader. Operators
	// can extend (e.g. ["host","date","content-type","x-amz-target"])
	// to harden specific routes, but emptying the list is rejected —
	// that would silently disable host/date binding.
	required := []string{"host", strings.ToLower(dateHdr)}
	if v, ok := raw["requiredSignedHeaders"].([]any); ok {
		required = required[:0]
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				required = append(required, strings.ToLower(s))
			}
		}
		if len(required) == 0 {
			return nil, fmt.Errorf("%w: hmac.requiredSignedHeaders: empty list disables host/date binding", module.ErrConfig)
		}
	}
	required = dedupStrings(required)

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
		name:            name,
		header:          hdr,
		scheme:          scheme,
		dateHeader:      dateHdr,
		clockSkew:       skew,
		requiredHeaders: required,
		keys:            keys,
	}, nil
}

func dedupStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// RevocationKeys implements module.RevocationChecker for the HMAC identifier.
// It derives keys from the HMAC key ID and the identity's subject.
func (i *identifier) RevocationKeys(id *module.Identity, tenantID string) []string {
	if id == nil {
		return nil
	}
	var keys []string

	// Key by key ID — revokes a specific HMAC signing key.
	if kid, ok := id.Claims["keyId"].(string); ok && kid != "" {
		keys = append(keys, "kid:"+kid)
	}

	// Key by subject — revokes ALL credentials for this identity.
	if id.Subject != "" {
		prefix := "sub:"
		if tenantID != "" {
			prefix += tenantID + ":"
		}
		keys = append(keys, prefix+id.Subject)
	}

	return keys
}

func init() { module.RegisterIdentifier("hmac", factory) }
