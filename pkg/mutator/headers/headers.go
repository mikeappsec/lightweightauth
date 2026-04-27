// Package headers is the trio of header response mutators (DESIGN.md §4).
//
// Three modules register here:
//
//   - "header-add"      — set headers from literals or claim values.
//   - "header-remove"   — strip headers from the inbound request before
//                         it reaches upstream (e.g. drop the IdP-issued
//                         Authorization once we've minted our own).
//   - "header-passthrough" — copy a list of inbound headers verbatim onto
//                         the upstream side.
//
// All three target Decision.UpstreamHeaders / Decision.ResponseHeaders.
package headers

import (
	"context"
	"fmt"
	"strings"

	"github.com/yourorg/lightweightauth/pkg/module"
)

// ----- header-add ---------------------------------------------------------

type addMutator struct {
	name        string
	upstream    map[string]string // literal headers; values may be ${claim:foo}
	response    map[string]string
	subjectHdr  string // optional: convenience to set X-Auth-Subject = identity.Subject
}

func (m *addMutator) Name() string { return m.name }

func (m *addMutator) Mutate(_ context.Context, _ *module.Request, id *module.Identity, d *module.Decision) error {
	if d.UpstreamHeaders == nil && (len(m.upstream) > 0 || m.subjectHdr != "") {
		d.UpstreamHeaders = map[string]string{}
	}
	for k, v := range m.upstream {
		d.UpstreamHeaders[k] = expand(v, id)
	}
	if m.subjectHdr != "" && id != nil {
		d.UpstreamHeaders[m.subjectHdr] = id.Subject
	}
	if len(m.response) > 0 && d.ResponseHeaders == nil {
		d.ResponseHeaders = map[string]string{}
	}
	for k, v := range m.response {
		d.ResponseHeaders[k] = expand(v, id)
	}
	return nil
}

// expand resolves ${claim:foo} / ${sub} placeholders. Unknown placeholders
// are left as-is so misconfigurations are visible at runtime.
func expand(s string, id *module.Identity) string {
	if id == nil || !strings.Contains(s, "${") {
		return s
	}
	out := s
	out = strings.ReplaceAll(out, "${sub}", id.Subject)
	if id.Claims != nil {
		for k, v := range id.Claims {
			tok := "${claim:" + k + "}"
			if !strings.Contains(out, tok) {
				continue
			}
			out = strings.ReplaceAll(out, tok, fmt.Sprint(v))
		}
	}
	return out
}

func addFactory(name string, raw map[string]any) (module.ResponseMutator, error) {
	m := &addMutator{name: name}
	if v, ok := raw["upstream"].(map[string]any); ok {
		m.upstream = stringMap(v)
	}
	if v, ok := raw["response"].(map[string]any); ok {
		m.response = stringMap(v)
	}
	if v, ok := raw["subjectHeader"].(string); ok {
		m.subjectHdr = v
	}
	if len(m.upstream) == 0 && len(m.response) == 0 && m.subjectHdr == "" {
		return nil, fmt.Errorf("%w: header-add %q: at least one of upstream / response / subjectHeader required",
			module.ErrConfig, name)
	}
	return m, nil
}

// ----- header-remove ------------------------------------------------------

type removeMutator struct {
	name     string
	upstream []string
}

func (m *removeMutator) Name() string { return m.name }

// Mutate sets the listed upstream headers to the empty string. Envoy's
// ext_authz contract treats empty UpstreamHeaders values as "delete";
// other transports MAY interpret differently. Native Door B clients see
// "header X is dropped" as the intended semantics.
func (m *removeMutator) Mutate(_ context.Context, _ *module.Request, _ *module.Identity, d *module.Decision) error {
	if len(m.upstream) == 0 {
		return nil
	}
	if d.UpstreamHeaders == nil {
		d.UpstreamHeaders = map[string]string{}
	}
	for _, h := range m.upstream {
		d.UpstreamHeaders[h] = ""
	}
	return nil
}

func removeFactory(name string, raw map[string]any) (module.ResponseMutator, error) {
	var hdrs []string
	if v, ok := raw["upstream"].([]any); ok {
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				hdrs = append(hdrs, s)
			}
		}
	}
	if len(hdrs) == 0 {
		return nil, fmt.Errorf("%w: header-remove %q: upstream list is required", module.ErrConfig, name)
	}
	return &removeMutator{name: name, upstream: hdrs}, nil
}

// ----- header-passthrough -------------------------------------------------

type passthroughMutator struct {
	name string
	keys []string
}

func (m *passthroughMutator) Name() string { return m.name }

func (m *passthroughMutator) Mutate(_ context.Context, r *module.Request, _ *module.Identity, d *module.Decision) error {
	if len(m.keys) == 0 {
		return nil
	}
	if d.UpstreamHeaders == nil {
		d.UpstreamHeaders = map[string]string{}
	}
	for _, k := range m.keys {
		if v := r.Header(k); v != "" {
			d.UpstreamHeaders[k] = v
		}
	}
	return nil
}

func passthroughFactory(name string, raw map[string]any) (module.ResponseMutator, error) {
	var keys []string
	if v, ok := raw["headers"].([]any); ok {
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				keys = append(keys, s)
			}
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: header-passthrough %q: headers list is required", module.ErrConfig, name)
	}
	return &passthroughMutator{name: name, keys: keys}, nil
}

func stringMap(in map[string]any) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = fmt.Sprint(v)
	}
	return out
}

func init() {
	module.RegisterMutator("header-add", addFactory)
	module.RegisterMutator("header-remove", removeFactory)
	module.RegisterMutator("header-passthrough", passthroughFactory)
}
