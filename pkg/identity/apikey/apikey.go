// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package apikey is the default API-key identifier module.
//
// Storage backends (see store.go):
//
//   - in-memory plaintext map (`static`)         — tests / dev only.
//   - in-memory argon2id (`hashed.entries`)      — small static fleets.
//   - flat file of argon2id digests (`hashed.file`) — ConfigMap / file mount.
//   - directory of argon2id digests (`hashed.dir`) — K8s Secret volume.
//
// Wire keys are NEVER stored at rest in production-grade modes; the only
// plaintext is the value the client sends.
package apikey

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/mikeappsec/lightweightauth/pkg/keyrotation"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// Config is the YAML/CRD shape.
//
//	type: apikey
//	headerName: X-Api-Key       # default
//	# Pick exactly one of:
//	static:                     # plaintext, tests/dev only
//	  k1: alice
//	  k2: { subject: bob, roles: [admin] }
//	hashed:
//	  file: /etc/lwauth/apikeys.txt
//	  # OR
//	  dir:  /etc/lwauth/apikeys/
//	  # OR
//	  entries:                  # in-line argon2id hashes
//	    abc:
//	      hash:    "$argon2id$v=19$m=65536,t=2,p=1$..."
//	      subject: alice
//	      roles:   [admin]
//	# OR, for rotation support:
//	secrets:
//	  - kid: "v2"
//	    secret: "<base64-or-utf8>"
//	    notAfter: "2026-05-02T00:00:00Z"
type Config struct {
	HeaderName string         `yaml:"headerName" json:"headerName"`
	Header     string         `yaml:"header" json:"header"`
	Static     map[string]any `yaml:"static" json:"static"`
	Hashed     map[string]any `yaml:"hashed" json:"hashed"`
	Secrets    []any          `yaml:"secrets" json:"secrets"`
}

type entry struct {
	subject string
	roles   []string
	keyID   string
}

type identifier struct {
	name   string
	header string
	store  Store
}

func (i *identifier) Name() string { return i.name }

func (i *identifier) Identify(ctx context.Context, r *module.Request) (*module.Identity, error) {
	v := r.Header(i.header)
	if v == "" {
		return nil, module.ErrNoMatch
	}
	e, ok := i.store.Lookup(v)
	if !ok {
		return nil, module.ErrInvalidCredential
	}
	claims := map[string]any{"sub": e.subject}
	if e.keyID != "" {
		claims["keyId"] = e.keyID
	}
	if len(e.roles) > 0 {
		rs := make([]any, len(e.roles))
		for i, r := range e.roles {
			rs[i] = r
		}
		claims["roles"] = rs
	}
	return &module.Identity{
		Subject: e.subject,
		Source:  i.name,
		Claims:  claims,
	}, nil
}

func factory(name string, raw map[string]any) (module.Identifier, error) {
	var cfg Config
	if err := module.DecodeConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("apikey %q: %w", name, err)
	}
	hdr := "X-Api-Key"
	if cfg.HeaderName != "" {
		hdr = cfg.HeaderName
	} else if cfg.Header != "" {
		hdr = cfg.Header
	}
	store, keyset, err := buildStore(name, raw)
	if err != nil {
		return nil, err
	}
	base := identifier{name: name, header: hdr, store: store}
	if keyset != nil {
		return &rotatableIdentifier{identifier: base, keyset: keyset}, nil
	}
	return &base, nil
}

// buildStore picks exactly one of `static`, `hashed`, or `secrets`. The
// returned KeySet is non-nil only for the `secrets` (rotation-aware) path.
func buildStore(name string, raw map[string]any) (Store, *keyrotation.KeySet[entry], error) {
	staticRaw, hasStatic := raw["static"].(map[string]any)
	hashedRaw, hasHashed := raw["hashed"].(map[string]any)
	secretsRaw, hasSecrets := raw["secrets"].([]any)
	hasSecrets = hasSecrets && len(secretsRaw) > 0
	switch n := boolCount(hasStatic, hasHashed, hasSecrets); {
	case n > 1:
		return nil, nil, fmt.Errorf("%w: apikey %q: pick exactly one of static / hashed / secrets", module.ErrConfig, name)
	case n == 0:
		return nil, nil, fmt.Errorf("%w: apikey %q: one of static / hashed / secrets is required", module.ErrConfig, name)
	}

	if hasSecrets {
		entries, err := keyrotation.ParseSecretsConfig(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: apikey %q: %v", module.ErrConfig, name, err)
		}
		store, ks := buildRotatableStore(entries)
		return store, ks, nil
	}

	if hasStatic {
		// Plaintext keys belong in dev/test only. Emit a single
		// startup warning so an operator who mounts an example config
		// in production sees it in their logs immediately, alongside
		// pod boot.
		slog.Warn("apikey: plaintext static backend loaded; suitable for dev only -- use hashed.{file,dir,entries} in production",
			"identifier", name, "keys", len(staticRaw))
		keys := make(map[string]entry, len(staticRaw))
		for k, val := range staticRaw {
			switch t := val.(type) {
			case string:
				if t == "" {
					return nil, nil, fmt.Errorf("%w: apikey %q: static[%q] subject is required (empty subject defeats RBAC and audit)", module.ErrConfig, name, k)
				}
				keys[k] = entry{subject: t, keyID: shortID(k)}
			case map[string]any:
				e := entry{keyID: shortID(k)}
				if s, ok := t["subject"].(string); ok {
					e.subject = s
				}
				if e.subject == "" {
					return nil, nil, fmt.Errorf("%w: apikey %q: static[%q].subject is required (empty subject defeats RBAC and audit)", module.ErrConfig, name, k)
				}
				if rs, ok := t["roles"].([]any); ok {
					for _, r := range rs {
						if s, ok := r.(string); ok {
							e.roles = append(e.roles, s)
						}
					}
				}
				keys[k] = e
			}
		}
		return &staticStore{keys: keys}, nil, nil
	}

	// Hashed branch.
	if file, ok := hashedRaw["file"].(string); ok && file != "" {
		store, err := LoadHashedStoreFromFile(file)
		return store, nil, err
	}
	if dir, ok := hashedRaw["dir"].(string); ok && dir != "" {
		store, err := LoadHashedStoreFromDir(dir)
		return store, nil, err
	}
	if entries, ok := hashedRaw["entries"].(map[string]any); ok {
		store := &HashedStore{}
		for id, v := range entries {
			spec, ok := v.(map[string]any)
			if !ok {
				return nil, nil, fmt.Errorf("%w: apikey %q: hashed.entries[%q] must be an object", module.ErrConfig, name, id)
			}
			hash, _ := spec["hash"].(string)
			if hash == "" {
				return nil, nil, fmt.Errorf("%w: apikey %q: hashed.entries[%q].hash is required", module.ErrConfig, name, id)
			}
			subject, _ := spec["subject"].(string)
			if subject == "" {
				return nil, nil, fmt.Errorf("%w: apikey %q: hashed.entries[%q].subject is required (empty subject defeats RBAC and audit)", module.ErrConfig, name, id)
			}
			var roles []string
			if rs, ok := spec["roles"].([]any); ok {
				for _, r := range rs {
					if s, ok := r.(string); ok {
						roles = append(roles, s)
					}
				}
			}
			if err := store.AddHashed(id, hash, subject, roles); err != nil {
				return nil, nil, fmt.Errorf("apikey %q entry %q: %w", name, id, err)
			}
		}
		return store, nil, nil
	}
	return nil, nil, fmt.Errorf("%w: apikey %q: hashed needs one of file / dir / entries", module.ErrConfig, name)
}

// boolCount returns how many of the given booleans are true.
func boolCount(bs ...bool) int {
	n := 0
	for _, b := range bs {
		if b {
			n++
		}
	}
	return n
}

// RevocationKeys implements module.RevocationChecker for the API key identifier.
// It derives keys from the key ID and the identity's subject.
func (i *identifier) RevocationKeys(id *module.Identity, tenantID string) []string {
	if id == nil {
		return nil
	}
	var keys []string

	// Key by key ID — revokes a specific API key.
	if kid, ok := id.Claims["keyId"].(string); ok && kid != "" {
		keys = append(keys, "kid:"+kid)
	}

	// Key by subject — revokes ALL credentials for this user/service.
	if id.Subject != "" {
		prefix := "sub:"
		if tenantID != "" {
			prefix += tenantID + ":"
		}
		keys = append(keys, prefix+id.Subject)
	}

	return keys
}

func init() { module.RegisterIdentifier("apikey", factory) }
