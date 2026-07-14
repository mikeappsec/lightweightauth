// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package configmgmt

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// secretValueSentinel replaces a single value-secret field in a
// GET/history/rollback response. PushConfig restores the real value from
// the previous version wherever it finds this exact string — see
// mergeSecrets. Deliberately a distinctive printable string, not a
// NUL-bracketed marker: this value round-trips through an HTML
// <textarea> in the console's edit mode, and some browsers mangle
// control bytes in .value, which would silently corrupt an "unchanged"
// signal into "here's a new secret: <mangled sentinel>".
const secretValueSentinel = "◄◄LWAUTH:REDACTED-SECRET:DO-NOT-TYPE-THIS►►"

// secretBlockSentinelPrefix marks an entire redacted subtree collapsed to
// a single descriptive string (e.g. apikey's `static`, whose keys — not
// values — are the actual secrets, so per-entry redaction can't safely
// round-trip). Matching on push is by prefix; the rest of the string is
// a human-readable summary only, not semantically significant.
const secretBlockSentinelPrefix = "◄◄LWAUTH:REDACTED-BLOCK"

// errFirstPushSentinel is returned when submitted content contains a
// redaction sentinel but there is no previous version to restore the
// real value from (first-ever push for this instance, or the field/
// module the sentinel appears under has no counterpart in the previous
// version). Silently accepting the sentinel in this case would persist
// the literal placeholder string as if it were a real secret.
var errFirstPushSentinel = errors.New("config contains a redacted-secret placeholder but there is no previous version to restore the real value from — enter the actual value")

// FieldClass says how a field is treated by redaction (GET-time) and
// merge (PUSH-time).
type FieldClass int

const (
	// ClassNone is the zero value; unused, present so an omitted Class
	// in a table literal is caught by review rather than silently
	// treated as some other meaningful class.
	ClassNone FieldClass = iota
	// ClassValueSecret: the field's value is a secret. Redacted to
	// secretValueSentinel; merge restores the real value from the
	// previous version at the same path.
	ClassValueSecret
	// ClassHash: a one-way digest (e.g. apikey's argon2id hashed
	// entries). Lower sensitivity than a raw secret — passed through
	// unredacted today. Kept in the table so the omission is a
	// documented decision, not a gap.
	ClassHash
	// ClassBlock: the secret is structural (the map KEY is the secret,
	// not a value under it — e.g. apikey.static, keyed by the raw API
	// key). The whole subtree is collapsed to a single
	// secretBlockSentinelPrefix string on redact; on merge, the
	// sentinel restores the whole prior subtree verbatim, anything
	// else submitted is accepted as a deliberate full replacement.
	ClassBlock
	// ClassBlockIfHeuristic is like ClassBlock, but only collapses when
	// a cheap heuristic finds something secret-shaped inside — used for
	// grpc-plugin's lifecycle.env, which is unstructured "KEY=VALUE"
	// strings with no schema.
	ClassBlockIfHeuristic
)

// FieldRule locates one sensitive field within a module's Config map (or,
// for topLevelRules, within the whole parsed AuthConfig document).
type FieldRule struct {
	// Path is applied depth-first. "*" matches every element of a
	// map[string]any (keyed by the map's own key) or every element of a
	// []any (paired by ArrayIDKey when set, else by position).
	Path []string
	// Class selects the redact/merge behavior — see the FieldClass docs.
	Class FieldClass
	// ArrayIDKey pairs old/new array elements by this field's value
	// (e.g. "kid", "id") instead of position, so inserting or
	// reordering array entries doesn't misattribute a restored secret
	// to the wrong entry. Ignored for map wildcards (already keyed) and
	// for array elements lacking this field (falls back to position).
	ArrayIDKey string
	// BlockKind is a short label embedded in the block sentinel text,
	// for humans reading raw JSON. Not used for matching.
	BlockKind string
}

// moduleRules is keyed by ModuleSpec.Type. Paths are relative to that
// module's Config map. Module type strings verified against each
// package's init() registration (module.RegisterIdentifier/Authorizer/
// Mutator calls); field paths verified against each module's factory
// (the map key it actually reads out of the raw config), not just its
// doc comments.
var moduleRules = map[string][]FieldRule{
	"apikey": {
		{Path: []string{"static"}, Class: ClassBlock, BlockKind: "static-keys"},
		{Path: []string{"hashed", "entries", "*", "hash"}, Class: ClassHash},
		{Path: []string{"secrets", "*", "secret"}, Class: ClassValueSecret, ArrayIDKey: "kid"},
	},
	"hmac": {
		{Path: []string{"keys", "*", "secret"}, Class: ClassValueSecret}, // map keyed by kid, already stable
		{Path: []string{"secrets", "*", "secret"}, Class: ClassValueSecret, ArrayIDKey: "kid"},
	},
	"oauth2": {
		{Path: []string{"clientSecret"}, Class: ClassValueSecret},
		{Path: []string{"cookie", "secret"}, Class: ClassValueSecret},
		{Path: []string{"secrets", "*", "secret"}, Class: ClassValueSecret, ArrayIDKey: "kid"},
	},
	"oauth2-introspection": {
		{Path: []string{"clientSecret"}, Class: ClassValueSecret},
		{Path: []string{"secrets", "*", "secret"}, Class: ClassValueSecret, ArrayIDKey: "kid"},
	},
	"scim":      {{Path: []string{"bearerToken"}, Class: ClassValueSecret}},
	"openfga":   {{Path: []string{"apiToken"}, Class: ClassValueSecret}},
	"spicedb":   {{Path: []string{"token"}, Class: ClassValueSecret}},
	"jwt-issue": {{Path: []string{"key"}, Class: ClassValueSecret}},
	"grpc-plugin": {
		{Path: []string{"signing", "keys", "*", "hmacSecret"}, Class: ClassValueSecret, ArrayIDKey: "id"},
		{Path: []string{"lifecycle", "env"}, Class: ClassBlockIfHeuristic, BlockKind: "lifecycle-env"},
	},
}

// topLevelRules apply directly to the parsed AuthConfig root object,
// outside any module Config map.
//
// cache.password/sharedHmacKey and revocation.password: internal/config's
// typed structs mark these json:"-", but configmgmt.Store never parses
// Content into that struct — it's an opaque JSON string end to end — so
// that tag provides zero protection on this path. Listed here explicitly
// so it isn't mistaken for already-handled.
var topLevelRules = []FieldRule{
	{Path: []string{"secrets", "backends", "*", "token"}, Class: ClassValueSecret},
	{Path: []string{"cache", "password"}, Class: ClassValueSecret},
	{Path: []string{"cache", "sharedHmacKey"}, Class: ClassValueSecret},
	{Path: []string{"revocation", "password"}, Class: ClassValueSecret},
	{Path: []string{"caches", "*", "password"}, Class: ClassValueSecret, ArrayIDKey: "name"},
}

// heuristicSecretKeyRE is the fallback for module types with no entry in
// moduleRules (unknown types, and gRPC/WASM plugins, which have no
// schema mechanism to declare their own sensitive fields). Mirrors
// ui/console/src/lib/highlight.ts's SECRET_KEY_RE, plus "hash" — keep
// the two patterns in sync; the frontend one exists to catch anything
// this fallback misses, so drift between them quietly reopens gaps.
//
// Matched against normalizeKeyForMatch(key), not the raw key: \b word
// boundaries don't fire around "_" (it's a regex word character), so
// without normalizing first this would silently miss the extremely
// common SCREAMING_SNAKE_CASE env-var convention -- "API_TOKEN" has no
// \b between "_" and "TOKEN", so \btoken\b would never match it as
// written, even though it plainly should.
var heuristicSecretKeyRE = regexp.MustCompile(`(?i)\b(secret|password|passphrase|token|api[_-]?key|private[_-]?key|signing[_-]?key|client[_-]?secret|credential|hash)\b`)

var keyMatchNormalizer = strings.NewReplacer("_", " ", "-", " ")

func normalizeKeyForMatch(key string) string {
	return keyMatchNormalizer.Replace(key)
}

type walkMode int

const (
	redactMode walkMode = iota
	mergeMode
)

// RedactConfigJSON parses content (validated JSON — an AuthConfig-shaped
// document) and returns a JSON string with every field matched by
// moduleRules/topLevelRules/the heuristic fallback replaced by this
// package's sentinels. content is never mutated.
func RedactConfigJSON(content string) (string, error) {
	doc, err := parseDoc(content)
	if err != nil {
		return "", err
	}
	if err := applyModuleRules(doc, nil, redactMode); err != nil {
		return "", err
	}
	if err := applyTopLevelRules(doc, nil, redactMode); err != nil {
		return "", err
	}
	return marshalDoc(doc)
}

// RedactConfigVersion returns a copy of v with v.Content passed through
// RedactConfigJSON. Callers must use this only when building an HTTP
// response — never before persisting via Store.Push/PushConfig/Rollback,
// which must always keep real secrets.
func RedactConfigVersion(v ConfigVersion) (ConfigVersion, error) {
	redacted, err := RedactConfigJSON(v.Content)
	if err != nil {
		return ConfigVersion{}, err
	}
	out := v
	out.Content = redacted
	return out, nil
}

// mergeSecrets computes the content that should actually be persisted
// for a PushConfig call. newContent is the just-submitted JSON.
// prevContent/hasPrev describe the previous stored version, if any.
//
// Fast path: if newContent contains neither sentinel substring, it is
// returned completely unchanged — the common case (edits that don't
// touch any secret field) never gets re-serialized, preserving the
// user's exact formatting/key order in history.
func mergeSecrets(newContent, prevContent string, hasPrev bool) (string, error) {
	hasSentinel := strings.Contains(newContent, secretValueSentinel) || strings.Contains(newContent, secretBlockSentinelPrefix)
	if !hasSentinel {
		return newContent, nil
	}
	if !hasPrev {
		return "", errFirstPushSentinel
	}

	newDoc, err := parseDoc(newContent)
	if err != nil {
		return "", err
	}
	prevDoc, err := parseDoc(prevContent)
	if err != nil {
		return "", fmt.Errorf("internal error parsing stored config: %w", err)
	}

	if err := applyModuleRules(newDoc, prevDoc, mergeMode); err != nil {
		return "", err
	}
	if err := applyTopLevelRules(newDoc, prevDoc, mergeMode); err != nil {
		return "", err
	}
	return marshalDoc(newDoc)
}

func parseDoc(content string) (map[string]any, error) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return doc, nil
}

func marshalDoc(doc map[string]any) (string, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("failed to serialize config: %w", err)
	}
	return string(b), nil
}

// applyModuleRules walks the three module sections (identifiers,
// authorizers, response), pairing new/prev module entries by
// (section, name) — never by array index, since inserting a new
// identifier before an existing one is an entirely ordinary edit that
// would otherwise misattribute a restored secret to the wrong module.
func applyModuleRules(doc, prevDoc map[string]any, mode walkMode) error {
	for _, section := range []string{"identifiers", "authorizers", "response"} {
		entries, _ := doc[section].([]any)
		prevByName := map[string]map[string]any{}
		if prevDoc != nil {
			prevEntries, _ := prevDoc[section].([]any)
			for _, pe := range prevEntries {
				pm, ok := pe.(map[string]any)
				if !ok {
					continue
				}
				name, _ := pm["name"].(string)
				cfg, _ := pm["config"].(map[string]any)
				if name != "" {
					prevByName[name] = cfg
				}
			}
		}

		for _, e := range entries {
			em, ok := e.(map[string]any)
			if !ok {
				continue
			}
			typ, _ := em["type"].(string)
			name, _ := em["name"].(string)
			cfg, ok := em["config"].(map[string]any)
			if !ok {
				continue
			}

			var prevCfg any
			var haveModule bool
			if pc, found := prevByName[name]; found {
				prevCfg = pc
				haveModule = true
			}

			rules, known := moduleRules[typ]
			if !known {
				var err error
				if mode == redactMode {
					heuristicRedact(cfg)
				} else {
					err = heuristicMerge(cfg, prevCfg, haveModule)
				}
				if err != nil {
					return fmt.Errorf("%s %q (%s): %w", section, name, typ, err)
				}
				continue
			}

			for _, rule := range rules {
				var pc any
				if haveModule {
					pc = prevCfg
				}
				if err := applyRule(cfg, pc, rule, mode); err != nil {
					return fmt.Errorf("%s %q (%s): %w", section, name, typ, err)
				}
			}
		}
	}
	return nil
}

func applyTopLevelRules(doc map[string]any, prevDoc map[string]any, mode walkMode) error {
	var prevRoot any
	if prevDoc != nil {
		prevRoot = prevDoc
	}
	for _, rule := range topLevelRules {
		if err := applyRule(doc, prevRoot, rule, mode); err != nil {
			return fmt.Errorf("top-level: %w", err)
		}
	}
	return nil
}

// leafVisitor is called at each location a FieldRule's Path resolves to.
// newLeaf is the current value there (nil if absent — callers should
// treat that as "nothing to do"). oldLeaf/oldFound describe the paired
// location in the previous version, when one exists. Returning
// changed=false leaves newLeaf untouched.
type leafVisitor func(newLeaf, oldLeaf any, oldFound bool) (newValue any, changed bool, err error)

// applyRule dispatches a single FieldRule to the appropriate visitor.
// prevNode is nil when there is no previous version, or when this rule's
// module has no counterpart in the previous version — walkPair's
// per-leaf oldFound (not a coarser "have a previous version at all"
// flag) is what visitors actually key their restore-vs-reject decision
// on, since a sentinel can appear on a field with no previous
// counterpart even when other fields do have one.
func applyRule(node, prevNode any, rule FieldRule, mode walkMode) error {
	switch rule.Class {
	case ClassNone, ClassHash:
		return nil
	case ClassValueSecret:
		return walkPair(node, prevNode, rule.Path, rule.ArrayIDKey, valueSecretVisitor(mode))
	case ClassBlock:
		return walkPair(node, prevNode, rule.Path, "", blockVisitor(mode, func(any) bool { return true }))
	case ClassBlockIfHeuristic:
		return walkPair(node, prevNode, rule.Path, "", blockVisitor(mode, heuristicLooksSecret))
	default:
		return nil
	}
}

func valueSecretVisitor(mode walkMode) leafVisitor {
	return func(newLeaf, oldLeaf any, oldFound bool) (any, bool, error) {
		if newLeaf == nil {
			return nil, false, nil
		}
		if mode == redactMode {
			return secretValueSentinel, true, nil
		}
		if !isValueSentinel(newLeaf) {
			return nil, false, nil // real value submitted — keep as-is
		}
		if !oldFound {
			return nil, false, errFirstPushSentinel
		}
		return oldLeaf, true, nil
	}
}

func blockVisitor(mode walkMode, shouldCollapse func(any) bool) leafVisitor {
	return func(newLeaf, oldLeaf any, oldFound bool) (any, bool, error) {
		if newLeaf == nil {
			return nil, false, nil
		}
		if mode == redactMode {
			if !shouldCollapse(newLeaf) {
				return nil, false, nil
			}
			return blockSentinel(newLeaf), true, nil
		}
		s, ok := newLeaf.(string)
		if !ok || !strings.HasPrefix(s, secretBlockSentinelPrefix) {
			return nil, false, nil // real block submitted — accept as full replacement
		}
		if !oldFound {
			return nil, false, errFirstPushSentinel
		}
		return oldLeaf, true, nil
	}
}

func blockSentinel(value any) string {
	count := 0
	switch v := value.(type) {
	case map[string]any:
		count = len(v)
	case []any:
		count = len(v)
	}
	return fmt.Sprintf("%s:%d-entries►►", secretBlockSentinelPrefix, count)
}

func isValueSentinel(v any) bool {
	s, ok := v.(string)
	return ok && s == secretValueSentinel
}

func heuristicLooksSecret(v any) bool {
	switch vv := v.(type) {
	case []any:
		for _, item := range vv {
			s, ok := item.(string)
			if !ok {
				continue
			}
			key, _, found := strings.Cut(s, "=")
			if found && heuristicSecretKeyRE.MatchString(normalizeKeyForMatch(key)) {
				return true
			}
		}
	}
	return false
}

// walkPair walks newNode and oldNode in parallel along path. "*"
// iterates every element of a map (keyed by the map's own key, which
// naturally pairs old/new) or slice (paired by arrayIDKey when the
// elements are objects carrying that field, else by position). At the
// final path segment, fn is called and, if it signals a change,
// newNode is mutated in place.
func walkPair(newNode, oldNode any, path []string, arrayIDKey string, fn leafVisitor) error {
	if len(path) == 0 {
		return nil
	}
	seg, rest := path[0], path[1:]

	if seg == "*" {
		switch nv := newNode.(type) {
		case map[string]any:
			ov, _ := oldNode.(map[string]any)
			for k, child := range nv {
				var oldChild any
				var oldFound bool
				if ov != nil {
					oldChild, oldFound = ov[k]
				}
				if len(rest) == 0 {
					newVal, changed, err := fn(child, oldChild, oldFound)
					if err != nil {
						return err
					}
					if changed {
						nv[k] = newVal
					}
					continue
				}
				if err := walkPair(child, oldChild, rest, arrayIDKey, fn); err != nil {
					return err
				}
			}
		case []any:
			oldSlice, _ := oldNode.([]any)
			for i, child := range nv {
				oldChild, oldFound := pairArrayElement(child, oldSlice, i, arrayIDKey)
				if len(rest) == 0 {
					newVal, changed, err := fn(child, oldChild, oldFound)
					if err != nil {
						return err
					}
					if changed {
						nv[i] = newVal
					}
					continue
				}
				if err := walkPair(child, oldChild, rest, arrayIDKey, fn); err != nil {
					return err
				}
			}
		}
		return nil
	}

	nm, ok := newNode.(map[string]any)
	if !ok {
		return nil
	}
	child, exists := nm[seg]
	if !exists {
		return nil
	}
	var oldChild any
	var oldFound bool
	if om, ok := oldNode.(map[string]any); ok {
		oldChild, oldFound = om[seg]
	}
	if len(rest) == 0 {
		newVal, changed, err := fn(child, oldChild, oldFound)
		if err != nil {
			return err
		}
		if changed {
			nm[seg] = newVal
		}
		return nil
	}
	return walkPair(child, oldChild, rest, arrayIDKey, fn)
}

func pairArrayElement(newElem any, oldSlice []any, idx int, idKey string) (any, bool) {
	if idKey != "" {
		if nm, ok := newElem.(map[string]any); ok {
			if id, ok := nm[idKey]; ok {
				for _, oe := range oldSlice {
					if om, ok := oe.(map[string]any); ok {
						if oid, ok := om[idKey]; ok && oid == id {
							return oe, true
						}
					}
				}
				return nil, false
			}
		}
	}
	if idx < len(oldSlice) {
		return oldSlice[idx], true
	}
	return nil, false
}

// heuristicRedact recursively redacts an arbitrary map/slice tree (used
// for module types with no moduleRules entry) by matching key names
// against heuristicSecretKeyRE. Best-effort only — see the doc comment
// on heuristicSecretKeyRE. It cannot catch a key-secret pattern (secret
// material stored as a map key rather than a value); that class of gap
// is only fixed by an explicit ClassBlock rule.
func heuristicRedact(node any) {
	m, ok := node.(map[string]any)
	if !ok {
		return
	}
	for k, v := range m {
		if _, isString := v.(string); isString && heuristicSecretKeyRE.MatchString(normalizeKeyForMatch(k)) {
			m[k] = secretValueSentinel
			continue
		}
		heuristicRedactChild(v)
	}
}

func heuristicRedactChild(v any) {
	switch vv := v.(type) {
	case map[string]any:
		heuristicRedact(vv)
	case []any:
		for _, item := range vv {
			heuristicRedactChild(item)
		}
	}
}

func heuristicMerge(node, prevNode any, oldFound bool) error {
	m, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	var pm map[string]any
	if oldFound {
		pm, _ = prevNode.(map[string]any)
	}
	for k, v := range m {
		if isValueSentinel(v) {
			if pm == nil {
				return errFirstPushSentinel
			}
			old, found := pm[k]
			if !found {
				return errFirstPushSentinel
			}
			m[k] = old
			continue
		}
		var pv any
		var pFound bool
		if pm != nil {
			pv, pFound = pm[k]
		}
		if err := heuristicMergeChild(v, pv, pFound); err != nil {
			return err
		}
	}
	return nil
}

func heuristicMergeChild(v, pv any, pFound bool) error {
	switch vv := v.(type) {
	case map[string]any:
		return heuristicMerge(vv, pv, pFound)
	case []any:
		pSlice, _ := pv.([]any)
		for i, item := range vv {
			var pItem any
			var iFound bool
			if i < len(pSlice) {
				pItem = pSlice[i]
				iFound = true
			}
			if err := heuristicMergeChild(item, pItem, iFound); err != nil {
				return err
			}
		}
	}
	return nil
}
